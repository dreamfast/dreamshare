// Package sqlite opens the metadata store and applies migrations.
//
// WAL mode, a busy timeout and foreign keys on. The write pool is exactly one
// connection on purpose. Mutations serialise, which is what makes the multi
// statement download and ack transactions race free.
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure Go driver, keeps the static binary
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Store holds the two pools. Writer serialises every mutation. Reader serves
// status and admin queries so long reads never block writes.
type Store struct {
	Writer *sql.DB
	Reader *sql.DB
}

// Open refuses an unwritable path so startup dies loudly instead of on the
// first query, then applies pragmas, migrations and the foreign key check.
func Open(path string) (*Store, error) {
	if err := ensureWritable(path); err != nil {
		return nil, fmt.Errorf("sqlite path: %w", err)
	}

	writer, err := openPool(path, 1, false)
	if err != nil {
		return nil, fmt.Errorf("open writer: %w", err)
	}
	reader, err := openPool(path, 4, true)
	if err != nil {
		_ = writer.Close() // already failing, nothing actionable left
		return nil, fmt.Errorf("open reader: %w", err)
	}

	if err := Migrate(context.Background(), writer); err != nil {
		_ = writer.Close() // already failing, nothing actionable left
		_ = reader.Close()
		return nil, err
	}

	s := &Store{Writer: writer, Reader: reader}
	if err := s.assertOpenPath(context.Background(), path); err != nil {
		_ = s.Close() // already failing, nothing actionable left
		return nil, err
	}
	if err := s.assertForeignKeys(context.Background()); err != nil {
		_ = s.Close() // already failing, nothing actionable left
		return nil, err
	}
	return s, nil
}

// assertOpenPath proves the connection landed on the configured file. A path
// character that split the DSN would otherwise run the app on an empty
// ledger, which the later orphan sweep would treat as garbage to delete.
func (s *Store) assertOpenPath(ctx context.Context, path string) error {
	var seq int
	var name, file string
	if err := s.Writer.QueryRowContext(ctx, "pragma database_list").Scan(&seq, &name, &file); err != nil {
		return fmt.Errorf("database_list: %w", err)
	}
	abs := func(p string) string {
		a, err := filepath.Abs(p)
		if err != nil {
			return filepath.Clean(p)
		}
		return a
	}
	got, want := abs(strings.TrimPrefix(file, "file:")), abs(path)
	if got != want {
		return fmt.Errorf("opened database %q does not match configured path %q", got, want)
	}
	return nil
}

// Close closes both pools.
func (s *Store) Close() error {
	var firstErr error
	if err := s.Writer.Close(); err != nil {
		firstErr = err
	}
	if err := s.Reader.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

func openPool(path string, maxOpen int, readOnly bool) (*sql.DB, error) {
	// Pragmas ride in the DSN so they apply to every pooled connection, not
	// just the first one the pool happened to open. query_only makes the
	// reader pool refuse writes at the driver, so the one writer invariant
	// is a mechanism instead of caller discipline.
	// The path goes through url.URL so a ? or # in the filename cannot split
	// the DSN and silently point the app at a different database file.
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	dsn := u.String() +
		"?_pragma=busy_timeout(5000)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=foreign_keys(1)"
	if readOnly {
		dsn += "&_pragma=query_only(1)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxOpen)
	db.SetConnMaxLifetime(0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close() // already failing, nothing actionable left
		return nil, err
	}
	return db, nil
}

// assertForeignKeys proves the pragma landed. foreign_keys defaults to off
// per connection, and with it off every cascade delete is a silent no-op.
func (s *Store) assertForeignKeys(ctx context.Context) error {
	for name, db := range map[string]*sql.DB{"writer": s.Writer, "reader": s.Reader} {
		var on int
		if err := db.QueryRowContext(ctx, "pragma foreign_keys").Scan(&on); err != nil {
			return fmt.Errorf("pragma foreign_keys on %s: %w", name, err)
		}
		if on != 1 {
			return fmt.Errorf("foreign_keys is %d on %s, want 1, cascade deletes would be a no-op", on, name)
		}
	}
	return nil
}

func ensureWritable(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	// 0600 on create. A directory path, a read only mount or someone else's
	// file all fail right here.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- the path is operator config validated at load, never request data
	if err != nil {
		return err
	}
	return f.Close()
}

// Migrate applies pending migrations in order, each in one transaction, with
// progress in user_version. Running against an up to date database is a no-op.
func Migrate(ctx context.Context, db *sql.DB) error {
	migrations, err := loadMigrations()
	if err != nil {
		return err
	}

	var current int
	if err := db.QueryRowContext(ctx, "pragma user_version").Scan(&current); err != nil {
		return fmt.Errorf("read user_version: %w", err)
	}
	// an older binary against a newer schema is a silent downgrade, and
	// every assumption the binary makes about the schema is then wrong
	if current > len(migrations) {
		return fmt.Errorf("database schema version %d is newer than this binary knows, %d migrations, refusing to run", current, len(migrations))
	}

	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		if err := applyMigration(ctx, db, m); err != nil {
			return fmt.Errorf("migration %d: %w", m.version, err)
		}
	}
	return nil
}

type migration struct {
	version int
	sqlText string
}

// loadMigrations demands 1..n with no gaps so a botched renumber fails at
// startup instead of splitting deployments.
func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	var out []migration
	for _, e := range entries {
		name := e.Name()
		var v int
		if _, err := fmt.Sscanf(name, "%d-", &v); err != nil {
			return nil, fmt.Errorf("migration %q: filename must start '<n>-': %w", name, err)
		}
		b, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return nil, err
		}
		out = append(out, migration{version: v, sqlText: string(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	for i, m := range out {
		if m.version != i+1 {
			return nil, fmt.Errorf("migration versions must be 1..n without gaps, got %d at position %d", m.version, i+1)
		}
	}
	return out, nil
}

func applyMigration(ctx context.Context, db *sql.DB, m migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, m.sqlText); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "pragma user_version = "+strconv.Itoa(m.version)); err != nil {
		return err
	}
	return tx.Commit()
}
