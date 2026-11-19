package sqlite

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestForeignKeysActuallyOn(t *testing.T) {
	s := openTemp(t)
	for name, db := range map[string]*sql.DB{"writer": s.Writer, "reader": s.Reader} {
		var on int
		if err := db.QueryRowContext(t.Context(), "pragma foreign_keys").Scan(&on); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		// off is the sqlite default and would make every cascade a no-op,
		// which is silent retention failure
		if on != 1 {
			t.Fatalf("foreign_keys off on %s, cascades would silently do nothing", name)
		}
	}
}

func insertShare(t *testing.T, db *sql.DB, id string) {
	t.Helper()
	_, err := db.ExecContext(t.Context(), `insert into shares(id, format_version, expiry_mode, expires_at, created_at)
		values(?, 'ds1', 'burn_on_ack', ?, ?)`, id, time.Now().Add(time.Hour).Unix(), time.Now().Unix())
	if err != nil {
		t.Fatalf("insert share: %v", err)
	}
}

// Two shares in one unix second is a normal busy second, not an error.
// A reviewer proved the old unique index refused the second insert outright.
func TestTwoSharesInTheSameSecond(t *testing.T) {
	s := openTemp(t)
	for _, id := range []string{"sh-a", "sh-b", "sh-c"} {
		mustExec(t, s.Writer, `insert into shares(id, format_version, expiry_mode, expires_at, created_at)
			values('`+id+`','ds1','burn_on_ack',0,0)`)
	}
}

// The one unsent row per share and kind rule is enforced by the partial
// unique index, not by caller discipline.
func TestOutboxSingleUnsentRowPerShareAndKind(t *testing.T) {
	s := openTemp(t)
	db := s.Writer
	insertShare(t, db, "sh1")
	mustExec(t, db, `insert into outbox(share_id, to_addr, kind, created_at) values('sh1','a@b.c','downloaded',0)`)
	if _, err := db.ExecContext(t.Context(),
		`insert into outbox(share_id, to_addr, kind, created_at) values('sh1','x@y.z','downloaded',1)`); err == nil {
		t.Fatal("second unsent row for the same share and kind accepted")
	}
	// a second kind, and a row after the first sent, must both be fine
	mustExec(t, db, `update outbox set sent_at = 1 where share_id='sh1'`)
	mustExec(t, db, `insert into outbox(share_id, to_addr, kind, created_at) values('sh1','a@b.c','downloaded',2)`)
}

// Duplicate manager tokens would mean two shares answering one revoke link.
func TestManagerTokenHashUnique(t *testing.T) {
	s := openTemp(t)
	db := s.Writer
	insertShare(t, db, "sh1")
	insertShare(t, db, "sh2")
	mustExec(t, db, `update shares set manager_token_hash='h' where id='sh1'`)
	if _, err := db.ExecContext(t.Context(), `update shares set manager_token_hash='h' where id='sh2'`); err == nil {
		t.Fatal("duplicate manager token hash accepted")
	}
}

// Every child table must lose its rows with the parent. This is the whole
// retention story, so it gets tested rather than trusted.
func TestCascadeDeletesEveryChild(t *testing.T) {
	s := openTemp(t)
	db := s.Writer
	insertShare(t, db, "sh1")

	mustExec(t, db, `insert into share_files(id, share_id, position, object_key, byte_size,
		frame_count, frame_size, part_size) values('f1','sh1',0,'f/2608/f1',45,1,1,45)`)
	mustExec(t, db, `insert into upload_sessions(id, share_id, file_id, part_size, expected_parts,
		created_at, expires_at) values('s1','sh1','f1',32,2,0,0)`)
	mustExec(t, db, `insert into upload_parts(sid, part_number, size) values('s1',1,32)`)
	mustExec(t, db, `insert into share_events(share_id, ts, event) values('sh1',0,'created')`)
	mustExec(t, db, `insert into outbox(share_id, to_addr, kind, created_at) values('sh1','a@b.c','downloaded',0)`)

	mustExec(t, db, `delete from shares where id='sh1'`)

	for _, table := range []string{"share_files", "upload_sessions", "upload_parts", "share_events", "outbox"} {
		var n int
		if err := db.QueryRowContext(t.Context(), "select count(*) from "+table).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if n != 0 {
			t.Errorf("%s kept %d rows after the parent died, retention is broken", table, n)
		}
	}
}

func TestAdminSessionsCascade(t *testing.T) {
	s := openTemp(t)
	db := s.Writer
	mustExec(t, db, `insert into admin_users(id, email, password_hash, created_at)
		values('u1','owner@example.com','x',0)`)
	mustExec(t, db, `insert into admin_sessions(token_hash, user_id, created_at, last_seen_at, expires_at)
		values('th1','u1',0,0,0)`)
	mustExec(t, db, `delete from admin_users where id='u1'`)

	var n int
	if err := db.QueryRowContext(t.Context(), "select count(*) from admin_sessions").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("admin session outlived its user")
	}
}

// The enums are the state machine. A value outside the list must never land.
func TestEnumsEnforced(t *testing.T) {
	s := openTemp(t)
	db := s.Writer
	insertShare(t, db, "sh2")

	if _, err := db.ExecContext(t.Context(), `update shares set status='gone' where id='sh2'`); err == nil {
		t.Fatal("bogus status accepted")
	}
	if _, err := db.ExecContext(t.Context(), `insert into shares(id, format_version, expiry_mode, expires_at)
		values('sh3','ds1',NULL,0)`); err == nil {
		t.Fatal("null expiry_mode accepted")
	}
	if _, err := db.ExecContext(t.Context(), `insert into share_events(share_id, ts, event) values('sh2',0,'unlocked')`); err == nil {
		t.Fatal("bogus event accepted")
	}
	// the expiry mode is the wipe state machine, garbage must never land
	if _, err := db.ExecContext(t.Context(), `insert into shares(id, format_version, expiry_mode, expires_at)
		values('sh4','ds1','banana',0)`); err == nil {
		t.Fatal("bogus expiry_mode accepted")
	}
}

// The reader pool must refuse writes at the driver. If it ever accepts one,
// the one writer invariant is caller discipline and the race analysis dies.
func TestReaderPoolIsReadOnly(t *testing.T) {
	s := openTemp(t)
	insertShare(t, s.Writer, "sh1")
	if _, err := s.Reader.ExecContext(t.Context(),
		`insert into shares(id, format_version, expiry_mode, expires_at) values('sh2','ds1','ttl',0)`); err == nil {
		t.Fatal("reader pool accepted a write")
	}
}

// A ? in the database filename must not split the DSN and point the app at a
// different, empty database. The later orphan sweep would delete everything
// in the bucket over an empty ledger.
func TestPathCharactersDoNotSplitTheDSN(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a?b.db")
	s1, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	insertShare(t, s1.Writer, "sh1")
	_ = s1.Close()

	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })
	var n int
	if err := s2.Reader.QueryRowContext(t.Context(), "select count(*) from shares").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("reopened a different database, found %d shares, want 1", n)
	}
}

// An older binary must refuse a newer schema instead of running on guesses.
func TestRefuseNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, s.Writer, "pragma user_version = 99")
	_ = s.Close()

	if _, err := Open(path); err == nil {
		t.Fatal("opened a database with a newer schema version")
	}
}

// UPDATE ... RETURNING carries the whole download and ack design. Prove the
// bundled driver supports it, so a driver bump that drops it fails here
// instead of in production wipe logic.
func TestUpdateReturningSupported(t *testing.T) {
	s := openTemp(t)
	db := s.Writer
	insertShare(t, db, "sh1")
	mustExec(t, db, `insert into share_files(id, share_id, position, object_key, byte_size,
		frame_count, frame_size, part_size) values('f1','sh1',0,'f/2608/f1',45,1,1,45)`)
	var attempts int
	if err := db.QueryRowContext(t.Context(),
		`update share_files set attempts = attempts + 1 where id='f1' returning attempts`).
		Scan(&attempts); err != nil {
		t.Fatalf("update returning: %v", err)
	}
	if attempts != 1 {
		t.Fatalf("returning gave %d, want 1", attempts)
	}
}

// One writer connection is the concurrency contract the download and ack
// transactions lean on. If this drifts, races come back.
func TestWriterIsSingleConnection(t *testing.T) {
	s := openTemp(t)
	if got := s.Writer.Stats().MaxOpenConnections; got != 1 {
		t.Fatalf("writer pool has %d max connections, want 1", got)
	}
}

func TestMigrationIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	s1, err := Open(path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	_ = s1.Close() // nothing to assert on a warm close

	s2, err := Open(path)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })

	var v int
	if err := s2.Writer.QueryRowContext(t.Context(), "pragma user_version").Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != 2 {
		t.Fatalf("user_version = %d, want 2", v)
	}

	var integrity string
	if err := s2.Writer.QueryRowContext(t.Context(), "pragma integrity_check").Scan(&integrity); err != nil {
		t.Fatal(err)
	}
	if integrity != "ok" {
		t.Fatalf("integrity_check = %q", integrity)
	}
}

func mustExec(t *testing.T, db *sql.DB, q string) {
	t.Helper()
	if _, err := db.ExecContext(t.Context(), q); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}
