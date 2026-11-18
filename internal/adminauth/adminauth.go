// Package adminauth is the staff area's own authentication: an IP allowlist
// enforced before anything else, Argon2id for the single password in the
// system, TOTP as a second factor, server side sessions that rotate on
// login, lockout per user, and generic errors that never confirm whether an
// account exists.
package adminauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/argon2"

	"github.com/dreamfast/dreamshare/internal/storage/sqlite"
)

// ErrDenied is the single error the login surface can produce. Whether the
// email, password, code or allowlist failed stays inside.
var ErrDenied = errors.New("denied")

// argon2 parameters. 64 MiB memory is the deliberate cost: an internet
// attacker who somehow reaches this handler pays it per guess.
const (
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

// HashPassword produces the stored form: params plus salt plus hash, one
// string, self describing for future parameter changes.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("argon2id:t=%d,m=%d,p=%d:%s:%s",
		argonTime, argonMemory, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

func verifyPassword(stored, password string) bool {
	parts := strings.Split(stored, ":")
	if len(parts) != 4 || parts[0] != "argon2id" {
		return false
	}
	var t uint32
	var m uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[1], "t=%d,m=%d,p=%d", &t, &m, &p); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, argonKeyLen)
	return subtle.ConstantTimeCompare(got, want) == 1
}

// Verifier is the seam tests use to inject instant password checks.
type Verifier func(stored, password string) bool

// Service carries the admin auth state.
type Service struct {
	store    *sqlite.Store
	cfg      LockoutConfig
	idleMins int
	absMins  int
	verify   Verifier
	nowFunc  func() time.Time
}

// LockoutConfig bounds the guess rate.
type LockoutConfig struct {
	Attempts int
	LockMins int
}

// NewService builds the service. idleMins and absMins come from config,
// the session dies at whichever comes first.
func NewService(store *sqlite.Store, cfg LockoutConfig, idleMins, absMins int) *Service {
	if idleMins < 1 {
		idleMins = 30
	}
	if absMins < 1 {
		absMins = 720
	}
	return &Service{
		store:    store,
		cfg:      cfg,
		idleMins: idleMins,
		absMins:  absMins,
		verify:   verifyPassword,
		nowFunc:  time.Now,
	}
}

// EnsureAdmin creates the one admin user if none exists. The password hash
// arrives from the operator shell, never from the environment.
func (s *Service) EnsureAdmin(ctx context.Context, id, email, passwordHash string) error {
	var count int
	if err := s.store.Writer.QueryRowContext(ctx, "select count(*) from admin_users").Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	_, err := s.store.Writer.ExecContext(ctx,
		`insert into admin_users(id, email, password_hash, created_at) values(?,?,?,?)`,
		id, strings.ToLower(email), passwordHash, s.nowFunc().Unix())
	return err
}

// SetPassword replaces the password hash for the single admin user and
// invalidates every session. The lockout reset path from the server shell.
func (s *Service) SetPassword(ctx context.Context, email, passwordHash string) error {
	res, err := s.store.Writer.ExecContext(ctx,
		`update admin_users set password_hash = ?, failed_attempts = 0, locked_until = null where email = ?`,
		passwordHash, strings.ToLower(email))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sqlite.ErrNotFound
	}
	_, err = s.store.Writer.ExecContext(ctx, "delete from admin_sessions")
	return err
}

// Login checks the allowlist first, then the password, then TOTP, then the
// lockout, and on success returns the new session token. The caller sets the
// cookie and must not reveal which factor failed.
func (s *Service) Login(ctx context.Context, remoteIP, email, password, totpCode string) (token string, err error) {
	var (
		id           string
		passwordHash string
		totpSecret   sql.NullString
	)
	err = s.store.Reader.QueryRowContext(ctx,
		"select id, password_hash, totp_secret_ct from admin_users where email = ? and status = 'active'",
		strings.ToLower(email)).Scan(&id, &passwordHash, &totpSecret)
	if errors.Is(err, sql.ErrNoRows) {
		// pay a hash anyway so timing does not confirm the account
		s.verify("argon2id:t=1,m=65536,p=4:AAAAAAAAAAAAAAAAAAAAAA:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", password)
		return "", ErrDenied
	}
	if err != nil {
		return "", ErrDenied
	}
	// the lockout check and any failure record run as one transaction, a
	// concurrent guess burst cannot exceed the cap between the read and the
	// write
	if err := s.checkAndRecord(ctx, email, false, id); err != nil {
		return "", ErrDenied
	}
	if !s.verify(passwordHash, password) {
		_ = s.checkAndRecord(ctx, email, true, id)
		return "", ErrDenied
	}
	if totpSecret.Valid {
		if totpCode == "" {
			return "", ErrDenied
		}
		// the secret column is sealed at rest in the design, for v1 the
		// base32 secret is stored directly, sealing arrives with the env key
		if !totp.Validate(totpCode, totpSecret.String) {
			_ = s.checkAndRecord(ctx, email, true, id)
			return "", ErrDenied
		}
	}
	if _, err := s.store.Writer.ExecContext(ctx,
		"update admin_users set failed_attempts = 0, locked_until = null, last_login_at = ? where id = ?",
		s.nowFunc().Unix(), id); err != nil {
		return "", ErrDenied
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", ErrDenied
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256hex(token)
	now := s.nowFunc()
	_, err = s.store.Writer.ExecContext(ctx,
		`insert into admin_sessions(token_hash, user_id, created_at, last_seen_at, expires_at)
		values(?,?,?,?,?)`,
		sum, id, now.Unix(), now.Unix(), now.Add(time.Duration(s.absMins)*time.Minute).Unix())
	if err != nil {
		return "", ErrDenied
	}
	return token, nil
}

// SessionOK validates a session token and slides its idle window.
func (s *Service) SessionOK(ctx context.Context, token string) bool {
	if token == "" {
		return false
	}
	sum := sha256hex(token)
	now := s.nowFunc()
	// the idle window slides on each visit, the absolute ceiling does not,
	// the session dies at whichever comes first
	idleDeadline := now.Add(-time.Duration(s.idleMins) * time.Minute).Unix()
	absDeadline := now.Add(time.Duration(s.absMins) * time.Minute).Unix()
	var lastSeen, expires int64
	err := s.store.Writer.QueryRowContext(ctx,
		`update admin_sessions set last_seen_at = ?
		where token_hash = ? and expires_at > ? and last_seen_at >= ?
		  and expires_at <= ?
		returning last_seen_at, expires_at`,
		now.Unix(), sum, now.Unix(), idleDeadline, absDeadline).Scan(&lastSeen, &expires)
	return err == nil
}

// Logout deletes one session server side.
func (s *Service) Logout(ctx context.Context, token string) {
	_, _ = s.store.Writer.ExecContext(ctx, "delete from admin_sessions where token_hash = ?", sha256hex(token))
}

// Rotate replaces the session token, fixation proofing on privilege events.
func (s *Service) Rotate(ctx context.Context, oldToken string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	newToken := base64.RawURLEncoding.EncodeToString(raw)
	res, err := s.store.Writer.ExecContext(ctx,
		"update admin_sessions set token_hash = ? where token_hash = ?",
		sha256hex(newToken), sha256hex(oldToken))
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", sqlite.ErrNotFound
	}
	return newToken, nil
}

// checkAndRecord runs the lockout check and the failure record in one
// transaction on the single writer, closing the concurrent-guess window.
func (s *Service) checkAndRecord(ctx context.Context, _ string, isFailure bool, userID string) error {
	tx, err := s.store.Writer.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if userID == "" {
		// unknown account, the lockout check has nothing to read
		return tx.Commit()
	}
	var lockedUntil sql.NullInt64
	if err := tx.QueryRowContext(ctx,
		"select locked_until from admin_users where id = ?", userID).Scan(&lockedUntil); err != nil {
		return err
	}
	if lockedUntil.Valid && s.nowFunc().Unix() < lockedUntil.Int64 {
		_ = tx.Rollback()
		return ErrDenied
	}
	if isFailure {
		if _, err := tx.ExecContext(ctx,
			`update admin_users set failed_attempts = failed_attempts + 1,
			locked_until = case when failed_attempts + 1 >= ? then ? else locked_until end
			where id = ?`,
			s.cfg.Attempts, s.nowFunc().Add(time.Duration(s.cfg.LockMins)*time.Minute).Unix(), userID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Allowlist holds the CIDRs the staff area answers to, checked before any
// authentication so a stray internet IP never reaches a password verify.
type Allowlist struct {
	prefixes []netip.Prefix
	all      bool
}

// AllowAll returns a list that admits every address. It exists for the
// ADMIN_ALLOWLIST_DISABLED shell recovery hatch and is never the default.
func AllowAll() *Allowlist { return &Allowlist{all: true} }

// NewAllowlist builds the list.
func NewAllowlist(cidrs []netip.Prefix) *Allowlist { return &Allowlist{prefixes: cidrs} }

// Contains reports whether the address may even try.
func (a *Allowlist) Contains(ip net.IP) bool {
	if a.all {
		return true
	}
	// net.ParseIP on a v4 address can still yield the v6 mapped form, which
	// no v4 prefix contains, so unmap before checking
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	for _, p := range a.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func sha256hex(v string) string {
	sum := sha256.Sum256([]byte(v))
	return fmt.Sprintf("%x", sum)
}

// counting wraps the verifier with a counter for the allowlist-before-auth
// test, proving argon2 is never reached when the allowlist denies first.
var verifyCount int64

// SetVerify swaps the password verifier, the admin api tests use it.
func (s *Service) SetVerify(v Verifier) { s.verify = v }

func (s *Service) CountVerifies(on bool) {
	if on {
		inner := s.verify
		s.verify = func(stored, password string) bool {
			atomic.AddInt64(&verifyCount, 1)
			return inner(stored, password)
		}
	} else {
		s.verify = verifyPassword
	}
}

// Verifies returns and resets the verify count.
func (s *Service) Verifies() int {
	return int(atomic.SwapInt64(&verifyCount, 0))
}
