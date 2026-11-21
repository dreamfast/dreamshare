package adminauth

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/dreamfast/dreamshare/internal/storage/sqlite"
)

func openAuth(t *testing.T) *Service {
	t.Helper()
	store, err := sqlite.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	s := NewService(store, LockoutConfig{Attempts: 3, LockMins: 15}, 30, 720)
	// instant password checks so the suite does not pay argon2 per guess
	s.verify = func(stored, password string) bool { return stored == "hash:"+password }
	return s
}

func TestLoginHappyPathAndLockout(t *testing.T) {
	s := openAuth(t)
	ctx := context.Background()
	if err := s.EnsureAdmin(ctx, "u1", "owner@example.com", "hash:correct"); err != nil {
		t.Fatal(err)
	}

	// wrong password fails generic
	if _, err := s.Login(ctx, "1.2.3.4", "owner@example.com", "wrong", ""); !errors.Is(err, ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
	// two more failures hit the lockout ceiling of three
	_, _ = s.Login(ctx, "1.2.3.4", "owner@example.com", "wrong", "")
	_, _ = s.Login(ctx, "1.2.3.4", "owner@example.com", "wrong", "")
	// now even the correct password is locked out
	if _, err := s.Login(ctx, "1.2.3.4", "owner@example.com", "correct", ""); !errors.Is(err, ErrDenied) {
		t.Fatal("lockout did not engage")
	}
	// after the window it opens again
	s.nowFunc = func() time.Time { return time.Now().Add(20 * time.Minute) }
	tok, err := s.Login(ctx, "1.2.3.4", "owner@example.com", "correct", "")
	if err != nil || tok == "" {
		t.Fatalf("post lockout login: %v %q", err, tok)
	}
}

func TestUnknownAccountSameError(t *testing.T) {
	s := openAuth(t)
	_, err := s.Login(t.Context(), "1.2.3.4", "nobody@example.com", "x", "")
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
}

func TestSessionsRotateAndExpire(t *testing.T) {
	s := openAuth(t)
	ctx := context.Background()
	_ = s.EnsureAdmin(ctx, "u1", "owner@example.com", "hash:p")
	tok, err := s.Login(ctx, "1.2.3.4", "owner@example.com", "p", "")
	if err != nil {
		t.Fatal(err)
	}
	if !s.SessionOK(ctx, tok) {
		t.Fatal("fresh session rejected")
	}
	newTok, err := s.Rotate(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	if s.SessionOK(ctx, tok) {
		t.Fatal("old token still valid after rotation")
	}
	if !s.SessionOK(ctx, newTok) {
		t.Fatal("rotated token rejected")
	}
	// expiry
	s.nowFunc = func() time.Time { return time.Now().Add(25 * time.Hour) }
	if s.SessionOK(ctx, newTok) {
		t.Fatal("expired session accepted")
	}
	s.Logout(ctx, newTok)
}

func TestSetPasswordInvalidatesSessions(t *testing.T) {
	s := openAuth(t)
	ctx := context.Background()
	_ = s.EnsureAdmin(ctx, "u1", "owner@example.com", "hash:old")
	tok, _ := s.Login(ctx, "1.2.3.4", "owner@example.com", "old", "")
	if !s.SessionOK(ctx, tok) {
		t.Fatal("session should be valid")
	}
	if err := s.SetPassword(ctx, "owner@example.com", "hash:new"); err != nil {
		t.Fatal(err)
	}
	if s.SessionOK(ctx, tok) {
		t.Fatal("session survived a password reset")
	}
	if _, err := s.Login(ctx, "1.2.3.4", "owner@example.com", "new", ""); err != nil {
		t.Fatalf("login with new password: %v", err)
	}
}

func TestArgon2HashRoundTrip(t *testing.T) {
	// the real verifier, once: proves the stored format parses and verifies
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !verifyPassword(hash, "correct horse battery staple") {
		t.Fatal("correct password rejected")
	}
	if verifyPassword(hash, "wrong") {
		t.Fatal("wrong password accepted")
	}
}

func TestAllowlist(t *testing.T) {
	al := NewAllowlist(mustPrefixes(t, "203.0.113.0/24", "2001:db8::/48"))
	if !al.Contains(mustIP(t, "203.0.113.7")) {
		t.Fatal("listed v4 refused")
	}
	if !al.Contains(mustIP(t, "2001:db8::1")) {
		t.Fatal("listed v6 refused")
	}
	if al.Contains(mustIP(t, "198.51.100.1")) {
		t.Fatal("unlisted ip accepted")
	}
}

func mustPrefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}

func mustIP(t *testing.T, v string) net.IP {
	t.Helper()
	ip := net.ParseIP(v)
	if ip == nil {
		t.Fatal("bad ip")
	}
	return ip
}

// §13 test 11: idle expiry is enforced distinct from the absolute ceiling.
func TestSessionIdleExpiry(t *testing.T) {
	s := openAuth(t)
	ctx := context.Background()
	_ = s.EnsureAdmin(ctx, "u1", "owner@example.com", "hash:p")
	tok, err := s.Login(ctx, "1.2.3.4", "owner@example.com", "p", "")
	if err != nil {
		t.Fatal(err)
	}
	if !s.SessionOK(ctx, tok) {
		t.Fatal("fresh session rejected")
	}
	// past the 30 minute idle window but inside the 12 hour absolute ceiling
	s.nowFunc = func() time.Time { return time.Now().Add(31 * time.Minute) }
	if s.SessionOK(ctx, tok) {
		t.Fatal("idle expiry not enforced")
	}
}

func TestTOTPEnrolmentRoundTrip(t *testing.T) {
	svc := openAuth(t)
	ctx := t.Context()
	if err := svc.EnsureAdmin(ctx, "admin-1", "root@example.com", "hash:hunter2"); err != nil {
		t.Fatal(err)
	}

	if svc.HasTOTP(ctx, "root@example.com") {
		t.Fatal("fresh admin must not have the factor")
	}
	secret, otpauth, err := svc.BeginTOTP(ctx, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if secret == "" || otpauth == "" {
		t.Fatal("begin returned an empty candidate")
	}
	// nothing is stored before a live code confirms
	if svc.HasTOTP(ctx, "root@example.com") {
		t.Fatal("begin must not enrol by itself")
	}

	code, cerr := totp.GenerateCode(secret, time.Now())
	if cerr != nil {
		t.Fatal(cerr)
	}
	if err := svc.ConfirmTOTP(ctx, "root@example.com", "wrongpw", secret, code); err == nil {
		t.Fatal("confirm with a wrong password must refuse")
	}
	if err := svc.ConfirmTOTP(ctx, "root@example.com", "hunter2", secret, "000000"); err == nil {
		t.Fatal("confirm with a wrong code must refuse")
	}
	if err := svc.ConfirmTOTP(ctx, "root@example.com", "hunter2", secret, code); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if !svc.HasTOTP(ctx, "root@example.com") {
		t.Fatal("confirm must enrol the factor")
	}

	// login now demands the code
	if _, err := svc.Login(ctx, "127.0.0.1", "root@example.com", "hunter2", ""); err == nil {
		t.Fatal("login without the code must refuse once enrolled")
	}
	tok, err := svc.Login(ctx, "127.0.0.1", "root@example.com", "hunter2", code)
	if err != nil {
		t.Fatalf("login with the code: %v", err)
	}
	if tok == "" {
		t.Fatal("login returned an empty session token")
	}

	// disable needs the password again
	if err := svc.DisableTOTP(ctx, "root@example.com", "wrongpw"); err == nil {
		t.Fatal("disable with a wrong password must refuse")
	}
	if err := svc.DisableTOTP(ctx, "root@example.com", "hunter2"); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if svc.HasTOTP(ctx, "root@example.com") {
		t.Fatal("disable must clear the factor")
	}
}
