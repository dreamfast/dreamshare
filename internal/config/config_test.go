package config

import (
	"path/filepath"
	"strings"
	"testing"
)

// validEnv builds a dev baseline that must always load. Overrides replace,
// an empty value deletes, so tests can pull a var out on purpose.
func validEnv(overrides map[string]string) Env {
	base := map[string]string{
		"APP_ENV":            "dev",
		"TURNSTILE_MODE":     "disabled",
		"B2_ENDPOINT":        "http://localhost:9000",
		"B2_REGION":          "us-west-002",
		"B2_BUCKET":          "dreamshare",
		"B2_KEY_ID":          "test-key-id",
		"B2_APPLICATION_KEY": "test-application-key-16",
	}
	for k, v := range overrides {
		if v == "" {
			delete(base, k)
		} else {
			base[k] = v
		}
	}
	return TestEnv(base)
}

func mustLoad(t *testing.T, e Env) *Config {
	t.Helper()
	c, err := Load(e)
	if err != nil {
		t.Fatalf("expected valid config, got: %v", err)
	}
	return c
}

func mustFailContaining(t *testing.T, e Env, want ...string) {
	t.Helper()
	_, err := Load(e)
	if err == nil {
		t.Fatalf("expected failure mentioning %q, got success", want)
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error missing %q, got: %v", w, err)
		}
	}
}

func TestValidDevConfig(t *testing.T) {
	c := mustLoad(t, validEnv(nil))
	if c.Prod {
		t.Fatal("dev flagged as prod")
	}
	if c.Limits.CheckCTBytes != 45 {
		t.Fatalf("check blob size drifted from the frame format, got %d", c.Limits.CheckCTBytes)
	}
	if c.Limits.MaxShareBytes != 1<<30 || c.Limits.DailyIPBytes != 5<<30 {
		t.Fatalf("default caps drifted, got share=%d daily=%d", c.Limits.MaxShareBytes, c.Limits.DailyIPBytes)
	}
}

// A config that loads with every prod knob set, so the prod failures below
// are about the missing knob, not a broken baseline.
func validProdEnv(t *testing.T, overrides map[string]string) Env {
	t.Helper()
	base := map[string]string{
		"APP_ENV":            "prod",
		"BASE_URL":           "https://share.example.com",
		"SQLITE_PATH":        filepath.Join(t.TempDir(), "dreamshare.db"),
		"TURNSTILE_MODE":     "disabled",
		"B2_ENDPOINT":        "https://s3.us-west-002.backblazeb2.com",
		"B2_REGION":          "us-west-002",
		"B2_BUCKET":          "dreamshare",
		"B2_KEY_ID":          "prod-key-id",
		"B2_APPLICATION_KEY": "prod-application-key-16",
		"SMTP_HOST":          "mail.smtp2go.com",
		"SMTP_USER":          "user",
		"SMTP_PASS":          "long-enough-password",
		"NOTIFY_FROM":        "share@example.com",
		"ADMIN_EMAIL":        "owner@example.com",
		"ADMIN_ALLOWLIST":    "203.0.113.7/32,2001:db8::/48",
	}
	for k, v := range overrides {
		if v == "" {
			delete(base, k)
		} else {
			base[k] = v
		}
	}
	return TestEnv(base)
}

func TestValidProdConfig(t *testing.T) {
	mustLoad(t, validProdEnv(t, nil))
}

func TestMissingOrShortSecretsRefuseStartup(t *testing.T) {
	mustFailContaining(t, validEnv(map[string]string{"B2_APPLICATION_KEY": ""}), "B2_APPLICATION_KEY")
	mustFailContaining(t, validEnv(map[string]string{"B2_APPLICATION_KEY": "short"}), "B2_APPLICATION_KEY")
	mustFailContaining(t, validEnv(map[string]string{"B2_BUCKET": ""}), "B2_BUCKET")
	mustFailContaining(t, validEnv(map[string]string{"TURNSTILE_MODE": ""}), "TURNSTILE_MODE")

	// required is the default mode, so forgetting the keys kills startup
	mustFailContaining(t, validEnv(map[string]string{"TURNSTILE_MODE": "required"}),
		"TURNSTILE_SITE_KEY", "TURNSTILE_SECRET")
	mustFailContaining(t,
		validEnv(map[string]string{"TURNSTILE_MODE": "required", "TURNSTILE_SITE_KEY": "0123456789abcdef0123"}),
		"TURNSTILE_SECRET")

	// with the keys present the required mode must load
	c := mustLoad(t, validEnv(map[string]string{
		"TURNSTILE_MODE":     "required",
		"TURNSTILE_SITE_KEY": "0123456789abcdefghijk",
		"TURNSTILE_SECRET":   "0123456789abcdefghijk",
	}))
	if c.TurnstileMode != "required" {
		t.Fatalf("turnstile mode not honoured, got %q", c.TurnstileMode)
	}
}

func TestProxyTrustFailClosed(t *testing.T) {
	mustFailContaining(t, validEnv(map[string]string{"BEHIND_PROXY": "true"}), "TRUSTED_PROXIES")
	mustFailContaining(t,
		validEnv(map[string]string{"BEHIND_PROXY": "true", "TRUSTED_PROXIES": "not-a-cidr"}),
		"bad CIDR")
	// proxies named without the flag is the same ambiguity, refuse it too
	mustFailContaining(t,
		validEnv(map[string]string{"BEHIND_PROXY": "false", "TRUSTED_PROXIES": "10.0.0.0/8"}),
		"TRUSTED_PROXIES set but BEHIND_PROXY")

	c := mustLoad(t, validEnv(map[string]string{
		"BEHIND_PROXY":    "true",
		"TRUSTED_PROXIES": "10.0.0.0/8, 192.0.2.1/32",
	}))
	if len(c.TrustedProxies) != 2 {
		t.Fatalf("want 2 trusted prefixes, got %d", len(c.TrustedProxies))
	}
}

func TestProdRequiresItsWholeSurface(t *testing.T) {
	mustFailContaining(t, validProdEnv(t, map[string]string{"BASE_URL": ""}), "BASE_URL")
	mustFailContaining(t,
		validProdEnv(t, map[string]string{"BASE_URL": "http://share.example.com"}),
		"absolute URL")
	mustFailContaining(t,
		validProdEnv(t, map[string]string{"SQLITE_PATH": "relative.db"}),
		"absolute")
	mustFailContaining(t, validProdEnv(t, map[string]string{"SMTP_PASS": ""}), "SMTP_HOST")
	mustFailContaining(t, validProdEnv(t, map[string]string{"ADMIN_ALLOWLIST": ""}), "ADMIN_ALLOWLIST")
	mustFailContaining(t, validProdEnv(t, map[string]string{"ADMIN_EMAIL": ""}), "ADMIN_EMAIL")
	// the documented lockout escape hatch exists and is loud, not silent
	c := mustLoad(t, validProdEnv(t, map[string]string{
		"ADMIN_ALLOWLIST":          "",
		"ADMIN_ALLOWLIST_DISABLED": "true",
	}))
	if !c.Admin.AllowlistOff {
		t.Fatal("allowlist override flag not honoured")
	}
}

func TestUnwritableSQLitePathRefusesStartup(t *testing.T) {
	// a directory where the file would be, the classic mistake
	mustFailContaining(t, validEnv(map[string]string{"SQLITE_PATH": t.TempDir()}), "not a regular file")
}

func TestEnumsAndRanges(t *testing.T) {
	mustFailContaining(t, validEnv(map[string]string{"IP_MODE": "banana"}), "IP_MODE")
	mustFailContaining(t, validEnv(map[string]string{"APP_ENV": "staging"}), "APP_ENV")
	mustFailContaining(t, validEnv(map[string]string{"MAX_FILES_PER_SHARE": "0"}), "MAX_FILES_PER_SHARE")
	mustFailContaining(t, validEnv(map[string]string{"MAX_FILES_PER_SHARE": "999"}), "MAX_FILES_PER_SHARE")
	mustFailContaining(t, validEnv(map[string]string{"TOMBSTONE_HOURS": "1000"}), "TOMBSTONE_HOURS")
	mustFailContaining(t, validEnv(map[string]string{"CHECK_CT_BYTES": "44"}), "CHECK_CT_BYTES")
	mustFailContaining(t, validEnv(map[string]string{"CHUNK_MIN_BYTES": "1000000"}), "CHUNK_MIN_BYTES")
	mustFailContaining(t, validEnv(map[string]string{"B2_LIFECYCLE_HIDE_DAYS": "3"}), "B2_LIFECYCLE_HIDE_DAYS")
}

// BASE_URL garbage must produce a refusal, never a panic. Trailing
// whitespace from an env file is trimmed and loads, embedded garbage
// refuses. url.Parse returns a nil url with its error, the old code
// dereferenced it.
func TestBaseURLGarbageRefusesNotPanics(t *testing.T) {
	for _, bad := range []string{"https://exa mple.com", "https://example.com/%zz", "https://sha\tre.example.com"} {
		mustFailContaining(t, validEnv(map[string]string{"BASE_URL": bad}), "BASE_URL")
	}
	// a stray crlf from an env parser is trimmed away, not a crash loop
	c := mustLoad(t, validEnv(map[string]string{"BASE_URL": "https://share.example.com\n"}))
	if c.BaseURL == nil || c.BaseURL.Host != "share.example.com" {
		t.Fatalf("trimmed BASE_URL not parsed, got %+v", c.BaseURL)
	}
}

// A typo'd allowlist is reported even with the hatch on, so the error does
// not surface the day the hatch is switched off.
func TestAllowlistParsesEvenWithHatchOn(t *testing.T) {
	mustFailContaining(t, validProdEnv(t, map[string]string{
		"ADMIN_ALLOWLIST":          "not-a-cidr",
		"ADMIN_ALLOWLIST_DISABLED": "true",
	}), "bad CIDR")
}

func TestLifecycleWindowOutlastsTombstone(t *testing.T) {
	mustFailContaining(t, validEnv(map[string]string{"B2_LIFECYCLE_HIDE_DAYS": "7"}), "outlast")
	mustFailContaining(t,
		validEnv(map[string]string{"B2_LIFECYCLE_HIDE_DAYS": "8", "TOMBSTONE_HOURS": "48"}),
		"outlast")
	// the exact boundary: 8 days equals 7 plus 24 hours, equality must refuse
	mustFailContaining(t,
		validEnv(map[string]string{"B2_LIFECYCLE_HIDE_DAYS": "8", "TOMBSTONE_HOURS": "24"}),
		"outlast")
}

func TestProxyWholeInternetRefused(t *testing.T) {
	mustFailContaining(t,
		validEnv(map[string]string{"BEHIND_PROXY": "true", "TRUSTED_PROXIES": "0.0.0.0/0"}),
		"whole internet")
	mustFailContaining(t,
		validEnv(map[string]string{"BEHIND_PROXY": "true", "TRUSTED_PROXIES": "::/0"}),
		"whole internet")
}

func TestB2EndpointSchemeParsed(t *testing.T) {
	mustFailContaining(t,
		validEnv(map[string]string{"B2_ENDPOINT": "s3.us-west-002.backblazeb2.com"}),
		"absolute URL")
	mustFailContaining(t, validProdEnv(t, map[string]string{"B2_ENDPOINT": "HTTP://s3.example.com"}),
		"https when APP_ENV=prod")
}

func TestDevBaseURLHostTrickRefused(t *testing.T) {
	mustFailContaining(t,
		validEnv(map[string]string{"BASE_URL": "http://localhost.evil.com"}),
		"absolute URL")
	mustFailContaining(t,
		validEnv(map[string]string{"BASE_URL": "http://localhost@evil.com"}),
		"absolute URL")
}

func TestSecurityDialsHaveRanges(t *testing.T) {
	mustFailContaining(t, validEnv(map[string]string{"ADMIN_LOCKOUT_ATTEMPTS": "0"}), "ADMIN_LOCKOUT_ATTEMPTS")
	mustFailContaining(t, validEnv(map[string]string{"ADMIN_SESSION_IDLE_MINS": "0"}), "ADMIN_SESSION_IDLE_MINS")
	mustFailContaining(t,
		validEnv(map[string]string{"ADMIN_SESSION_IDLE_MINS": "90", "ADMIN_SESSION_ABS_MINS": "60"}),
		"cannot exceed")
	mustFailContaining(t, validEnv(map[string]string{"UPLOAD_SEMAPHORE": "0"}), "UPLOAD_SEMAPHORE")
	mustFailContaining(t, validEnv(map[string]string{"TITLE_CT_MAX_BYTES": "0"}), "TITLE_CT_MAX_BYTES")
	mustFailContaining(t, validEnv(map[string]string{"MANIFEST_CT_MAX_BYTES": "99999999999"}), "MANIFEST_CT_MAX_BYTES")
}

func TestUnknownEnvValuesFallBackNotFail(t *testing.T) {
	// garbage numbers behave like unset, the range checks are the real gate
	c := mustLoad(t, validEnv(map[string]string{"TOMBSTONE_HOURS": "banana"}))
	if c.Limits.TombstoneHours != 24 {
		t.Fatalf("garbage input should fall back to the default, got %d", c.Limits.TombstoneHours)
	}
}
