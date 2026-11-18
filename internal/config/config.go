// Package config loads the environment and refuses to start on anything
// ambiguous. A proxy with no trusted ranges, a short secret, an unwritable
// database path, a bad enum. Names only are documented in .env.example, real
// values live in the process environment and never in git.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Env abstracts os.Getenv so tests inject a map instead of mutating process
// state and serialising each other.
type Env func(string) string

func mapEnv(m map[string]string) Env {
	return func(k string) string { return m[k] }
}

// TestEnv builds an Env from a map, for tests that need a valid baseline.
func TestEnv(m map[string]string) Env { return mapEnv(m) }

// Limits carries the size and abuse caps. Every value is overridable because
// they are operational dials, not constants of nature.
type Limits struct {
	MaxShareBytes    int64 // total ciphertext per submission, 1 GiB default
	DailyIPBytes     int64 // per IP per day across uploads and downloads, 5 GB default
	MaxFilesPerShare int   // bounds the manifest, the session count and the ack arithmetic
	TombstoneHours   int   // how long terminal rows survive so the feed can show what ended
	UploadSemaphore  int   // in-flight chunk cap, each chunk costs roughly two buffers

	ChunkMinBytes int64 // b2 rejects parts below 5,000,000 bytes, so never plan smaller
	ChunkMaxBytes int64 // 32 MiB in ds1

	TitleCTMaxBytes    int64 // finalise blob caps, sqlite must not become the free storage tier
	ManifestCTMaxBytes int64
	CheckCTBytes       int64 // fixed by the frame format, 1 version + 12 nonce + 16 data + 16 tag
}

// B2 is the storage configuration. The application key is bucket scoped with
// an f/ prefix and must never be logged.
type B2 struct {
	Endpoint string
	Region   string // the numeric b2 region id, never "auto"
	Bucket   string
	KeyID    string
	AppKey   string

	// The deep health check compares these against the real bucket rules.
	// B2 counts deletion from hiding, not upload, so hide must exceed the
	// longest ttl plus the tombstone grace.
	LifecycleHideDays   int
	LifecycleDeleteDays int
}

// SMTP is SMTP2GO. Dev may leave it unset, prod refuses without it.
type SMTP struct {
	Host     string
	Port     int
	User     string
	Password string
	From     string // bare address, appears in the notification From header
}

// Admin configures the one staff account. The allowlist runs before auth so
// an unknown address never reaches a password check.
type Admin struct {
	Allowlist       []netip.Prefix
	AllowlistOff    bool // shell escape hatch for a lockout, loud in the logs
	Email           string
	SessionIdleMins int
	SessionAbsMins  int
	LockoutAttempts int
	LockoutMinutes  int
}

// Config is the fully validated configuration. The zero value is never
// usable: Load returns a complete Config or one error listing every problem.
type Config struct {
	AppEnv   string // "dev" | "prod"
	Prod     bool
	BaseURL  *url.URL
	ListenOn string

	SQLitePath string

	BehindProxy    bool
	TrustedProxies []netip.Prefix // empty unless behind a proxy, the real client ip comes only from these
	IPMode         string         // "full" or "truncated"

	TurnstileMode    string // "required", "optional" or "disabled"
	TurnstileSiteKey string
	TurnstileSecret  string

	B2     B2
	SMTP   SMTP
	Admin  Admin
	Limits Limits
}

// Load reads the environment and validates it fail closed.
func Load(getenv Env) (*Config, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	c := &Config{}
	var errs []error

	c.AppEnv = get(getenv, "APP_ENV", "dev")
	switch c.AppEnv {
	case "dev":
		c.Prod = false
	case "prod":
		c.Prod = true
	default:
		errs = append(errs, fmt.Errorf("APP_ENV must be dev or prod, got %q", c.AppEnv))
	}

	c.ListenOn = get(getenv, "LISTEN_ON", ":8080")

	if u := get(getenv, "BASE_URL", ""); u != "" {
		// url.Parse returns a nil url with its error for control characters,
		// so the error is checked before anything touches the parsed value.
		// a stray crlf from an env file must refuse startup, not panic it.
		parsed, err := url.Parse(u)
		// compare the parsed host, a prefix match on the raw string accepts
		// localhost.evil.com
		switch {
		case err != nil:
			errs = append(errs, errors.New("BASE_URL is not a valid URL"))
		case parsed.Host == "":
			errs = append(errs, errors.New("BASE_URL must be an absolute URL, https in prod"))
		default:
			localDev := parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1"
			if parsed.Scheme != "https" && !localDev {
				errs = append(errs, errors.New("BASE_URL must be an absolute URL, https in prod"))
			} else if c.Prod && parsed.Scheme != "https" {
				errs = append(errs, errors.New("BASE_URL must be https when APP_ENV=prod"))
			} else {
				c.BaseURL = parsed
			}
		}
	} else if c.Prod {
		errs = append(errs, errors.New("BASE_URL is required when APP_ENV=prod, links are built from it"))
	}

	c.SQLitePath = get(getenv, "SQLITE_PATH", "data/dreamshare.db")
	// A directory where the database should be is the classic mistake. The
	// write probe happens when the store opens, this catches the obvious case
	// at config load.
	if fi, err := os.Stat(c.SQLitePath); err == nil && !fi.Mode().IsRegular() {
		errs = append(errs, fmt.Errorf("SQLITE_PATH %q exists and is not a regular file", c.SQLitePath))
	}
	if !filepath.IsAbs(c.SQLitePath) && c.Prod {
		errs = append(errs, errors.New("SQLITE_PATH must be absolute when APP_ENV=prod, it lives on the /data volume"))
	}

	// Behind a proxy the socket address is the proxy's, so trusting nobody is
	// the only safe default.
	c.BehindProxy = boolEnv(getenv, "BEHIND_PROXY")
	if c.BehindProxy {
		prefixes, perr := parseCIDRs(getenv("TRUSTED_PROXIES"))
		// a wider-than-intended prefix here makes every client ip spoofable,
		// and /0 is always a mistake rather than a choice
		for _, p := range prefixes {
			if p.Bits() == 0 {
				errs = append(errs, errors.New("TRUSTED_PROXIES must not contain the whole internet, 0.0.0.0/0 or ::/0 is a spoofing hole"))
			}
		}
		if perr != nil {
			errs = append(errs, perr)
		} else if len(prefixes) == 0 {
			errs = append(errs, errors.New("BEHIND_PROXY=true requires TRUSTED_PROXIES CIDRs, otherwise every client ip is spoofable"))
		} else {
			c.TrustedProxies = prefixes
		}
	} else if strings.TrimSpace(getenv("TRUSTED_PROXIES")) != "" {
		errs = append(errs, errors.New("TRUSTED_PROXIES set but BEHIND_PROXY is not true, pick one, ambiguity here is a security bug"))
	}

	c.IPMode = get(getenv, "IP_MODE", "full")
	if c.IPMode != "full" && c.IPMode != "truncated" {
		errs = append(errs, fmt.Errorf("IP_MODE must be full or truncated, got %q", c.IPMode))
	}

	// required by default so forgetting the keys fails startup rather than
	// the first bot.
	c.TurnstileMode = get(getenv, "TURNSTILE_MODE", "required")
	switch c.TurnstileMode {
	case "required", "optional", "disabled":
	default:
		errs = append(errs, fmt.Errorf("TURNSTILE_MODE must be required, optional or disabled, got %q", c.TurnstileMode))
	}
	c.TurnstileSiteKey = getenv("TURNSTILE_SITE_KEY")
	c.TurnstileSecret = getenv("TURNSTILE_SECRET")
	if c.TurnstileMode == "required" {
		if len(c.TurnstileSiteKey) < 20 {
			errs = append(errs, errors.New("TURNSTILE_MODE=required needs TURNSTILE_SITE_KEY of at least 20 chars"))
		}
		if len(c.TurnstileSecret) < 20 {
			errs = append(errs, errors.New("TURNSTILE_MODE=required needs TURNSTILE_SECRET of at least 20 chars"))
		}
	}

	c.B2.Endpoint = getenv("B2_ENDPOINT")
	c.B2.Region = getenv("B2_REGION")
	c.B2.Bucket = getenv("B2_BUCKET")
	c.B2.KeyID = getenv("B2_KEY_ID")
	c.B2.AppKey = getenv("B2_APPLICATION_KEY")
	for k, v := range map[string]string{
		"B2_ENDPOINT": c.B2.Endpoint, "B2_REGION": c.B2.Region,
		"B2_BUCKET": c.B2.Bucket, "B2_KEY_ID": c.B2.KeyID,
	} {
		if v == "" {
			errs = append(errs, fmt.Errorf("%s is required, point it at local minio in dev", k))
		}
	}
	if len(c.B2.AppKey) < 16 {
		errs = append(errs, errors.New("B2_APPLICATION_KEY is required, at least 16 chars, bucket scoped read and write with the f/ prefix"))
	}
	// parse, do not prefix match, HTTP:// or a schemeless host must not pass
	if b2u, err := url.Parse(c.B2.Endpoint); err == nil && b2u.Host != "" {
		if b2u.Scheme != "https" && b2u.Scheme != "http" {
			errs = append(errs, errors.New("B2_ENDPOINT must be an http or https URL"))
		}
		if b2u.Scheme != "https" && c.Prod {
			errs = append(errs, errors.New("B2_ENDPOINT must be https when APP_ENV=prod"))
		}
	} else {
		errs = append(errs, errors.New("B2_ENDPOINT must be an absolute URL"))
	}

	c.B2.LifecycleHideDays = intEnv(getenv, "B2_LIFECYCLE_HIDE_DAYS", 9)
	c.B2.LifecycleDeleteDays = intEnv(getenv, "B2_LIFECYCLE_DELETE_DAYS", 1)
	if c.B2.LifecycleDeleteDays < 1 {
		errs = append(errs, errors.New("B2_LIFECYCLE_DELETE_DAYS must be at least 1, the delete timer runs from hiding"))
	}

	c.SMTP.Host = getenv("SMTP_HOST")
	c.SMTP.Port = intEnv(getenv, "SMTP_PORT", 587)
	c.SMTP.User = getenv("SMTP_USER")
	c.SMTP.Password = getenv("SMTP_PASS")
	c.SMTP.From = getenv("NOTIFY_FROM")
	if c.Prod {
		if c.SMTP.Host == "" || c.SMTP.User == "" || len(c.SMTP.Password) < 8 || c.SMTP.From == "" {
			errs = append(errs, errors.New("APP_ENV=prod requires SMTP_HOST, SMTP_USER, SMTP_PASS of at least 8 chars and NOTIFY_FROM"))
		}
	}

	// the allowlist parses even when disabled, so a typo is reported at
	// startup instead of surfacing the day the hatch is switched off
	allowlist, alErr := parseCIDRs(getenv("ADMIN_ALLOWLIST"))
	if alErr != nil {
		errs = append(errs, alErr)
	}
	c.Admin.Allowlist = allowlist
	c.Admin.AllowlistOff = boolEnv(getenv, "ADMIN_ALLOWLIST_DISABLED")
	c.Admin.Email = getenv("ADMIN_EMAIL")
	if c.Prod {
		if c.Admin.Email == "" {
			errs = append(errs, errors.New("ADMIN_EMAIL is required when APP_ENV=prod, there is exactly one admin user"))
		}
		if len(c.Admin.Allowlist) == 0 && !c.Admin.AllowlistOff {
			errs = append(errs, errors.New("ADMIN_ALLOWLIST CIDRs are required when APP_ENV=prod, enforced before login, the shell escape hatch is ADMIN_ALLOWLIST_DISABLED=true"))
		}
	}
	c.Admin.SessionIdleMins = intEnv(getenv, "ADMIN_SESSION_IDLE_MINS", 30)
	c.Admin.SessionAbsMins = intEnv(getenv, "ADMIN_SESSION_ABS_MINS", 720)
	c.Admin.LockoutAttempts = intEnv(getenv, "ADMIN_LOCKOUT_ATTEMPTS", 5)
	c.Admin.LockoutMinutes = intEnv(getenv, "ADMIN_LOCKOUT_MINS", 15)
	// zero or absurd dials here silently disable the lockout and session
	// expiry, so they get ranges like every other security control
	for k, v := range map[string]int{
		"ADMIN_SESSION_IDLE_MINS": c.Admin.SessionIdleMins,
		"ADMIN_SESSION_ABS_MINS":  c.Admin.SessionAbsMins,
		"ADMIN_LOCKOUT_ATTEMPTS":  c.Admin.LockoutAttempts,
		"ADMIN_LOCKOUT_MINS":      c.Admin.LockoutMinutes,
	} {
		if v < 1 {
			errs = append(errs, fmt.Errorf("%s must be at least 1, got %d", k, v))
		}
	}
	if c.Admin.SessionIdleMins > c.Admin.SessionAbsMins {
		errs = append(errs, errors.New("ADMIN_SESSION_IDLE_MINS cannot exceed ADMIN_SESSION_ABS_MINS, the idle window would be dead code"))
	}

	l := &c.Limits
	l.MaxShareBytes = intEnv64(getenv, "MAX_SHARE_BYTES", 1<<30)
	l.DailyIPBytes = intEnv64(getenv, "DAILY_IP_BYTES", 5<<30)
	l.MaxFilesPerShare = intEnv(getenv, "MAX_FILES_PER_SHARE", 32)
	l.TombstoneHours = intEnv(getenv, "TOMBSTONE_HOURS", 24)
	l.UploadSemaphore = intEnv(getenv, "UPLOAD_SEMAPHORE", 8)
	l.ChunkMinBytes = intEnv64(getenv, "CHUNK_MIN_BYTES", 5_000_000)
	l.ChunkMaxBytes = intEnv64(getenv, "CHUNK_MAX_BYTES", 32<<20)
	l.TitleCTMaxBytes = intEnv64(getenv, "TITLE_CT_MAX_BYTES", 4096)
	l.ManifestCTMaxBytes = intEnv64(getenv, "MANIFEST_CT_MAX_BYTES", 256<<10)
	l.CheckCTBytes = intEnv64(getenv, "CHECK_CT_BYTES", 45)

	for k, v := range map[string]int{
		"MAX_FILES_PER_SHARE": l.MaxFilesPerShare,
		"TOMBSTONE_HOURS":     l.TombstoneHours,
		"UPLOAD_SEMAPHORE":    l.UploadSemaphore,
	} {
		if v < 1 {
			// a zero semaphore or zero files accepts nothing, a zero
			// tombstone is legal but arrives as a deliberate 0, not garbage
			if k != "TOMBSTONE_HOURS" || v < 0 {
				errs = append(errs, fmt.Errorf("%s must be at least 1, got %d", k, v))
			}
		}
	}
	if l.UploadSemaphore > 64 {
		errs = append(errs, fmt.Errorf("UPLOAD_SEMAPHORE above 64 buys throttling, not throughput, got %d", l.UploadSemaphore))
	}
	for k, v := range map[string]int64{
		"TITLE_CT_MAX_BYTES":    l.TitleCTMaxBytes,
		"MANIFEST_CT_MAX_BYTES": l.ManifestCTMaxBytes,
	} {
		if v < 1 || v > 16<<20 {
			errs = append(errs, fmt.Errorf("%s must be 1 byte to 16 MiB, got %d", k, v))
		}
	}
	if l.MaxFilesPerShare < 1 || l.MaxFilesPerShare > 256 {
		errs = append(errs, fmt.Errorf("MAX_FILES_PER_SHARE must be 1..256, got %d", l.MaxFilesPerShare))
	}
	if l.TombstoneHours > 24*7 {
		errs = append(errs, fmt.Errorf("TOMBSTONE_HOURS must be 168 or less, the window past a share's end stays small, got %d", l.TombstoneHours))
	}
	if l.ChunkMinBytes < 5_000_000 || l.ChunkMaxBytes > 5<<30 || l.ChunkMinBytes > l.ChunkMaxBytes {
		errs = append(errs, errors.New("CHUNK_MIN_BYTES must be at least 5000000, b2 part minimum, and no larger than CHUNK_MAX_BYTES which is at most 5 GiB"))
	}
	if l.CheckCTBytes != 45 {
		errs = append(errs, fmt.Errorf("CHECK_CT_BYTES is fixed by the ds1 frame format at 45, got %d", l.CheckCTBytes))
	}
	if l.MaxShareBytes < 1 || l.DailyIPBytes < 1 {
		errs = append(errs, errors.New("MAX_SHARE_BYTES and DAILY_IP_BYTES must be positive"))
	}
	// b2 counts deletion from hiding, so the hide day must outlast the
	// longest ttl plus the tombstone window or a dead app's backstop fires
	// while records still exist
	if int64(c.B2.LifecycleHideDays)*24 <= 7*24+int64(l.TombstoneHours) {
		errs = append(errs, fmt.Errorf(
			"B2_LIFECYCLE_HIDE_DAYS must exceed the 7 day ttl ceiling plus TOMBSTONE_HOURS, %d days does not outlast %d hours",
			c.B2.LifecycleHideDays, l.TombstoneHours))
	}
	if l.MaxShareBytes/l.ChunkMaxBytes > 10000 {
		errs = append(errs, errors.New("MAX_SHARE_BYTES exceeds 10000 max parts at CHUNK_MAX_BYTES"))
	}

	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("invalid configuration:\n%w", err)
	}
	return c, nil
}

func get(e Env, key, def string) string {
	if v := strings.TrimSpace(e(key)); v != "" {
		return v
	}
	return def
}

func boolEnv(e Env, key string) bool {
	switch strings.ToLower(strings.TrimSpace(e(key))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// intEnv silently falls back on garbage input because the fail-closed checks
// above are the real gate. An unparsable value behaves like unset.
func intEnv(e Env, key string, def int) int {
	if v := strings.TrimSpace(e(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func intEnv64(e Env, key string, def int64) int64 {
	if v := strings.TrimSpace(e(key)); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func parseCIDRs(raw string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("bad CIDR %q: %w", part, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// Tombstone is the window past a share's end as a Duration, for the reconciler.
func (l Limits) Tombstone() time.Duration { return time.Duration(l.TombstoneHours) * time.Hour }
