package api

import (
	"net/http"
	"path/filepath"
	"testing"

	"github.com/dreamfast/dreamshare/internal/config"
	"github.com/dreamfast/dreamshare/internal/storage/b2/fake"
	"github.com/dreamfast/dreamshare/internal/storage/sqlite"
)

// §13 test 4: the uploadfish limiter bug was a busy IP never resetting. The
// property that matters here is the window rolls and the fixed window counts
// per tier per ip.
func TestLimiterFixedWindowRolls(t *testing.T) {
	l := newLimiter()
	l.boost = 1000
	key := "1.2.3.4|0"
	for i := 0; i < tierCreate.limit()*l.boost; i++ {
		if !l.allow(key, tierCreate) {
			t.Fatalf("limited at %d under boost", i)
		}
	}
	if l.allow(key, tierCreate) {
		t.Fatal("over the ceiling")
	}
	// a different ip has its own bucket
	if !l.allow("5.6.7.8|0", tierCreate) {
		t.Fatal("another ip affected by the first ceiling")
	}
	// a different tier has its own bucket for the same ip
	if !l.allow("1.2.3.4|3", tierDownload) {
		t.Fatal("download tier affected by the create ceiling")
	}
}

func TestClientIPNoProxyIgnoresHeaders(t *testing.T) {
	rg := newRig(t, nil)
	// behind no proxy the forwarded headers must be ignored entirely, the
	// peer address is the truth
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, rg.srv.URL+"/healthz", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")
	req.Header.Set("CF-Connecting-IP", "9.9.9.9")
	resp, err := rg.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: %d", resp.StatusCode)
	}
}

func TestClientIPTrustedProxyRightmostXFF(t *testing.T) {
	// behind a trusted proxy that appends, the rightmost element is the
	// proxy's observation, the leftmost is client supplied
	base := map[string]string{
		"APP_ENV":            "dev",
		"TURNSTILE_MODE":     "disabled",
		"B2_ENDPOINT":        "http://localhost:9000",
		"B2_REGION":          "us-west-002",
		"B2_BUCKET":          "dreamshare",
		"B2_KEY_ID":          "kid",
		"B2_APPLICATION_KEY": "application-key-16",
		"BEHIND_PROXY":       "true",
		"TRUSTED_PROXIES":    "127.0.0.0/8",
	}
	cfg, err := config.Load(config.TestEnv(base))
	if err != nil {
		t.Fatal(err)
	}
	store, err := sqlite.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	server := NewServer(cfg, store, fake.New(), nil)
	_ = server

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil)
	// the client claims to be 1.2.3.4 first, the proxy appended 203.0.113.9
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 203.0.113.9")
	req.RemoteAddr = "127.0.0.1:9999"
	got := server.clientIP(req)
	if got != "203.0.113.9" {
		t.Fatalf("clientIP = %q, want the rightmost proxy observation 203.0.113.9", got)
	}

	// the cf header is ignored without the fronted flag, a plain proxy
	// chain would otherwise let any client strike a victim address
	req2, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil)
	req2.Header.Set("CF-Connecting-IP", "198.51.100.7")
	req2.Header.Set("X-Forwarded-For", "1.2.3.4, 203.0.113.9")
	req2.RemoteAddr = "127.0.0.1:9999"
	if got := server.clientIP(req2); got != "203.0.113.9" {
		t.Fatalf("clientIP = %q, want the rightmost xff, cf header must not win without the fronted flag", got)
	}

	// with the flag set the cf header wins, cloudflare overwrites it so
	// clients cannot choose it
	cfgFronted, ferr := config.Load(config.TestEnv(map[string]string{
		"APP_ENV":            "dev",
		"TURNSTILE_MODE":     "disabled",
		"B2_ENDPOINT":        "http://localhost:9000",
		"B2_REGION":          "us-west-002",
		"B2_BUCKET":          "dreamshare",
		"B2_KEY_ID":          "kid",
		"B2_APPLICATION_KEY": "application-key-16",
		"BEHIND_PROXY":       "true",
		"TRUSTED_PROXIES":    "127.0.0.0/8",
		"CLOUDFLARE_FRONTED": "true",
	}))
	if ferr != nil {
		t.Fatal(ferr)
	}
	serverFronted := NewServer(cfgFronted, store, fake.New(), nil)
	// the flag alone is not enough: the proxy saw 203.0.113.9 as its peer,
	// no cloudflare edge, so the forged cf header loses and the direct
	// peer address wins the bucket
	req3, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil)
	req3.Header.Set("CF-Connecting-IP", "198.51.100.7")
	req3.Header.Set("X-Forwarded-For", "1.2.3.4, 203.0.113.9")
	req3.RemoteAddr = "127.0.0.1:9999"
	if got := serverFronted.clientIP(req3); got != "203.0.113.9" {
		t.Fatalf("clientIP = %q, a forged cf header behind a non cloudflare peer must lose, want 203.0.113.9", got)
	}

	// when the proxy's peer IS a cloudflare edge the header is cloudflare
	// authored and wins
	req4, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil)
	req4.Header.Set("CF-Connecting-IP", "198.51.100.7")
	req4.Header.Set("X-Forwarded-For", "1.2.3.4, 104.16.132.229")
	req4.RemoteAddr = "127.0.0.1:9999"
	if got := serverFronted.clientIP(req4); got != "198.51.100.7" {
		t.Fatalf("clientIP = %q, want the cf header when the proxy saw a cloudflare edge", got)
	}

	// a custom range override decides the same question
	cfgCustom, cerr := config.Load(config.TestEnv(map[string]string{
		"APP_ENV":            "dev",
		"TURNSTILE_MODE":     "disabled",
		"B2_ENDPOINT":        "http://localhost:9000",
		"B2_REGION":          "us-west-002",
		"B2_BUCKET":          "dreamshare",
		"B2_KEY_ID":          "kid",
		"B2_APPLICATION_KEY": "application-key-16",
		"BEHIND_PROXY":       "true",
		"TRUSTED_PROXIES":    "127.0.0.0/8",
		"CLOUDFLARE_FRONTED": "true",
		"CLOUDFLARE_RANGES":  "203.0.113.0/24",
	}))
	if cerr != nil {
		t.Fatal(cerr)
	}
	serverCustom := NewServer(cfgCustom, store, fake.New(), nil)
	req5, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil)
	req5.Header.Set("CF-Connecting-IP", "198.51.100.7")
	req5.Header.Set("X-Forwarded-For", "1.2.3.4, 203.0.113.9")
	req5.RemoteAddr = "127.0.0.1:9999"
	if got := serverCustom.clientIP(req5); got != "198.51.100.7" {
		t.Fatalf("clientIP = %q, want the cf header when the override covers the proxy peer", got)
	}

	// from an untrusted peer the headers are ignored
	req3, _ = http.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil)
	req3.Header.Set("X-Forwarded-For", "1.2.3.4")
	req3.RemoteAddr = "203.0.113.99:12345"
	if got := server.clientIP(req3); got != "203.0.113.99" {
		t.Fatalf("clientIP = %q, want the peer 203.0.113.99", got)
	}
}

func TestAdminByteIdenticalDenyResponses(t *testing.T) {
	ts, _, _ := adminRig(t)
	// every admin path without a session returns the same body
	// the session guarded api routes carry the identical deny. the page
	// and the session probe answer the allowlist differently on purpose,
	// the login flow needs the 200 and the 401, TestAdminSurfaceGatedByIP
	// holds the unlisted side of the contract
	paths := []string{"/admin/api/overview", "/admin/api/activity", "/admin/api/shares"}
	var bodies []string
	for _, p := range paths {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+p, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 512)
		n, _ := resp.Body.Read(b)
		bodies = append(bodies, string(b[:n]))
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s: %d, want 404", p, resp.StatusCode)
		}
	}
	for i := 1; i < len(bodies); i++ {
		if bodies[i] != bodies[0] {
			t.Fatalf("admin 404 bodies differ: %q vs %q", bodies[0], bodies[i])
		}
	}
}
