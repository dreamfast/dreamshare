package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dreamfast/dreamshare/internal/config"
	"github.com/dreamfast/dreamshare/internal/storage/b2/fake"
	"github.com/dreamfast/dreamshare/internal/storage/sqlite"
	"github.com/dreamfast/dreamshare/internal/token"
)

type rig struct {
	t       *testing.T
	srv     *httptest.Server
	store   *sqlite.Store
	objects *fake.Store
	cfg     *config.Config
}

func newRig(t *testing.T, envOverrides map[string]string) *rig {
	t.Helper()
	base := map[string]string{
		"APP_ENV":            "dev",
		"TURNSTILE_MODE":     "disabled",
		"B2_ENDPOINT":        "http://localhost:9000",
		"B2_REGION":          "us-west-002",
		"B2_BUCKET":          "dreamshare",
		"B2_KEY_ID":          "kid",
		"B2_APPLICATION_KEY": "application-key-16",
	}
	for k, v := range envOverrides {
		if v == "" {
			delete(base, k)
		} else {
			base[k] = v
		}
	}
	cfg, err := config.Load(config.TestEnv(base))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	store, err := sqlite.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	objects := fake.New()
	server := NewServer(cfg, store, objects, nil)
	ts := httptest.NewServer(server.Handler())
	t.Cleanup(ts.Close)
	return &rig{t: t, srv: ts, store: store, objects: objects, cfg: cfg}
}

func (rg *rig) do(method, path string, body []byte, hdr map[string]string) *http.Response {
	rg.t.Helper()
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(rg.t.Context(), method, rg.srv.URL+path, rdr)
	if err != nil {
		rg.t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if body != nil && req.ContentLength == 0 {
		req.ContentLength = int64(len(body))
	}
	resp, err := rg.srv.Client().Do(req)
	if err != nil {
		rg.t.Fatal(err)
	}
	return resp
}

func (rg *rig) bootstrap() map[string]string {
	rg.t.Helper()
	resp := rg.do("GET", "/api/bootstrap", nil, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		rg.t.Fatalf("bootstrap: %d", resp.StatusCode)
	}
	var out struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		rg.t.Fatal(err)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "ds_csrf" {
			return map[string]string{
				"Cookie":       "ds_csrf=" + c.Value,
				"X-CSRF-Token": c.Value,
			}
		}
	}
	rg.t.Fatal("no csrf cookie")
	return nil
}

// uploadShare drives a full upload for n files of the given ciphertext
// sizes and returns the share id, the manager token and the csrf headers.
func (rg *rig) uploadShare(files []int64, expiryMode string) (string, string, map[string]string) {
	rg.t.Helper()
	csrf := rg.bootstrap()

	var fileList []map[string]any
	for _, size := range files {
		// one part per MiB of ciphertext, the part planner in miniature
		parts := int((size + 1<<20 - 1) / (1 << 20))
		fileList = append(fileList, map[string]any{
			"size": size, "frame_count": parts, "frame_size": 1 << 20, "part_size": 1 << 20, "expected_parts": parts,
		})
	}
	body, _ := json.Marshal(map[string]any{
		"files": fileList, "expiry_mode": expiryMode, "expiry_days": 1,
	})
	resp := rg.do("POST", "/api/shares", body, csrf)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		rg.t.Fatalf("create: %d %s", resp.StatusCode, b)
	}
	var created createResponse
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		rg.t.Fatal(err)
	}

	// upload each file as deterministic ciphertext
	filesLen := len(files)
	for i, sess := range created.UploadSessions {
		if i < 0 || i >= filesLen {
			rg.t.Fatalf("session index %d outside files 0..%d", i, filesLen-1)
			continue
		}
		size := files[i] //nolint:gosec // guarded above, gosec misses the fatalf guard form

		data := deterministic(size, byte(i))
		sent := 0
		for p := 1; sent < int(size); p++ {
			end := sent + 1<<20
			if end > int(size) {
				end = int(size)
			}
			chunk := data[sent:end]
			sum := sha256.Sum256(chunk)
			hdr := map[string]string{
				"Cookie":        csrf["Cookie"],
				"X-CSRF-Token":  csrf["X-CSRF-Token"],
				"X-Part-Token":  token.PartToken(rg.chunkSecret(rg.t, sess.SessionID), sess.SessionID, p),
				"X-Part-SHA256": hex.EncodeToString(sum[:]),
			}
			// part 1 token comes from the response, later ones from next_tokens
			if p > 1 {
				hdr["X-Part-Token"] = rg.nextToken(rg.t, sess.SessionID, p)
			}
			pre := rg.do("POST", fmt.Sprintf("/api/sessions/%s/parts/%d", sess.SessionID, p), chunk, hdr)
			if pre.StatusCode != http.StatusOK {
				b, _ := io.ReadAll(pre.Body)
				rg.t.Fatalf("part %d: %d %s", p, pre.StatusCode, b)
			}
			sent = end
		}
		done := rg.do("POST", fmt.Sprintf("/api/sessions/%s/complete", sess.SessionID), []byte("{}"),
			map[string]string{
				"Cookie": csrf["Cookie"], "X-CSRF-Token": csrf["X-CSRF-Token"],
				"X-Part-Token": token.PartToken(rg.chunkSecret(rg.t, sess.SessionID), sess.SessionID, 1),
			})
		defer func() { _ = done.Body.Close() }()
		if done.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(done.Body)
			rg.t.Fatalf("complete: %d %s", done.StatusCode, b)
		}
	}

	blobs := map[string]any{
		"title_ct":    base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("t"), 8)),
		"manifest_ct": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("m"), 64)),
		"check_ct":    base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("c"), 45)),
	}
	fb, _ := json.Marshal(blobs)
	fin := rg.do("POST", "/api/shares/"+created.ShareID+"/finalize", fb, csrf) //nolint:misspell // the route token
	if fin.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(fin.Body)
		rg.t.Fatalf("finalise: %d %s", fin.StatusCode, b)
	}
	return created.ShareID, created.ManagerToken, csrf
}

var (
	secretsMu sync.Mutex
	secrets   = map[string][]byte{}
)

func (rg *rig) chunkSecret(t *testing.T, sessionID string) []byte {
	t.Helper()
	secretsMu.Lock()
	defer secretsMu.Unlock()
	if s, ok := secrets[sessionID]; ok {
		return s
	}
	var secret []byte
	err := rg.store.Reader.QueryRowContext(rg.t.Context(), "select chunk_secret from upload_sessions where id = ?", sessionID).Scan(&secret)
	if err != nil {
		t.Fatal(err)
	}
	secrets[sessionID] = secret
	return secret
}

func (rg *rig) nextToken(t *testing.T, sessionID string, p int) string {
	t.Helper()
	return token.PartToken(rg.chunkSecret(t, sessionID), sessionID, p)
}

func deterministic(n int64, seed byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i%251) ^ seed
	}
	return out
}

func (rg *rig) fileIDFor(shareID string, index int) string {
	rg.t.Helper()
	var id string
	err := rg.store.Reader.QueryRowContext(rg.t.Context(),
		"select id from share_files where share_id = ? order by position limit 1 offset ?", shareID, index).Scan(&id)
	if err != nil {
		rg.t.Fatal(err)
	}
	return id
}

func TestUploadDownloadAckWipe(t *testing.T) {
	rg := newRig(t, nil)
	shareID, _, csrf := rg.uploadShare([]int64{2_500_000, 300}, "burn_on_ack")

	// download both files
	f1 := rg.fileIDFor(shareID, 0)
	f2 := rg.fileIDFor(shareID, 1)
	resp := rg.do("GET", "/dl/"+shareID+"/"+f1, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("download 1: %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("content type %q", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment") {
		t.Fatalf("disposition %q", cd)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(body, deterministic(2_500_000, 0)) {
		t.Fatal("ciphertext mismatch")
	}
	resp2 := rg.do("GET", "/dl/"+shareID+"/"+f2, nil, nil)
	_, _ = io.Copy(io.Discard, resp2.Body)

	// counters: two logical downloads
	sh, _ := rg.store.GetShare(t.Context(), shareID)
	if sh.DownloadsUsed != 2 {
		t.Fatalf("downloads_used %d, want 2", sh.DownloadsUsed)
	}

	// ack both, the second flips
	ack := func(fid string) {
		b, _ := json.Marshal(map[string]any{"file_id": fid, "verified": true})
		resp := rg.do("POST", "/api/shares/"+shareID+"/ack", b, csrf)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("ack %s: %d", fid, resp.StatusCode)
		}
	}
	ack(f1)
	sh, _ = rg.store.GetShare(t.Context(), shareID)
	if sh.Status != "active" {
		t.Fatalf("status %s after partial ack", sh.Status)
	}
	ack(f2)

	// the wipe is async, poll briefly
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		sh, _ = rg.store.GetShare(t.Context(), shareID)
		if sh.Status == "delivered" || sh.Status == "wiped" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if sh.Status != "delivered" && sh.Status != "wiped" {
		t.Fatalf("status %s after full ack", sh.Status)
	}

	// downloads refuse after delivery
	resp = rg.do("GET", "/dl/"+shareID+"/"+f1, nil, nil)
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("download after delivery: %d", resp.StatusCode)
	}
}

func TestRangeContinuationDoesNotDoubleCount(t *testing.T) {
	rg := newRig(t, nil)
	shareID, _, _ := rg.uploadShare([]int64{2_500_000}, "burn_on_ack")
	f1 := rg.fileIDFor(shareID, 0)

	resp := rg.do("GET", "/dl/"+shareID+"/"+f1, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("full fetch: %d", resp.StatusCode)
	}
	_, _ = io.Copy(io.Discard, resp.Body)

	resp = rg.do("GET", "/dl/"+shareID+"/"+f1, nil, map[string]string{"Range": "bytes=1000000-"})
	if resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("continuation: %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(b, deterministic(2_500_000, 0)[1_000_000:]) {
		t.Fatal("continuation bytes mismatch")
	}

	sh, _ := rg.store.GetShare(t.Context(), shareID)
	if sh.DownloadsUsed != 1 {
		t.Fatalf("downloads_used %d after resume, want 1", sh.DownloadsUsed)
	}
}

func TestPartHashMismatchRejected(t *testing.T) {
	rg := newRig(t, nil)
	csrf := rg.bootstrap()
	body, _ := json.Marshal(map[string]any{
		"files":       []map[string]any{{"size": 1000, "frame_count": 1, "frame_size": 1 << 20, "part_size": 1 << 20, "expected_parts": 1}},
		"expiry_mode": "ttl", "expiry_days": 1,
	})
	resp := rg.do("POST", "/api/shares", body, csrf)
	var created createResponse
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		rg.t.Fatal(err)
	}
	sess := created.UploadSessions[0]

	chunk := deterministic(1000, 7)
	hdr := map[string]string{
		"Cookie": csrf["Cookie"], "X-CSRF-Token": csrf["X-CSRF-Token"],
		"X-Part-Token":  token.PartToken(rg.chunkSecret(rg.t, sess.SessionID), sess.SessionID, 1),
		"X-Part-SHA256": strings.Repeat("0", 64),
	}
	bad := rg.do("POST", "/api/sessions/"+sess.SessionID+"/parts/1", chunk, hdr)
	if bad.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("hash mismatch: %d", bad.StatusCode)
	}
}

func TestCSRFRequiredOnMutations(t *testing.T) {
	rg := newRig(t, nil)
	resp := rg.do("POST", "/api/shares", []byte("{}"), nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("no csrf: %d", resp.StatusCode)
	}
}

func TestQuotaRefused(t *testing.T) {
	rg := newRig(t, map[string]string{"DAILY_IP_BYTES": "1000"})
	csrf := rg.bootstrap()
	body, _ := json.Marshal(map[string]any{
		"files":       []map[string]any{{"size": 5000, "frame_count": 1, "frame_size": 1 << 20, "part_size": 1 << 20, "expected_parts": 1}},
		"expiry_mode": "ttl",
		"expiry_days": 1,
	})
	resp := rg.do("POST", "/api/shares", body, csrf)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("over quota create: %d", resp.StatusCode)
	}
}

func TestTurnstileFailClosed(t *testing.T) {
	rg := newRig(t, map[string]string{
		"TURNSTILE_MODE":     "required",
		"TURNSTILE_SITE_KEY": "0123456789abcdefghijk",
		"TURNSTILE_SECRET":   "0123456789abcdefghijk",
	})
	csrf := rg.bootstrap()
	body, _ := json.Marshal(map[string]any{"files": nil, "expiry_mode": "ttl", "expiry_days": 1})
	// no turnstile token and the siteverify call will fail closed in tests
	resp := rg.do("POST", "/api/shares", body, csrf)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("turnstile bypass: %d", resp.StatusCode)
	}
}

func TestNotifyThrottle(t *testing.T) {
	rg := newRig(t, nil)
	shareID, _, csrf := rg.uploadShare(nil, "burn_on_ack")
	send := func() int {
		b, _ := json.Marshal(map[string]string{"to": "owner@example.com"})
		resp := rg.do("POST", "/api/shares/"+shareID+"/notify", b, csrf)
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	if got := send(); got != 200 {
		t.Fatalf("first notify: %d", got)
	}
	if got := send(); got != http.StatusTooManyRequests {
		t.Fatalf("second notify: %d", got)
	}
}

func TestManagerGetNeverRevokes(t *testing.T) {
	rg := newRig(t, nil)
	shareID, mgr, _ := rg.uploadShare([]int64{1000}, "burn_on_ack")

	resp := rg.do("GET", "/m/"+mgr, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("manager page: %d", resp.StatusCode)
	}
	if rt := resp.Header.Get("X-Robots-Tag"); !strings.Contains(rt, "noindex") {
		t.Fatalf("manager page robots: %q", rt)
	}
	sh, _ := rg.store.GetShare(t.Context(), shareID)
	if sh.Status != "active" {
		t.Fatalf("GET revoked the share: %s", sh.Status)
	}

	revoked := rg.do("POST", "/m/"+mgr, nil, nil)
	if revoked.StatusCode != http.StatusOK {
		t.Fatalf("manager revoke: %d", revoked.StatusCode)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		sh, _ = rg.store.GetShare(t.Context(), shareID)
		if sh.Status == "revoked" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if sh.Status != "revoked" {
		t.Fatalf("status %s after revoke", sh.Status)
	}
	if len(rg.objects.Keys()) != 0 {
		t.Fatalf("objects survived revoke: %v", rg.objects.Keys())
	}
}

// the csp pins the page to same origin everything, a loosened directive
// must fail here rather than ship silently
func TestStaticCSP(t *testing.T) {
	rg := newRig(t, nil)
	// the test rig wires no spa bundle so / 404s, but the header middleware
	// wraps every response including errors, the csp must be there anyway
	resp := rg.do("GET", "/", nil, nil)
	csp := resp.Header.Get("Content-Security-Policy")
	want := []string{
		"default-src 'none'",
		"script-src 'self'",
		"style-src 'self'",
		"font-src 'self'",
		"img-src 'self' blob:",
		"connect-src 'self'",
		"frame-ancestors 'none'",
		"base-uri 'none'",
		"form-action 'self'",
		"object-src 'none'",
	}
	for _, w := range want {
		if !strings.Contains(csp, w) {
			t.Fatalf("csp missing %q in %q", w, csp)
		}
	}
	// the §13 hard nos, a loosened script-src with unsafe-inline or eval is
	// the classic quiet regression
	for _, banned := range []string{"unsafe-inline", "unsafe-eval", "://", "*", "data:"} {
		if strings.Contains(csp, banned) {
			t.Fatalf("csp allows %q: %q", banned, csp)
		}
	}
	if n := strings.Count(csp, "http"); n != 0 {
		t.Fatalf("csp allows a remote origin: %q", csp)
	}
}

func TestCheckNeverCountsAndPendingHidden(t *testing.T) {
	rg := newRig(t, nil)
	shareID, _, _ := rg.uploadShare([]int64{1000}, "burn_on_ack")
	resp := rg.do("GET", "/api/shares/"+shareID+"/check", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("check: %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if len(b) != 45 {
		t.Fatalf("check blob %d bytes", len(b))
	}
	sh, _ := rg.store.GetShare(t.Context(), shareID)
	if sh.DownloadsUsed != 0 {
		t.Fatal("check moved the download counter")
	}
}

func TestReconcilerExpiresAndDeletes(t *testing.T) {
	rg := newRig(t, nil)
	shareID, _, _ := rg.uploadShare([]int64{1000}, "ttl")
	// force the clock past the ceiling
	if _, err := rg.store.Writer.ExecContext(rg.t.Context(), "update shares set expires_at = ?", time.Now().Add(-time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}

	server := NewServer(rg.cfg, rg.store, rg.objects, nil)
	if err := server.ReconcileOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	sh, _ := rg.store.GetShare(t.Context(), shareID)
	if sh.Status != "expired" {
		t.Fatalf("status %s after reconcile", sh.Status)
	}
	// tombstone sweep past the window removes everything
	if _, err := rg.store.Writer.ExecContext(rg.t.Context(), "update shares set terminal_at = ?", time.Now().Add(-48*time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	n, err := rg.store.SweepTombstones(t.Context(), time.Now().Add(-24*time.Hour))
	if err != nil || n == 0 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	if _, err := rg.store.GetShare(t.Context(), shareID); !errors.Is(err, sqlite.ErrNotFound) {
		t.Fatalf("share row survived the sweep: %v", err)
	}
}

func TestFinalizeCapsRefusedAndShareStaysPending(t *testing.T) {
	rg := newRig(t, nil)
	csrf := rg.bootstrap()
	body, _ := json.Marshal(map[string]any{
		"files":       []map[string]any{{"size": 1000, "frame_count": 1, "frame_size": 1 << 20, "part_size": 1 << 20, "expected_parts": 1}},
		"expiry_mode": "ttl",
		"expiry_days": 1,
	})
	resp := rg.do("POST", "/api/shares", body, csrf)
	var created createResponse
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	sess := created.UploadSessions[0]
	chunk := deterministic(1000, 3)
	sum := sha256.Sum256(chunk)
	part := rg.do("POST", "/api/sessions/"+sess.SessionID+"/parts/1", chunk, map[string]string{
		"Cookie": csrf["Cookie"], "X-CSRF-Token": csrf["X-CSRF-Token"],
		"X-Part-Token":  token.PartToken(rg.chunkSecret(t, sess.SessionID), sess.SessionID, 1),
		"X-Part-SHA256": hex.EncodeToString(sum[:]),
	})
	if part.StatusCode != http.StatusOK {
		t.Fatalf("part: %d", part.StatusCode)
	}
	rg.do("POST", "/api/sessions/"+sess.SessionID+"/complete", []byte("{}"), map[string]string{
		"Cookie": csrf["Cookie"], "X-CSRF-Token": csrf["X-CSRF-Token"],
		"X-Part-Token": token.PartToken(rg.chunkSecret(t, sess.SessionID), sess.SessionID, 1),
	})

	over, _ := json.Marshal(map[string]string{
		"title_ct":    base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), 4097)),
		"manifest_ct": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("m"), 64)),
		"check_ct":    base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("c"), 45)),
	})
	fin := rg.do("POST", "/api/shares/"+created.ShareID+"/finalize", over, csrf) //nolint:misspell // the route token
	if fin.StatusCode != http.StatusBadRequest {
		t.Fatalf("over cap finalise: %d", fin.StatusCode)
	}
	sh, _ := rg.store.GetShare(t.Context(), created.ShareID)
	if sh.Status != "pending" {
		t.Fatalf("status %s after refused finalise, want pending", sh.Status)
	}
}

func TestRangeHonoursEndAndExhaustionRefused(t *testing.T) {
	rg := newRig(t, nil)
	shareID, _, _ := rg.uploadShare([]int64{2_500_000}, "burn_on_ack")
	f1 := rg.fileIDFor(shareID, 0)

	resp := rg.do("GET", "/dl/"+shareID+"/"+f1, nil, map[string]string{"Range": "bytes=0-0"})
	if resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("bytes=0-0: %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if len(b) != 1 {
		t.Fatalf("bytes=0-0 served %d bytes", len(b))
	}

	// exhaust the per file attempts with byte zero starts
	for i := 0; i < 4; i++ {
		r := rg.do("GET", "/dl/"+shareID+"/"+f1, nil, nil)
		_, _ = io.Copy(io.Discard, r.Body)
	}
	// a continuation must now be refused too, the cap cannot be dodged by
	// starting at byte one
	r := rg.do("GET", "/dl/"+shareID+"/"+f1, nil, map[string]string{"Range": "bytes=1-"})
	if r.StatusCode != http.StatusGone {
		t.Fatalf("range after exhaustion: %d", r.StatusCode)
	}
}

func TestEgressQuotaAbortsMidStream(t *testing.T) {
	// the upload itself spends quota, so the file fits inside the budget
	// while the download cannot
	rg := newRig(t, map[string]string{"DAILY_IP_BYTES": "1500000"})
	shareID, _, _ := rg.uploadShare([]int64{1_200_000}, "burn_on_ack")
	f1 := rg.fileIDFor(shareID, 0)
	resp := rg.do("GET", "/dl/"+shareID+"/"+f1, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("download start: %d", resp.StatusCode)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	if err == nil {
		t.Fatalf("copy completed with %d bytes despite the quota", n)
	}
	if n > 400_000 {
		t.Fatalf("streamed %d bytes, the ceiling is soft", n)
	}
}

func TestForwardedForSpoofIgnoredWithoutProxy(t *testing.T) {
	rg := newRig(t, nil)
	shareID, _, _ := rg.uploadShare([]int64{1000}, "burn_on_ack")
	_ = shareID
	resp := rg.do("GET", "/healthz", nil, map[string]string{"X-Forwarded-For": "1.2.3.4"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: %d", resp.StatusCode)
	}
	// behind no proxy the header is ignored, the limiter keys on the peer
	resp2 := rg.do("GET", "/healthz", nil, map[string]string{"X-Forwarded-For": "1.2.3.4"})
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("healthz again: %d", resp2.StatusCode)
	}
}

// Two parts in flight at once, the browser pipeline shape.
func TestConcurrentPartsThenComplete(t *testing.T) {
	rg := newRig(t, nil)
	csrf := rg.bootstrap()
	body, _ := json.Marshal(map[string]any{
		"files": []map[string]any{{
			"size": 2 * (1 << 20), "frame_count": 2, "frame_size": 1 << 20,
			"part_size": 1 << 20, "expected_parts": 2,
		}},
		"expiry_mode": "ttl", "expiry_days": 1,
	})
	resp := rg.do("POST", "/api/shares", body, csrf)
	var created createResponse
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	sess := created.UploadSessions[0]

	send := func(n int) error {
		chunk := deterministic(1<<20, byte(n%251)) //nolint:gosec // loop bound is 2, test fixture only
		sum := sha256.Sum256(chunk)
		hdr := map[string]string{
			"Cookie": csrf["Cookie"], "X-CSRF-Token": csrf["X-CSRF-Token"],
			"X-Part-Token":  token.PartToken(rg.chunkSecret(t, sess.SessionID), sess.SessionID, n),
			"X-Part-SHA256": hex.EncodeToString(sum[:]),
		}
		r := rg.do("POST", fmt.Sprintf("/api/sessions/%s/parts/%d", sess.SessionID, n), chunk, hdr)
		b, _ := io.ReadAll(r.Body)
		if r.StatusCode != http.StatusOK {
			return fmt.Errorf("part %d: %d %s", n, r.StatusCode, b)
		}
		return nil
	}

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for n := 1; n <= 2; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			errs <- send(n)
		}(n)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	done := rg.do("POST", fmt.Sprintf("/api/sessions/%s/complete", sess.SessionID), []byte("{}"), map[string]string{
		"Cookie": csrf["Cookie"], "X-CSRF-Token": csrf["X-CSRF-Token"],
		"X-Part-Token": token.PartToken(rg.chunkSecret(t, sess.SessionID), sess.SessionID, 1),
	})
	b, _ := io.ReadAll(done.Body)
	t.Logf("complete: %d %s", done.StatusCode, b)
	if done.StatusCode != http.StatusOK {
		t.Fatalf("complete failed: %s", b)
	}
}
