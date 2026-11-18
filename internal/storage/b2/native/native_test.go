package native

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

// The falsifier the review named: a token refresh in one request must not
// race every other request. Runs under -race in the normal suite.
func TestReauthNoRaceUnderConcurrency(t *testing.T) {
	var hits atomic.Int64
	data := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":"expired_auth_token"}`))
			return
		}
		// an empty token value also counts as expired
		if auth := r.Header.Get("Authorization"); len(auth) < 10 {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":"expired_auth_token"}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer data.Close()

	auth := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"accountId":          "acct",
			"authorizationToken": fmt.Sprintf("token-%d", hits.Add(1)),
			"apiInfo": map[string]any{
				"storageApi": map[string]any{"apiUrl": data.URL},
			},
		})
	}))
	defer auth.Close()

	orig := authURL
	authURL = auth.URL
	t.Cleanup(func() { authURL = orig })

	// the test doubles use self signed certs, verification is the real
	// server's job in production
	testClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // test double certs
	c := &Client{
		http:  testClient,
		keyID: "k", appKey: "s",
	}
	if err := c.reauth(t.Context()); err != nil {
		t.Fatalf("seed reauth: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				// some calls hit an expired token and refresh, the rest
				// race them through the normal path
				_ = c.DeleteVersion(t.Context(), "f/2608/x", "4_zid")
				_ = c.reauth(t.Context())
			}
		}()
	}
	wg.Wait()
}
