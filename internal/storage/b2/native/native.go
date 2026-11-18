// Package native is a minimal Backblaze B2 Native API client for the calls
// the S3 endpoint cannot express: authorizing with application keys,
// listing file versions by name, deleting a specific file version and
// reading lifecycle rules. Keep it small, the S3 client carries the data
// path.
package native

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// authURL is a var so the race test can point the client at a local
// double. Production never changes it.
var authURL = "https://api.backblazeb2.com/b2api/v3/b2_authorize_account"

// Client holds the authorization state, the token refreshes on each New
// call and lives as long as the process.
type apiInfo struct {
	StorageAPI struct {
		APIURL                  string `json:"apiUrl"`
		AbsoluteMinimumPartSize int64  `json:"absoluteMinimumPartSize"`
	} `json:"storageApi"`
}

type Client struct {
	http    *http.Client
	mu      sync.Mutex
	auth    string // the authorizationToken, guarded by mu
	apiURL  string // guarded by mu
	account string
	keyID   string
	appKey  string
	// AbsoluteMinimumPartSize comes from the authorize response, the
	// measured value on this account was 5,000,000 bytes
	AbsoluteMinimumPartSize int64
}

// New authorises with an application key. The key id is the K0 style value,
// the app key is the secret shown once at creation.
func New(ctx context.Context, keyID, appKey string) (*Client, error) {
	c := &Client{
		http: &http.Client{
			Timeout: 30 * time.Second,
			// the token must never follow a redirect, not even a same host
			// downgrade from https to http
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		keyID:  keyID,
		appKey: appKey,
	}
	var out struct {
		AccountID string  `json:"accountId"`
		Token     string  `json:"authorizationToken"`
		APIInfo   apiInfo `json:"apiInfo"`
	}
	if err := c.call(ctx, http.MethodGet, authURL, "", basicAuth(keyID, appKey), "", &out); err != nil {
		return nil, fmt.Errorf("authorize: %w", err)
	}
	apiURL := out.APIInfo.StorageAPI.APIURL
	if apiURL == "" {
		// defensive fallback, the grouping has changed before
		apiURL = findString(out.APIInfo, "apiUrl")
	}
	if apiURL == "" {
		return nil, fmt.Errorf("authorise: no apiUrl inside apiInfo")
	}
	if !strings.HasPrefix(apiURL, "https://") {
		return nil, fmt.Errorf("authorise: api url is not https, refusing")
	}
	c.AbsoluteMinimumPartSize = out.APIInfo.StorageAPI.AbsoluteMinimumPartSize
	c.auth = out.Token
	c.apiURL = strings.TrimSuffix(apiURL, "/")
	c.account = out.AccountID
	return c, nil
}

// FileVersion is one version of one object, newest first from the API.
type FileVersion struct {
	ID         string `json:"fileId"`
	Name       string `json:"fileName"`
	Size       int64  `json:"contentLength"`
	UploadTS   int64  `json:"uploadTimestamp"`
	Action     string `json:"action"`
	HideMarker bool   // derived from Action == hide, the wire field fileRetention is an object not a bool
}

// ListVersionsByName returns every version under one exact object name.
// Unique server minted keys mean at most one live version plus delete
// markers, this exists to resolve a version id when the S3 path did not
// surface one.
func (c *Client) ListVersionsByName(ctx context.Context, bucketID, name string) ([]FileVersion, error) {
	q := url.Values{}
	q.Set("bucketId", bucketID)
	q.Set("startFileName", name)
	q.Set("maxFileCount", "100")
	var out struct {
		Files []struct {
			FileID          string `json:"fileId"`
			FileName        string `json:"fileName"`
			ContentLength   int64  `json:"contentLength"`
			UploadTimestamp int64  `json:"uploadTimestamp"`
			Action          string `json:"action"`
		} `json:"files"`
		NextFileName string `json:"nextFileName"`
	}
	c.mu.Lock()
	apiBase := c.apiURL
	c.mu.Unlock()
	if err := c.call(ctx, http.MethodGet, apiBase+"/b2api/v3/b2_list_file_versions", q.Encode(), "", "", &out); err != nil {
		return nil, fmt.Errorf("list versions: %w", err)
	}
	var versions []FileVersion
	for _, f := range out.Files {
		if f.FileName != name {
			continue
		}
		versions = append(versions, FileVersion{
			ID: f.FileID, Name: f.FileName, Size: f.ContentLength, UploadTS: f.UploadTimestamp,
			Action: f.Action, HideMarker: f.Action == "hide",
		})
	}
	return versions, nil
}

// DeleteAllVersionsByName removes every version under one exact name and
// returns how many went. Keys are unique per file in this app, this exists
// for cleanup and the spike.
func (c *Client) DeleteAllVersionsByName(ctx context.Context, bucketID, name string) (int, error) {
	versions, err := c.ListVersionsByName(ctx, bucketID, name)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, v := range versions {
		if err := c.DeleteVersion(ctx, name, v.ID); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// DeleteVersion removes one specific version of one object. The argument
// order matches the b2.Store seam exactly, key first, so this client
// satisfies minio.VersionDeleter without an adapter and without a swap.
func (c *Client) DeleteVersion(ctx context.Context, key, fileID string) error {
	body := fmt.Sprintf(`{"fileId":%q,"fileName":%q}`, fileID, key)
	var out map[string]any
	c.mu.Lock()
	apiBase := c.apiURL
	c.mu.Unlock()
	if err := c.call(ctx, http.MethodPost, apiBase+"/b2api/v3/b2_delete_file_version", "", "", body, &out); err != nil {
		return fmt.Errorf("delete version %s: %w", fileID, err)
	}
	return nil
}

// LifecycleRule is one bucket lifecycle rule as B2 stores it.
type LifecycleRule struct {
	DaysFromUploadingToHiding int    `json:"daysFromUploadingToHiding"`
	DaysFromHidingToDeleting  int    `json:"daysFromHidingToDeleting"`
	FileNamePrefix            string `json:"fileNamePrefix"`
}

// LifecycleRules reads the bucket rules. B2 has no S3 PutBucketLifecycle,
// rules live in the console or here, and the app verifies rather than
// trusts.
func (c *Client) LifecycleRules(ctx context.Context, bucketID string) ([]LifecycleRule, error) {
	q := url.Values{}
	q.Set("bucketId", bucketID)
	var out struct {
		LifecycleRules []struct {
			DaysFromUploadingToHiding any `json:"daysFromUploadingToHiding"`
			DaysFromHidingToDeleting  any `json:"daysFromHidingToDeleting"`
			FileNamePrefix            any `json:"fileNamePrefix"`
		} `json:"lifecycleRules"`
	}
	c.mu.Lock()
	apiBase := c.apiURL
	c.mu.Unlock()
	if err := c.call(ctx, http.MethodGet, apiBase+"/b2api/v3/b2_get_bucket", q.Encode(), "", "", &out); err != nil {
		return nil, fmt.Errorf("get bucket: %w", err)
	}
	var rules []LifecycleRule
	for _, r := range out.LifecycleRules {
		rule := LifecycleRule{}
		rule.DaysFromUploadingToHiding = toInt(r.DaysFromUploadingToHiding)
		rule.DaysFromHidingToDeleting = toInt(r.DaysFromHidingToDeleting)
		if p, ok := r.FileNamePrefix.(string); ok {
			rule.FileNamePrefix = p
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// findString walks a nested json object for the first string value under
// the given key.
func findString(v any, key string) string {
	switch t := v.(type) {
	case map[string]any:
		if s, ok := t[key].(string); ok {
			return s
		}
		for _, inner := range t {
			if s := findString(inner, key); s != "" {
				return s
			}
		}
	case []any:
		for _, inner := range t {
			if s := findString(inner, key); s != "" {
				return s
			}
		}
	}
	return ""
}

func toInt(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case string:
		n, _ := strconv.Atoi(x)
		return n
	default:
		return 0
	}
}

// reauth refreshes the session token after expiry.
func (c *Client) reauth(ctx context.Context) error {
	var out struct {
		Token   string  `json:"authorizationToken"`
		APIInfo apiInfo `json:"apiInfo"`
	}
	if err := c.call(ctx, http.MethodGet, authURL, "", basicAuth(c.keyID, c.appKey), "", &out); err != nil {
		return fmt.Errorf("reauthorise: %w", err)
	}
	// validate everything first, then publish both fields under the lock in
	// one motion, a rejected url writes nothing
	c.mu.Lock()
	newURL := c.apiURL
	c.mu.Unlock()
	if u := out.APIInfo.StorageAPI.APIURL; u != "" {
		if !strings.HasPrefix(u, "https://") {
			return fmt.Errorf("reauthorise: api url is not https")
		}
		newURL = strings.TrimSuffix(u, "/")
	}
	c.mu.Lock()
	c.auth = out.Token
	c.apiURL = newURL
	c.mu.Unlock()
	return nil
}

func basicAuth(keyID, appKey string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(keyID+":"+appKey))
}

func (c *Client) call(ctx context.Context, method, endpoint, query, auth, body string, out any) error {
	return c.callDepth(ctx, method, endpoint, query, auth, body, out, 0)
}

// callDepth bounds reauthorisation retries, one refresh per call at most.
func (c *Client) callDepth(ctx context.Context, method, endpoint, query, auth, body string, out any, depth int) error {
	u := endpoint
	if query != "" {
		u += "?" + query
	}
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return err
	}
	if auth == "" {
		c.mu.Lock()
		auth = c.auth
		c.mu.Unlock()
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusUnauthorized && strings.Contains(string(raw), "expired_auth_token") && !strings.Contains(u, authURL) && depth == 0 {
		// tokens live a day, a long running server re-authorises, at most
		// once per call so a persistent 401 cannot loop
		if rerr := c.reauth(ctx); rerr != nil {
			return rerr
		}
		c.mu.Lock()
		fresh := c.auth
		c.mu.Unlock()
		return c.callDepth(ctx, method, endpoint, query, fresh, body, out, 1)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d: %.200s", resp.StatusCode, raw)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}
