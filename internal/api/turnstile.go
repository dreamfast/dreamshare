package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"
)

// turnstileEndpoint is the production siteverify url, kept as a constant
// so the request path never mutates server state.
const turnstileEndpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

// turnstileVerify is fail closed: when Cloudflare cannot be reached the
// creation is rejected rather than silently letting bots in. The second
// return says whether cloudflare actually answered, an unreachable
// verifier must not count toward the auto block or an outage would lock
// out every real user.
func (s *Server) turnstileVerify(ctx context.Context, tokenValue, ip string) (accepted, definite bool) {
	if s.cfg.TurnstileSecret == "" {
		return false, false
	}
	if tokenValue == "" {
		// no token at all is deliberate scripting, not an outage
		return false, true
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	form := url.Values{}
	form.Set("secret", s.cfg.TurnstileSecret)
	form.Set("response", tokenValue)
	form.Set("remoteip", ip)

	url := turnstileEndpoint
	if s.turnstileURL != "" {
		// tests point the verifier at a local stub
		url = s.turnstileURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url,
		bytes.NewReader([]byte(form.Encode())))
	if err != nil {
		return false, false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// no redirects, the endpoint is fixed and anything else is a defect
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("redirect refused")
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		s.log.Warn("turnstile unreachable, failing closed", "err", err)
		return false, false
	}
	defer func() { _ = resp.Body.Close() }()
	// any completed response is cloudflare judging the request, a non 200
	// or undecodable body still means the verdict is definite rejection
	if resp.StatusCode != http.StatusOK {
		return false, true
	}
	var out struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<16)).Decode(&out); err != nil {
		return false, true
	}
	// cloudflare answered, so the verdict is a definite judgement on the
	// token and a rejection may strike
	return out.Success, true
}
