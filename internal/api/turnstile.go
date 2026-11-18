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

// turnstileVerify is fail closed: when Cloudflare cannot be reached the
// creation is rejected rather than silently letting bots in.
func (s *Server) turnstileVerify(ctx context.Context, tokenValue, ip string) bool {
	if s.cfg.TurnstileSecret == "" {
		return false
	}
	if tokenValue == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	form := url.Values{}
	form.Set("secret", s.cfg.TurnstileSecret)
	form.Set("response", tokenValue)
	form.Set("remoteip", ip)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://challenges.cloudflare.com/turnstile/v0/siteverify",
		bytes.NewReader([]byte(form.Encode())))
	if err != nil {
		return false
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
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	var out struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<16)).Decode(&out); err != nil {
		return false
	}
	return out.Success
}
