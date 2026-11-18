package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// securityHeaders sets the response hardening on every response including
// errors. The X-Robots-Tag matrix is the four route classes that must never
// be indexed.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob:; "+
				"font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")
		if s.cfg.Prod {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		switch {
		case hasPrefixAny(r.URL.Path, "/s/", "/m/", "/dl/", "/admin"):
			h.Set("X-Robots-Tag", "noindex, nofollow")
		}
		next.ServeHTTP(w, r)
	})
}

func hasPrefixAny(path string, prefixes ...string) bool {
	for _, p := range prefixes {
		if len(path) >= len(p) && path[:len(p)] == p {
			return true
		}
	}
	return false
}

// csrfStore is a bounded server side token store. Both the cookie token and
// the posted header must be known here, so a subdomain that can set cookies
// still cannot forge a valid pair.
type csrfStore struct {
	mu      sync.Mutex
	entries map[string]time.Time
	order   []string
	max     int
	ttl     time.Duration
}

func newCSRFStore() *csrfStore {
	return &csrfStore{
		entries: map[string]time.Time{},
		max:     8192,
		ttl:     12 * time.Hour,
	}
}

func (c *csrfStore) mint() string {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		// no entropy means no service
		panic("csprng unavailable: " + err.Error())
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	c.mu.Lock()
	defer c.mu.Unlock()
	// fifo order is tracked explicitly, map iteration is random and random
	// eviction could drop a live form's token mid flow
	for len(c.order) >= c.max {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, oldest)
	}
	c.entries[token] = time.Now()
	c.order = append(c.order, token)
	return token
}

func (c *csrfStore) valid(token string) bool {
	if token == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	at, ok := c.entries[token]
	if !ok {
		return false
	}
	if time.Since(at) > c.ttl {
		delete(c.entries, token)
		return false
	}
	return true
}

func (s *Server) requireCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("ds_csrf")
		header := r.Header.Get("X-CSRF-Token")
		if err != nil || cookie.Value == "" || cookie.Value != header || !s.csrf.valid(header) {
			writeError(w, http.StatusForbidden, "csrf")
			return
		}
		next(w, r)
	}
}

// tier names the rate limit buckets. Uploads are strict, part traffic is
// permissive because one file means many requests, everything else normal.
type tier int

const (
	tierCreate tier = iota
	tierPart
	tierCheck
	tierBootstrap
	tierDownload
	tierCount
)

// limit is the requests per window for the tier, the window itself is one
// hour for every tier.
func (t tier) limit() int {
	switch t {
	case tierCreate:
		return 10
	case tierPart:
		return 600
	case tierCheck:
		return 240
	case tierBootstrap:
		// generous but bounded, an unauthenticated flood must not be able to
		// churn the csrf store through fifo eviction
		return 120
	case tierDownload:
		return 120
	case tierCount:
		return 240
	default:
		return 240
	}
}

// limiter is a fixed window counter per ip and tier. Sliding window
// precision is not worth the complexity at this traffic level, the property
// that matters is that a busy ip never gets locked out by resetting windows.
type limiter struct {
	mu      sync.Mutex
	buckets map[string]int
	window  time.Time
	boost   int
}

func newLimiter() *limiter {
	return &limiter{buckets: map[string]int{}}
}

func (l *limiter) allow(key string, t tier) bool {
	limit := t.limit()
	if l.boost > 1 {
		limit *= l.boost
	}
	span := time.Hour
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now().Truncate(span)
	if !l.window.Equal(now) {
		// the window rolled for everyone together, a busy ip does not hold
		// the reset hostage
		l.buckets = map[string]int{}
		l.window = now
	}
	l.buckets[key]++
	return l.buckets[key] <= limit
}

func (s *Server) limited(t tier, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// the admin kill switch: a blocked cidr answers before the tier
		// check, before any crypto, before any storage
		ip := s.clientIP(r)
		if s.ipBlocked(r.Context(), ip) {
			writeError(w, http.StatusForbidden, "blocked")
			return
		}
		// one bucket per ip and tier, a shared bucket would let the strict
		// create ceiling be eaten by permissive part traffic
		if !s.limiter.allow(ip+"|"+strconv.Itoa(int(t)), t) {
			writeError(w, http.StatusTooManyRequests, "rate_limited")
			return
		}
		next(w, r)
	}
}

func contextWithTimeout(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, d)
}
