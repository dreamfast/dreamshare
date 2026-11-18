// Package api is the HTTP surface: a dumb, validated ciphertext pipe. It
// authenticates capabilities, enforces limits, moves opaque bytes and
// records telemetry. It never sees plaintext or keys.
package api

import (
	"context"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dreamfast/dreamshare/internal/adminauth"
	"github.com/dreamfast/dreamshare/internal/config"
	"github.com/dreamfast/dreamshare/internal/storage/b2"
	"github.com/dreamfast/dreamshare/internal/storage/sqlite"
)

// Server wires the config, the metadata store and object storage together.
type Server struct {
	cfg     *config.Config
	store   *sqlite.Store
	objects b2.Store
	log     *slog.Logger

	uploadSem chan struct{}

	csrf *csrfStore

	limiter *limiter

	egressMu  sync.Mutex
	egress    map[string]int64 // per ip bytes served today, in memory fast path
	egressDay int64

	mailer sender

	admin      *adminauth.Service
	adminAllow *adminauth.Allowlist
}

// NewServer builds the server. The caller owns the store and object handle.
func NewServer(cfg *config.Config, store *sqlite.Store, objects b2.Store, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	l := newLimiter()
	if !cfg.Prod {
		// dev and the e2e rig iterate fast, production ceilings are for
		// strangers on the internet
		l.boost = 50
	}
	return &Server{
		cfg:       cfg,
		store:     store,
		objects:   objects,
		log:       log,
		uploadSem: make(chan struct{}, cfg.Limits.UploadSemaphore),
		csrf:      newCSRFStore(),
		limiter:   l,
		egress:    map[string]int64{},
	}
}

// Handler builds the route table with the middleware chain.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)

	mux.HandleFunc("GET /api/bootstrap", s.limited(tierBootstrap, s.handleBootstrap))
	mux.HandleFunc("POST /api/shares", s.requireCSRF(s.limited(tierCreate, s.handleCreateShare)))
	mux.HandleFunc("POST /api/sessions/{sid}/parts/{n}", s.requireCSRF(s.limited(tierPart, s.handlePutPart)))
	mux.HandleFunc("POST /api/sessions/{sid}/complete", s.requireCSRF(s.limited(tierPart, s.handleCompleteSession)))
	mux.HandleFunc("POST /api/shares/{id}/finalize", s.requireCSRF(s.limited(tierCreate, s.handleFinalize)))

	mux.HandleFunc("GET /api/shares/{token}", s.limited(tierCheck, s.handleGetShare))
	mux.HandleFunc("GET /api/shares/{token}/check", s.limited(tierCheck, s.handleCheck))
	mux.HandleFunc("GET /api/shares/{token}/manifest", s.limited(tierCheck, s.handleManifest))
	mux.HandleFunc("GET /dl/{token}/{file}", s.limited(tierDownload, s.handleDownload))
	mux.HandleFunc("POST /api/shares/{token}/ack", s.requireCSRF(s.limited(tierCheck, s.handleAck)))
	mux.HandleFunc("POST /api/shares/{token}/notify", s.requireCSRF(s.limited(tierCheck, s.handleNotify)))

	mux.HandleFunc("DELETE /api/shares/{token}", s.limited(tierCheck, s.handleRevoke))
	mux.HandleFunc("GET /m/{token}", s.limited(tierCheck, s.handleManagerPage))
	mux.HandleFunc("POST /m/{token}", s.limited(tierCheck, s.handleManagerRevoke))

	// the built SPA with an index fallback: every non api path renders the
	// router, so /s/<token>#<key> deep links resolve client side
	s.mountAdmin(mux)

	mux.Handle("/", spaHandler())

	return s.securityHeaders(mux)
}

// ipBlocked checks the admin kill switch table. Cached for the request
// lifetime, the reconciler cleans expired rows.
func (s *Server) ipBlocked(ctx context.Context, ip string) bool {
	var count int
	_ = s.store.Reader.QueryRowContext(ctx,
		"select count(*) from admin_ip_blocks where expires_at is null or expires_at > ?",
		time.Now().Unix()).Scan(&count)
	return count > 0 && s.matchAnyBlock(ctx, ip)
}

func (s *Server) matchAnyBlock(ctx context.Context, ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	rows, err := s.store.Reader.QueryContext(ctx,
		"select ip_cidr from admin_ip_blocks where expires_at is null or expires_at > ?", time.Now().Unix())
	if err != nil {
		return false
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var cidr string
		if err := rows.Scan(&cidr); err != nil {
			continue
		}
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		if p.Contains(addr) {
			return true
		}
	}
	_ = rows.Err()
	// no row matched, a clean iteration with no error still means not blocked
	return false
}

// SetAdmin wires the staff area. A nil service leaves /admin answering 404
// for everything, the surface simply does not exist.
func (s *Server) SetAdmin(auth *adminauth.Service, allow *adminauth.Allowlist) {
	s.admin = auth
	s.adminAllow = allow
}

// spaFS is set by main from the embedded bundle.
var spaFS fs.FS

// SetSPA wires the embedded bundle, without it only the api routes serve.
func SetSPA(f fs.FS) { spaFS = f }

func spaHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if spaFS == nil {
			http.NotFound(w, r)
			return
		}
		// clean through a rooted join so no dot dot sequence survives, then
		// the embed fs only ever sees a plain relative name
		p := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if p == "" {
			p = "index.html"
		}
		if stat, err := fs.Stat(spaFS, p); err != nil || stat.IsDir() {
			// deep link or a directory, the router decides what it means and
			// no listing is ever served
			p = "index.html"
		}
		switch {
		case p == "index.html":
			// always revalidate, a stale index can reference hashed chunks
			// that no longer exist after a deploy
			w.Header().Set("Cache-Control", "no-cache")
		case strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".css"):
			// content hashed names, immutable
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		http.ServeFileFS(w, r, spaFS, p) // #nosec G703 -- path.Clean through a rooted join leaves no dot dot, and the embed fs cannot escape its root
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Reader.PingContext(ctx); err != nil {
		http.Error(w, "db not ready", http.StatusServiceUnavailable)
		return
	}
	if err := s.objects.Head(ctx); err != nil {
		http.Error(w, "storage not ready", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}

type bootstrapResponse struct {
	CSRFToken string `json:"csrf_token"`
	Limits    struct {
		MaxShareBytes    int64    `json:"max_share_bytes"`
		MaxFilesPerShare int      `json:"max_files_per_share"`
		ChunkMinBytes    int64    `json:"chunk_min_bytes"`
		ChunkMaxBytes    int64    `json:"chunk_max_bytes"`
		FrameSize        int      `json:"frame_size"`
		ExpiryModes      []string `json:"expiry_modes"`
		ExpiryDays       []int    `json:"expiry_days"`
	} `json:"limits"`
}

func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	token := s.csrf.mint()
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- HttpOnly is deliberately off: a double submit token the script reads back, the server side store is the real check
		Name:     "ds_csrf",
		Value:    token,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
		Secure:   true,
	})
	var resp bootstrapResponse
	resp.CSRFToken = token
	resp.Limits.MaxShareBytes = s.cfg.Limits.MaxShareBytes
	resp.Limits.MaxFilesPerShare = s.cfg.Limits.MaxFilesPerShare
	resp.Limits.ChunkMinBytes = s.cfg.Limits.ChunkMinBytes
	resp.Limits.ChunkMaxBytes = s.cfg.Limits.ChunkMaxBytes
	resp.Limits.FrameSize = 1 << 20
	resp.Limits.ExpiryModes = []string{"burn_on_ack", "ttl"}
	resp.Limits.ExpiryDays = []int{1, 3, 7}
	writeJSON(w, http.StatusOK, resp)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		return
	}
}

type errorResponse struct {
	Error   string `json:"error"`
	Request string `json:"request_id,omitempty"`
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, errorResponse{Error: code})
}

// clientIP resolves the peer. Behind a proxy only the trusted ranges may
// set the forwarding headers, everyone else's claim is ignored.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if !s.cfg.BehindProxy {
		return host
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return host
	}
	// net.ParseIP on a v4 address can yield the v6 mapped form, which no v4
	// prefix contains, unmap before the trusted proxy check
	addr = addr.Unmap()
	for _, prefix := range s.cfg.TrustedProxies {
		if prefix.Contains(addr) {
			// the proxy set headers win, but only the one the proxy itself
			// controls. CF-Connecting-IP is overwritten by cloudflare and
			// cannot be client chosen. the leftmost XFF entry is client
			// supplied when the proxy appends, so the rightmost element is
			// the proxy's own observation.
			if cip := r.Header.Get("CF-Connecting-IP"); net.ParseIP(cip) != nil {
				return cip
			}
			if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
				last := forwardedLast(fwd)
				if net.ParseIP(last) != nil {
					return last
				}
			}
		}
	}
	return host
}

func forwardedLast(v string) string {
	for i := len(v) - 1; i >= 0; i-- {
		if v[i] == ',' {
			return strings.TrimSpace(v[i+1:])
		}
	}
	return strings.TrimSpace(v)
}

func pathInt(r *http.Request, name string) (int, bool) {
	v := r.PathValue(name)
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return 0, false
	}
	return n, true
}
