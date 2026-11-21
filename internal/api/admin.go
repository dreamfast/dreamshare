package api

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/dreamfast/dreamshare/internal/storage/sqlite"
	"github.com/dreamfast/dreamshare/internal/token"
)

// AdminCookie is the staff session cookie name. The __Host- prefix pins it
// to the whole origin over https.
const AdminCookie = "__Host-ds_admin"

// mountAdmin wires the staff area. Its allowlist runs before every handler,
// before login, so an unlisted address never reaches a password check.
func (s *Server) mountAdmin(mux *http.ServeMux) {
	guard := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// byte identical responses for 401, 403 and 404 in here, so the
			// admin surface does not confirm its own existence
			deny := func() {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte("404 page not found\n"))
			}
			if s.admin == nil {
				deny()
				return
			}
			// the allowlist reads the real client ip, behind cloudflare the
			// socket address is cloudflare's own, so remoteaddr would make
			// the control a lockout or a no-op
			ip := net.ParseIP(s.clientIP(r))
			if ip == nil || !s.adminAllow.Contains(ip) {
				deny()
				return
			}
			// sessions for everything except the login itself
			if r.URL.Path == "/admin/login" {
				next(w, r)
				return
			}
			c, err := r.Cookie(AdminCookie)
			if err != nil || !s.admin.SessionOK(r.Context(), c.Value) {
				deny()
				return
			}
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				// admin mutations carry the csrf pair like every other
				// mutation in the system
				cookie2, cerr := r.Cookie("ds_csrf")
				header := r.Header.Get("X-CSRF-Token")
				if cerr != nil || cookie2.Value == "" || cookie2.Value != header || !s.csrf.valid(header) {
					deny()
					return
				}
			}
			next(w, r)
		}
	}

	mux.HandleFunc("POST /admin/login", guard(s.limited(tierCreate, s.handleAdminLogin)))
	mux.HandleFunc("POST /admin/logout", guard(s.handleAdminLogout))
	mux.HandleFunc("GET /admin/api/overview", guard(s.handleAdminOverview))
	mux.HandleFunc("GET /admin/api/activity", guard(s.handleAdminActivity))
	mux.HandleFunc("GET /admin/api/shares", guard(s.handleAdminShares))
	mux.HandleFunc("POST /admin/api/shares/{id}/revoke", guard(s.handleAdminRevoke))
	mux.HandleFunc("POST /admin/api/shares/{id}/expire", guard(s.handleAdminExpire))
	mux.HandleFunc("GET /admin/api/shares/{id}", guard(s.handleAdminShareDetail))
	mux.HandleFunc("POST /admin/api/blocks", guard(s.handleAdminBlock))
	mux.HandleFunc("DELETE /admin/api/blocks/{cidr}", guard(s.handleAdminUnblock))
	mux.HandleFunc("GET /admin/api/health/deep", guard(s.handleAdminDeepHealth))
	mux.HandleFunc("POST /admin/api/totp/begin", guard(s.handleAdminTOTPBegin))
	mux.HandleFunc("POST /admin/api/totp/confirm", guard(s.handleAdminTOTPConfirm))
	mux.HandleFunc("DELETE /admin/api/totp", guard(s.handleAdminTOTPDisable))
}

func (s *Server) handleAdminTOTPBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := decodeJSON(w, r, 4096, &req); err != nil {
		return
	}
	secret, otpauth, err := s.admin.BeginTOTP(r.Context(), req.Email)
	if err != nil {
		writeError(w, http.StatusForbidden, "denied")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"secret": secret, "otpauth": otpauth})
}

func (s *Server) handleAdminTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Secret   string `json:"secret"`
		Code     string `json:"code"`
	}
	if err := decodeJSON(w, r, 4096, &req); err != nil {
		return
	}
	if err := s.admin.ConfirmTOTP(r.Context(), req.Email, req.Password, req.Secret, req.Code); err != nil {
		writeError(w, http.StatusForbidden, "denied")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAdminTOTPDisable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, 4096, &req); err != nil {
		return
	}
	if err := s.admin.DisableTOTP(r.Context(), req.Email, req.Password); err != nil {
		writeError(w, http.StatusForbidden, "denied")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		TOTP     string `json:"totp"`
	}
	if err := decodeJSON(w, r, 4096, &req); err != nil {
		return
	}
	// the admin login carries the same fail closed bot gate as public
	// share creation, and the same per ip rate ceiling. no strike here,
	// the admin allowlist already bounds who can reach this route at all
	if accepted, _ := s.turnstileOk(r, s.clientIP(r)); !accepted {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 page not found\n"))
		return
	}
	tok, err := s.admin.Login(r.Context(), s.clientIP(r), req.Email, req.Password, req.TOTP)
	if err != nil {
		// the same body as every other denial, no account existence signal
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 page not found\n"))
		return
	}
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- the cookie carries Secure, HttpOnly and SameSite Strict, gosec does not see all three together
		Name:     AdminCookie,
		Value:    tok,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
		Secure:   true,
		HttpOnly: true,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(AdminCookie); err == nil {
		s.admin.Logout(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: AdminCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}) //nolint:gosec // clearing the cookie, the attributes match the real one
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAdminOverview(w http.ResponseWriter, r *http.Request) {
	type overview struct {
		Active      int64 `json:"active_shares"`
		InFlight    int64 `json:"in_flight_shares"`
		Terminal    int64 `json:"terminal_shares"`
		BytesStored int64 `json:"bytes_stored"`
		BytesToday  int64 `json:"bytes_today"`
		Events24h   int64 `json:"events_24h"`
		CheckFails  int64 `json:"check_fails_24h"`
		DBBytes     int64 `json:"db_bytes"`
	}
	var o overview
	day := time.Now().Truncate(24 * time.Hour)
	day24 := time.Now().Add(-24 * time.Hour).Unix()
	q := func(dst *int64, query string, args ...any) { //nolint:contextcheck // the closure captures the request context through the outer function
		_ = s.store.Reader.QueryRowContext(r.Context(), query, args...).Scan(dst)
	}
	q(&o.Active, "select count(*) from shares where status = 'active'")
	q(&o.InFlight, "select count(*) from shares where status = 'pending'")
	q(&o.Terminal, "select count(*) from shares where status in ('delivered','wiped','expired','revoked')")
	q(&o.BytesStored, "select coalesce(sum(byte_size),0) from share_files")
	q(&o.BytesToday, "select coalesce(sum(bytes),0) from share_events where event in ('finalised','downloaded') and ts >= ?", day.Unix())
	q(&o.Events24h, "select count(*) from share_events where ts >= ?", day24)
	q(&o.CheckFails, "select count(*) from share_events where event = 'check_fail' and ts >= ?", day24)
	var page int64
	_ = s.store.Reader.QueryRowContext(r.Context(), "pragma page_count").Scan(&page)
	var size int64
	_ = s.store.Reader.QueryRowContext(r.Context(), "pragma page_size").Scan(&size)
	o.DBBytes = page * size
	writeJSON(w, http.StatusOK, o)
}

func (s *Server) handleAdminActivity(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 || limit > 500 {
		limit = 100
	}
	rows, err := s.store.Reader.QueryContext(r.Context(),
		`select ts, event, ip, country, ua, bytes, share_id
		from share_events order by ts desc limit ?`, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	defer func() { _ = rows.Close() }()
	type event struct {
		TS      int64  `json:"ts"`
		Event   string `json:"event"`
		IP      string `json:"ip"`
		Country string `json:"country"`
		UA      string `json:"ua"`
		Bytes   *int64 `json:"bytes"`
		ShareID string `json:"share_id"`
	}
	var out []event
	for rows.Next() {
		var e event
		var bytes sql.NullInt64
		if err := rows.Scan(&e.TS, &e.Event, &e.IP, &e.Country, &e.UA, &bytes, &e.ShareID); err != nil {
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		if bytes.Valid {
			e.Bytes = &bytes.Int64
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": out})
}

func (s *Server) handleAdminShares(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 || limit > 500 {
		limit = 100
	}
	rows, err := s.store.Reader.QueryContext(r.Context(),
		`select id, status, expiry_mode, expires_at, created_at, created_ip,
		created_country, created_ua, file_count, total_bytes, downloads_used
		from shares order by created_at desc limit ?`, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	defer func() { _ = rows.Close() }()
	type share struct {
		ID         string `json:"id"`
		Status     string `json:"status"`
		ExpiryMode string `json:"expiry_mode"`
		ExpiresAt  int64  `json:"expires_at"`
		CreatedAt  int64  `json:"created_at"`
		IP         string `json:"ip"`
		Country    string `json:"country"`
		UA         string `json:"ua"`
		FileCount  int    `json:"file_count"`
		TotalBytes int64  `json:"total_bytes"`
		Downloads  int    `json:"downloads_used"`
	}
	var out []share
	for rows.Next() {
		var sh share
		if err := rows.Scan(&sh.ID, &sh.Status, &sh.ExpiryMode, &sh.ExpiresAt, &sh.CreatedAt,
			&sh.IP, &sh.Country, &sh.UA, &sh.FileCount, &sh.TotalBytes, &sh.Downloads); err != nil {
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		out = append(out, sh)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"shares": out})
}

func (s *Server) handleAdminShareDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !token.ValidID(id, 22) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	sh, err := s.store.GetShare(r.Context(), id)
	if errors.Is(err, sqlite.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	rows, err := s.store.Reader.QueryContext(r.Context(),
		`select ts, event, ip, ua, bytes from share_events where share_id = ? order by ts`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	defer func() { _ = rows.Close() }()
	var events []map[string]any
	for rows.Next() {
		var ts int64
		var event, ip, ua string
		var bytes sql.NullInt64
		if err := rows.Scan(&ts, &event, &ip, &ua, &bytes); err != nil {
			break
		}
		events = append(events, map[string]any{"ts": ts, "event": event, "ip": ip, "ua": ua, "bytes": bytes.Int64})
	}
	_ = rows.Err()
	writeJSON(w, http.StatusOK, map[string]any{
		"share": map[string]any{
			"id": sh.ID, "status": sh.Status, "expiry_mode": sh.ExpiryMode,
			"expires_at": sh.ExpiresAt.Unix(), "file_count": sh.FileCount,
			"total_bytes": sh.TotalBytes, "downloads_used": sh.DownloadsUsed,
		},
		"events": events,
	})
}

func (s *Server) handleAdminRevoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !token.ValidID(id, 22) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	_, err := s.store.Writer.ExecContext(r.Context(),
		"update shares set status = 'revoked', terminal_at = ? where id = ? and status in ('pending','active','delivered')",
		time.Now().Unix(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	s.wipeAsync(r.Context(), id)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAdminExpire(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !token.ValidID(id, 22) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	_, err := s.store.Writer.ExecContext(r.Context(),
		"update shares set expires_at = ? where id = ? and status in ('pending','active')",
		time.Now().Unix(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAdminBlock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CIDR   string `json:"cidr"`
		Reason string `json:"reason"`
	}
	if err := decodeJSON(w, r, 4096, &req); err != nil {
		return
	}
	if !validCIDR(req.CIDR) {
		writeError(w, http.StatusBadRequest, "bad_cidr")
		return
	}
	// an admin block is permanent by definition, re blocking an address
	// that holds a stale auto row must reinstate that, not inherit its
	// expiry
	_, err := s.store.Writer.ExecContext(r.Context(),
		`insert into admin_ip_blocks(ip_cidr, reason, created_by, created_at) values(?,?,?,?)
		on conflict(ip_cidr) do update set reason = excluded.reason, expires_at = null`,
		req.CIDR, req.Reason, "admin", time.Now().Unix())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAdminUnblock(w http.ResponseWriter, r *http.Request) {
	cidr := r.PathValue("cidr")
	if !validCIDR(cidr) {
		writeError(w, http.StatusBadRequest, "bad_cidr")
		return
	}
	_, err := s.store.Writer.ExecContext(r.Context(),
		"delete from admin_ip_blocks where ip_cidr = ?", cidr)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAdminDeepHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	out := map[string]string{}
	if err := s.store.Reader.PingContext(ctx); err != nil {
		out["db"] = "fail: " + err.Error()
	} else {
		out["db"] = "ok"
	}
	if err := s.objects.Head(ctx); err != nil {
		out["b2"] = "fail: " + err.Error()
	} else {
		out["b2"] = "ok"
	}
	// the last reconciler pass age, from the events table's newest wipe
	var last int64
	_ = s.store.Reader.QueryRowContext(ctx,
		"select coalesce(max(ts),0) from share_events where event = 'wiped'").Scan(&last)
	if last == 0 {
		out["reconciler"] = "no run recorded yet"
	} else {
		out["reconciler"] = "last pass " + time.Since(time.Unix(last, 0)).Round(time.Second).String() + " ago"
	}
	writeJSON(w, http.StatusOK, out)
}

func validCIDR(v string) bool {
	if len(v) > 64 || strings.ContainsAny(v, " \t\r\n") {
		return false
	}
	_, err := netip.ParsePrefix(v)
	return err == nil
}
