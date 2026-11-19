package api

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dreamfast/dreamshare/internal/storage/sqlite"
	"github.com/dreamfast/dreamshare/internal/token"
)

// handleGetShare answers share status for the recipient page. Manifest
// fields come from the browser's own decryption, never from here.
func (s *Server) handleGetShare(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("token")
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
	writeJSON(w, http.StatusOK, map[string]any{
		"share_id":       sh.ID,
		"format_version": sh.FormatVersion,
		"status":         sh.Status,
		"expiry_mode":    sh.ExpiryMode,
		"expires_at":     sh.ExpiresAt.Unix(),
		"file_count":     sh.FileCount,
		"total_bytes":    sh.TotalBytes,
	})
}

// handleCheck serves the key validation blob. It never moves the download
// counter, a burn share cannot consume itself by being opened.
func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("token")
	if !token.ValidID(id, 22) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	var check []byte
	err := s.store.Reader.QueryRowContext(r.Context(),
		"select check_ct from shares where id = ?", id).Scan(&check)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if check == nil {
		// pending or text only without a check blob
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(check)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(check)
}

// handleManifest serves the sealed manifest blob. Only a browser holding
// the fragment key can read it, to the server it is opaque bytes.
func (s *Server) handleManifest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("token")
	if !token.ValidID(id, 22) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	var manifest []byte
	err := s.store.Reader.QueryRowContext(r.Context(),
		"select manifest_ct from shares where id = ? and status = 'active'", id).Scan(&manifest)
	if errors.Is(err, sql.ErrNoRows) || manifest == nil {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(manifest)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(manifest)
}

// handleDownload streams ciphertext. Fixed headers mean attacker bytes can
// never execute from this origin, the browser applies the real type after
// decrypting the manifest.
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("token")
	fileID := r.PathValue("file")
	if !token.ValidID(id, 22) || !token.ValidID(fileID, 22) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}

	// range parsing first, only the simple single range form
	var offset, rngEnd int64
	isRange := false
	if rng := r.Header.Get("Range"); rng != "" {
		offset, rngEnd, isRange = parseByteRange(rng)
		if !isRange {
			writeError(w, http.StatusRequestedRangeNotSatisfiable, "range")
			return
		}
	}

	// only a fetch that starts at byte zero counts as a download, a resume
	// or a seek rides the rate limits and the egress meter instead
	var (
		f   *sqlite.File
		err error
	)
	if isRange && offset > 0 {
		f, err = s.store.PeekFile(r.Context(), id, fileID)
	} else {
		f, err = s.store.BeginDownload(r.Context(), id, fileID)
	}
	switch {
	case errors.Is(err, sqlite.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found")
		return
	case errors.Is(err, sqlite.ErrShareNotReady):
		writeError(w, http.StatusNotFound, "not_found")
		return
	case errors.Is(err, sqlite.ErrRefused):
		writeError(w, http.StatusGone, "gone")
		return
	case err != nil:
		s.log.Error("begin download", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	ip := s.clientIP(r)

	length := f.ByteSize - offset
	if isRange && rngEnd >= 0 && rngEnd < f.ByteSize {
		length = rngEnd - offset + 1
	}
	if length <= 0 {
		// a start at or past end of object cannot be served
		writeError(w, http.StatusRequestedRangeNotSatisfiable, "range")
		return
	}

	body, err := s.objects.Get(r.Context(), f.ObjectKey, offset, length)
	if err != nil {
		s.log.Error("object get", "err", err)
		writeError(w, http.StatusBadGateway, "storage")
		return
	}
	defer func() { _ = body.Close() }()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="blob"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Accept-Ranges", "bytes")
	if isRange {
		// the header describes the bytes actually served, never the tail
		// beyond the requested end
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", offset, offset+length-1, f.ByteSize))
		w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
		w.WriteHeader(http.StatusPartialContent)
	} else {
		w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
		w.WriteHeader(http.StatusOK)
	}

	s.seedEgress(r.Context(), ip)
	lim := &egressLimiter{w: w, s: s, ip: ip}
	written, err := copyWithLimit(lim, body)
	if err != nil {
		// the copy aborted mid stream, the quota ceiling is hard
		s.log.Warn("download aborted", "err", err, "written", written)
		return
	}
	if err := s.store.InsertEvent(r.Context(), id, "downloaded", ip, "", r.UserAgent(), written); err != nil {
		s.log.Error("event", "err", err)
	}
}

// egressLimiter aborts the stream when the per ip daily byte ceiling is hit
// mid stream. The ceiling is hard, not advisory.
type egressLimiter struct {
	w  http.ResponseWriter
	s  *Server
	ip string
}

func (e *egressLimiter) Write(p []byte) (int, error) {
	// the budget is checked under the lock per write, so two concurrent
	// streams from one ip cannot each spend the whole daily budget
	e.s.egressMu.Lock()
	if e.s.egress[e.ip]+int64(len(p)) > e.s.cfg.Limits.DailyIPBytes {
		e.s.egressMu.Unlock()
		return 0, errQuotaExceeded
	}
	e.s.egress[e.ip] += int64(len(p))
	e.s.egressMu.Unlock()
	return e.w.Write(p)
}

// seedEgress folds the persisted daily total into the fast path once per
// request, so uploads and earlier streams count against the same ceiling.
func (s *Server) seedEgress(ctx context.Context, ip string) {
	persisted, err := s.store.BytesTodayByIP(ctx, ip, time.Now().Truncate(24*time.Hour))
	if err != nil {
		return
	}
	s.egressMu.Lock()
	defer s.egressMu.Unlock()
	day := time.Now().Truncate(24 * time.Hour)
	if s.egressDay != day.Unix() {
		s.egress = map[string]int64{}
		s.egressDay = day.Unix()
	}
	if s.egress[ip] < persisted {
		s.egress[ip] = persisted
	}
}

// copyWithLimit streams through the limiter, the quota abort propagates.
func copyWithLimit(dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 64<<10)
	var total int64
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			wn, werr := dst.Write(buf[:n])
			total += int64(wn)
			if werr != nil {
				return total, werr
			}
		}
		if rerr == io.EOF {
			return total, nil
		}
		if rerr != nil {
			return total, rerr
		}
	}
}

var errQuotaExceeded = errors.New("daily egress quota exceeded")

// parseByteRange accepts only bytes=N- and bytes=N-M.
func parseByteRange(v string) (start, end int64, ok bool) {
	if !strings.HasPrefix(v, "bytes=") {
		return 0, 0, false
	}
	spec := strings.TrimPrefix(v, "bytes=")
	dash := strings.IndexByte(spec, '-')
	if dash < 0 {
		return 0, 0, false
	}
	startStr, endStr := spec[:dash], spec[dash+1:]
	start, err := strconv.ParseInt(startStr, 10, 64)
	if err != nil || start < 0 {
		return 0, 0, false
	}
	if endStr == "" {
		return start, -1, true
	}
	end, err = strconv.ParseInt(endStr, 10, 64)
	if err != nil || end < start {
		return 0, 0, false
	}
	return start, end, true
}

// validEmail is a shape check, not a deliverability claim. The mailer
// reports real failures when the send runs.
func validEmail(addr string) bool {
	at := strings.IndexByte(addr, '@')
	if at <= 0 || at == len(addr)-1 {
		return false
	}
	dot := strings.LastIndexByte(addr[at:], '.')
	return dot > 1 && dot < len(addr[at:])-1
}

// handleAck records a verified decrypt. The proof field carries the hash
// of the check verifier, which only a holder of the share key can
// produce, so a bare share id can no longer wipe a burn share. Shares
// finalised before the field existed keep the old assertion path.
func (s *Server) handleAck(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("token")
	if !token.ValidID(id, 22) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	var req struct {
		FileID   *string `json:"file_id"`
		Verified bool    `json:"verified"`
		Proof    string  `json:"proof"`
	}
	if err := decodeJSON(w, r, 4096, &req); err != nil {
		return
	}
	if !req.Verified {
		writeError(w, http.StatusBadRequest, "not_verified")
		return
	}
	wantSHA, err := s.store.CheckSHA(r.Context(), id)
	if errors.Is(err, sqlite.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		s.log.Error("check sha read", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if wantSHA != "" {
		got := strings.ToLower(strings.TrimSpace(req.Proof))
		if got == "" || len(got) != 64 {
			writeError(w, http.StatusForbidden, "check_proof")
			return
		}
		gotBytes, derr := hex.DecodeString(got)
		wantBytes, _ := hex.DecodeString(wantSHA)
		if derr != nil || subtle.ConstantTimeCompare(gotBytes, wantBytes) != 1 {
			writeError(w, http.StatusForbidden, "check_proof")
			return
		}
	}
	fileID := ""
	if req.FileID != nil {
		fileID = *req.FileID
		if fileID != "" && !token.ValidID(fileID, 22) {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
	}
	flipped, err := s.store.AckFile(r.Context(), id, fileID)
	if errors.Is(err, sqlite.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		s.log.Error("ack", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	// the sender address is server stored since create, the mail goes to
	// it once and the address is gone. no client supplied address exists
	// anywhere in the flow
	if email, nerr := s.store.ShareNotifyEmail(r.Context(), id); nerr == nil && email != "" {
		if qerr := s.store.NotifyEnqueue(r.Context(), id, email, time.Hour); qerr != nil &&
			!errors.Is(qerr, sqlite.ErrNotifyThrottled) {
			s.log.Error("notify enqueue", "err", qerr)
		} else if qerr == nil {
			if cerr := s.store.ClearNotifyEmail(r.Context(), id); cerr != nil {
				s.log.Error("notify address clear", "err", cerr)
			}
		}
	}
	if flipped {
		ip := s.clientIP(r)
		if err := s.store.InsertEvent(r.Context(), id, "ack", ip, "", r.UserAgent(), 0); err != nil {
			s.log.Error("event", "err", err)
		}
		s.wipeAsync(r.Context(), id)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleRevoke revokes by manager token header.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	mgr := r.Header.Get("X-Manager-Token")
	if mgr == "" {
		writeError(w, http.StatusUnauthorized, "manager_token")
		return
	}
	id, err := s.store.RevokeByManagerToken(r.Context(), token.HashToken(mgr))
	if errors.Is(err, sqlite.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	s.wipeAsync(r.Context(), id)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleManagerPage is the any device revoke link. GET never revokes, a
// scanner or prefetch must not be able to kill a share.
func (s *Server) handleManagerPage(w http.ResponseWriter, r *http.Request) {
	mgr := r.PathValue("token")
	if mgr == "" || !token.ValidID(mgr, 32) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	id, err := s.store.ShareIDByManagerHash(r.Context(), token.HashToken(mgr))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	sh, err := s.store.GetShare(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, `<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">`+
		`<title>Revoke share</title></head><body style="font-family:system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem">`+
		`<h1>Revoke share</h1><p>Share <code>%s</code> is <strong>%s</strong>.</p>`+
		`<form method="post"><button type="submit">Revoke now</button></form>`+
		`<p style="colour:#666">Revoking deletes every stored copy immediately. There is no undo.</p></body></html>`,
		id, sh.Status)
}

func (s *Server) handleManagerRevoke(w http.ResponseWriter, r *http.Request) {
	mgr := r.PathValue("token")
	if mgr == "" || !token.ValidID(mgr, 32) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	id, err := s.store.RevokeByManagerToken(r.Context(), token.HashToken(mgr))
	if errors.Is(err, sqlite.ErrNotFound) {
		// idempotent, the share is already gone
		writeError(w, http.StatusOK, "already_gone")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	s.wipeAsync(r.Context(), id)
	writeError(w, http.StatusOK, "revoked")
}
