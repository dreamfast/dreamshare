package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dreamfast/dreamshare/internal/storage/b2"
	"github.com/dreamfast/dreamshare/internal/storage/sqlite"
	"github.com/dreamfast/dreamshare/internal/token"
)

type createRequest struct {
	Files []struct {
		Size          int64 `json:"size"`
		FrameCount    int   `json:"frame_count"`
		FrameSize     int   `json:"frame_size"`
		PartSize      int   `json:"part_size"`
		ExpectedParts int   `json:"expected_parts"`
	} `json:"files"`
	ExpiryMode     string `json:"expiry_mode"`
	ExpiryDays     int    `json:"expiry_days"`
	NotifyWanted   bool   `json:"notify_wanted"`
	TurnstileToken string `json:"turnstile_token"`
}

type createResponse struct {
	ShareID        string              `json:"share_id"`
	ManagerToken   string              `json:"manager_token"`
	UploadSessions []uploadSessionView `json:"upload_sessions"`
}

type uploadSessionView struct {
	SessionID     string   `json:"session_id"`
	FileID        string   `json:"file_id"`
	ExpectedParts int      `json:"expected_parts"`
	PartSize      int64    `json:"part_size"`
	Multipart     bool     `json:"multipart"`
	FirstTokens   []string `json:"first_tokens"`
}

// handleCreateShare opens a share. The body is plaintext free: sizes only,
// names travel inside the encrypted manifest. The server mints every
// capability id before the browser seals anything.
func (s *Server) handleCreateShare(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)

	if !s.turnstileOk(r, ip) {
		writeError(w, http.StatusForbidden, "turnstile")
		return
	}

	var req createRequest
	if err := decodeJSON(w, r, 1<<16, &req); err != nil {
		return
	}
	for _, f := range req.Files {
		// the client owns the part plan, ciphertext overhead means the
		// server cannot derive it from sizes without guessing wrong at
		// chunk boundaries
		if f.ExpectedParts < 1 || f.ExpectedParts > 10000 {
			writeError(w, http.StatusBadRequest, "bad_file")
			return
		}
	}

	if req.ExpiryMode != "burn_on_ack" && req.ExpiryMode != "ttl" {
		writeError(w, http.StatusBadRequest, "expiry_mode")
		return
	}
	if len(req.Files) > s.cfg.Limits.MaxFilesPerShare {
		writeError(w, http.StatusBadRequest, "too_many_files")
		return
	}
	var total int64
	for _, f := range req.Files {
		if f.Size < 1 || f.FrameCount < 1 || f.FrameSize < 1 || f.PartSize < 1 {
			writeError(w, http.StatusBadRequest, "bad_file")
			return
		}
		total += f.Size
	}
	if total == 0 && len(req.Files) == 0 {
		// text only share, no sessions
	} else if total > s.cfg.Limits.MaxShareBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large")
		return
	}

	// the daily quota covers upload bytes, checked before any work
	dayStart := time.Now().Truncate(24 * time.Hour)
	used, err := s.store.BytesTodayByIP(r.Context(), ip, dayStart)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if used+total > s.cfg.Limits.DailyIPBytes {
		writeError(w, http.StatusTooManyRequests, "quota")
		return
	}

	shareID, err := token.NewMint(22)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	managerToken, err := token.NewMint(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	chunkSecret := make([]byte, 32)
	if _, err := rand.Read(chunkSecret); err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}

	var expiresAt time.Time
	if req.ExpiryMode == "ttl" {
		switch req.ExpiryDays {
		case 1, 3, 7:
			expiresAt = time.Now().AddDate(0, 0, req.ExpiryDays)
		default:
			writeError(w, http.StatusBadRequest, "expiry_days")
			return
		}
	} else {
		// the burn ceiling, an unclaimed link still dies
		expiresAt = time.Now().AddDate(0, 0, 7)
	}

	ns := sqlite.NewShare{
		ID: shareID, FormatVersion: "ds1",
		FileCount: len(req.Files), TotalBytes: total,
		ExpiryMode: req.ExpiryMode, ExpiresAt: expiresAt,
		MaxAttempts:      5,
		ManagerTokenHash: token.HashToken(managerToken),
		TurnstileOK:      s.turnstileEnforced(),
		CreatedIP:        ip,
		CreatedUA:        r.UserAgent(),
		ChunkSecret:      chunkSecret,
		SessionTTL:       24 * time.Hour,
	}
	ym := time.Now().Format("0601")
	var sessions []uploadSessionView
	for i, f := range req.Files {
		fileID, err := token.NewMint(22)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		sessionID, err := token.NewMint(22)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		// the client owns the part plan, ciphertext overhead means server
		// arithmetic on sizes guesses wrong at chunk boundaries
		expectedParts := f.ExpectedParts
		ns.Files = append(ns.Files, sqlite.NewFile{
			ID: fileID, Position: i, ObjectKey: token.ObjectKey(ym, fileID),
			ByteSize: f.Size, FrameCount: f.FrameCount, FrameSize: f.FrameSize,
			PartSize: int64(f.PartSize), SessionID: sessionID, ExpectedParts: expectedParts,
		})
		view := uploadSessionView{
			SessionID: sessionID, FileID: fileID,
			ExpectedParts: expectedParts, PartSize: int64(f.PartSize),
			Multipart: expectedParts > 1,
		}
		for p := 1; p <= expectedParts && p <= 3; p++ {
			view.FirstTokens = append(view.FirstTokens, token.PartToken(chunkSecret, sessionID, p))
		}
		sessions = append(sessions, view)
	}

	if err := s.store.CreateShare(r.Context(), ns); err != nil {
		s.log.Error("create share", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if err := s.store.InsertEvent(r.Context(), shareID, "created", ip, "", r.UserAgent(), total); err != nil {
		s.log.Error("event", "err", err)
	}

	resp := createResponse{ShareID: shareID, ManagerToken: managerToken, UploadSessions: sessions}
	writeJSON(w, http.StatusCreated, resp)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, max int64, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, max)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json")
		return err
	}
	return nil
}

// handlePutPart streams one ciphertext chunk to storage while hashing it.
// The client's sha256 must match or the part never lands.
func (s *Server) handlePutPart(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	sid := r.PathValue("sid")
	if !token.ValidID(sid, 22) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	partNumber, ok := pathInt(r, "n")
	if !ok || partNumber > 10000 {
		writeError(w, http.StatusBadRequest, "part")
		return
	}
	sess, err := s.store.LoadSession(r.Context(), sid)
	if errors.Is(err, sqlite.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if errors.Is(err, sqlite.ErrWrongState) {
		writeError(w, http.StatusConflict, "session_closed")
		return
	}
	if errors.Is(err, sqlite.ErrRefused) {
		writeError(w, http.StatusGone, "gone")
		return
	}
	if err != nil {
		s.log.Error("load session", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	part := r.Header.Get("X-Part-Token")
	if !token.VerifyPartToken(sess.ChunkSecret, sid, partNumber, part) {
		writeError(w, http.StatusForbidden, "part_token")
		return
	}
	if r.ContentLength <= 0 {
		// b2 refuses chunked transfer on uploads, the length is declared
		writeError(w, http.StatusBadRequest, "length_required")
		return
	}

	// acquire the in-flight slot, it bounds memory no matter the file size
	select {
	case s.uploadSem <- struct{}{}:
		defer func() { <-s.uploadSem }()
	case <-r.Context().Done():
		writeError(w, http.StatusServiceUnavailable, "busy")
		return
	}

	wantHash := r.Header.Get("X-Part-SHA256")
	if wantHash == "" {
		writeError(w, http.StatusBadRequest, "part_hash")
		return
	}
	if partNumber > sess.ExpectedParts {
		// a declared two part upload never mints a ten thousand part one
		writeError(w, http.StatusBadRequest, "part_out_of_plan")
		return
	}
	maxPart := s.cfg.Limits.ChunkMaxBytes + (s.cfg.Limits.ChunkMaxBytes/int64(1<<20))*29 + 1024
	if r.ContentLength > maxPart {
		writeError(w, http.StatusRequestEntityTooLarge, "part_too_large")
		return
	}
	// the session budget is the declared file size, a client that declared
	// small and ships big is refused here, not after storing
	if sess.FileByteSize > 0 && sess.BytesReceived+r.ContentLength > sess.FileByteSize+1024 {
		writeError(w, http.StatusRequestEntityTooLarge, "over_declared_size")
		return
	}
	// the daily quota counts actual stored bytes, keyed on the resolved
	// client ip exactly like the event rows
	dayStart := time.Now().Truncate(24 * time.Hour)
	used, err := s.store.BytesTodayByIP(r.Context(), ip, dayStart)
	if err != nil {
		// fail closed, an unreadable meter means no upload
		s.log.Error("quota meter", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if used+r.ContentLength > s.cfg.Limits.DailyIPBytes {
		writeError(w, http.StatusTooManyRequests, "quota")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, r.ContentLength)

	hasher := sha256.New()
	teedReader := io.TeeReader(r.Body, hasher)
	size := r.ContentLength

	var completed b2.Completed
	if !sess.Multipart {
		completed, err = s.objects.PutObject(r.Context(), sess.ObjectKey, size, teedReader)
	} else {
		if sess.UploadID == "" {
			uploadID, cerr := s.objects.CreateUpload(r.Context(), sess.ObjectKey)
			if cerr != nil {
				s.log.Error("create upload", "err", cerr)
				writeError(w, http.StatusBadGateway, "storage")
				return
			}
			if uerr := s.store.SetUploadID(r.Context(), sid, uploadID); uerr != nil {
				s.log.Error("save upload id", "err", uerr)
			}
			sess.UploadID = uploadID
		}
		var info b2.PartInfo
		info, err = s.objects.PutPart(r.Context(), sess.ObjectKey, sess.UploadID, partNumber, size, teedReader)
		if err == nil {
			completed = b2.Completed{ETag: info.ETag}
		}
	}
	if err != nil {
		s.log.Error("put part", "err", err)
		writeError(w, http.StatusBadGateway, "storage")
		return
	}
	gotHash := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(gotHash, wantHash) {
		// integrity failed, the just stored object or part is junk. delete
		// the version now, an orphan under a live key bills forever and no
		// by id delete can ever reach it once the id is overwritten
		if !sess.Multipart && completed.VersionID != "" {
			if derr := s.objects.DeleteVersion(r.Context(), sess.ObjectKey, completed.VersionID); derr != nil {
				s.log.Error("orphan cleanup after hash mismatch", "err", derr)
			}
		}
		writeError(w, http.StatusUnprocessableEntity, "hash_mismatch")
		return
	}
	if !sess.Multipart && completed.VersionID != "" {
		// a retry puts a second version under the same key. delete the
		// superseded one before its id is overwritten, otherwise it bills
		// forever and no by id delete can reach it
		if prev, perr := s.store.CurrentFileVersion(r.Context(), sess.FileID); perr == nil && prev != "" && prev != completed.VersionID {
			if derr := s.objects.DeleteVersion(r.Context(), sess.ObjectKey, prev); derr != nil && !errors.Is(derr, b2.ErrNotFound) {
				s.log.Error("superseded version cleanup", "err", derr)
			}
		}
		if err := s.store.SetFileVersionBySession(r.Context(), sid, completed.ETag, completed.VersionID); err != nil {
			s.log.Error("save file identity", "err", err)
		}
	}

	if err := s.store.RecordPart(r.Context(), sid, partNumber, completed.ETag, size, hasher.Sum(nil)); err != nil {
		s.log.Error("record part", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}

	// look ahead tokens, flow control with no session state
	var next []string
	for p := partNumber + 1; p <= partNumber+3 && p <= sess.ExpectedParts; p++ {
		next = append(next, token.PartToken(sess.ChunkSecret, sid, p))
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "next_tokens": next})
}

func (s *Server) handleCompleteSession(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	if !token.ValidID(sid, 22) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	sess, err := s.store.LoadSession(r.Context(), sid)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	part := r.Header.Get("X-Part-Token")
	if !token.VerifyPartToken(sess.ChunkSecret, sid, 1, part) && !token.VerifyPartToken(sess.ChunkSecret, sid, sess.ExpectedParts, part) {
		writeError(w, http.StatusForbidden, "part_token")
		return
	}

	if !sess.Multipart {
		if err := s.store.CompleteSession(r.Context(), sid, "etag", ""); err != nil {
			s.log.Error("complete session", "err", err)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}

	parts, err := s.store.PartsFor(r.Context(), sid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if len(parts) != sess.ExpectedParts {
		writeError(w, http.StatusBadRequest, "parts_missing")
		return
	}
	var infos []b2.PartInfo
	for _, p := range parts {
		infos = append(infos, b2.PartInfo{Number: p.Number, ETag: p.ETag, Size: p.Size})
	}
	completed, err := s.objects.CompleteUpload(r.Context(), sess.ObjectKey, sess.UploadID, infos)
	if err != nil {
		s.log.Error("complete upload", "err", err)
		writeError(w, http.StatusBadGateway, "storage")
		return
	}
	if err := s.store.CompleteSession(r.Context(), sid, completed.ETag, completed.VersionID); err != nil {
		s.log.Error("complete session", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleFinalize(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !token.ValidID(id, 22) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	blobsMax := s.cfg.Limits.TitleCTMaxBytes + s.cfg.Limits.ManifestCTMaxBytes + s.cfg.Limits.CheckCTBytes + 4096
	var req struct {
		TitleCT    string `json:"title_ct"`
		ManifestCT string `json:"manifest_ct"`
		CheckCT    string `json:"check_ct"`
	}
	if err := decodeJSON(w, r, blobsMax, &req); err != nil {
		return
	}
	title, err1 := b64(req.TitleCT, s.cfg.Limits.TitleCTMaxBytes)
	manifest, err2 := b64(req.ManifestCT, s.cfg.Limits.ManifestCTMaxBytes)
	check, err3 := b64(req.CheckCT, s.cfg.Limits.CheckCTBytes)
	if err1 != nil || err2 != nil || err3 != nil {
		writeError(w, http.StatusBadRequest, "blob_size")
		return
	}
	if len(check) != int(s.cfg.Limits.CheckCTBytes) {
		writeError(w, http.StatusBadRequest, "check_size")
		return
	}

	// the blobs are sqlite storage, they meter against the same daily quota
	// as parts. a text only share declares zero at create, this is the only
	// gate that bounds it
	blobTotal := int64(len(title) + len(manifest) + len(check))
	dayStart := time.Now().Truncate(24 * time.Hour)
	used, qerr := s.store.BytesTodayByIP(r.Context(), s.clientIP(r), dayStart)
	if qerr != nil {
		s.log.Error("quota meter", "err", qerr)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if used+blobTotal > s.cfg.Limits.DailyIPBytes {
		writeError(w, http.StatusTooManyRequests, "quota")
		return
	}

	err := s.store.FinalizeShare(r.Context(), id, sqlite.Blobs{TitleCT: title, ManifestCT: manifest, CheckCT: check})
	switch {
	case err == nil:
		if ierr := s.store.InsertEvent(r.Context(), id, "finalised", s.clientIP(r), "", r.UserAgent(), blobTotal); ierr != nil {
			s.log.Error("event", "err", ierr)
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "share_id": id})
	case errors.Is(err, sqlite.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found")
	case errors.Is(err, sqlite.ErrWrongState):
		writeError(w, http.StatusConflict, "wrong_state")
	default:
		s.log.Error("finalise", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
	}
}

func b64(v string, max int64) ([]byte, error) {
	if v == "" {
		return nil, nil
	}
	out, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, err
	}
	if int64(len(out)) > max {
		return nil, errors.New("too large")
	}
	return out, nil
}

func (s *Server) turnstileEnforced() bool {
	return s.cfg.TurnstileMode == "required"
}

func (s *Server) turnstileOk(r *http.Request, ip string) bool {
	switch s.cfg.TurnstileMode {
	case "disabled":
		return true
	case "optional":
		return true
	default:
		return s.turnstileVerify(r.Context(), r.Header.Get("X-Turnstile-Token"), ip)
	}
}
