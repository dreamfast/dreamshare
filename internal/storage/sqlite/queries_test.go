package sqlite

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func openStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func newShareBuilder(t *testing.T, id string, mode string, files int) NewShare {
	t.Helper()
	ns := NewShare{
		ID: id, FormatVersion: "ds1", FileCount: files, TotalBytes: int64(files * 100),
		ExpiryMode: mode, ExpiresAt: time.Now().Add(time.Hour), MaxAttempts: 5,
		ManagerTokenHash: "mgr-" + id, TurnstileOK: true,
		CreatedIP: "203.0.113.9", CreatedCountry: "AU", CreatedUA: "test",
		ChunkSecret: []byte("secret"), SessionTTL: time.Hour,
	}
	for i := range files {
		ns.Files = append(ns.Files, NewFile{
			ID: fileID(id, i), Position: i, ObjectKey: "f/2608/" + fileID(id, i),
			ByteSize: 100, FrameCount: 1, FrameSize: 1 << 20, PartSize: 100,
			SessionID: "sess-" + fileID(id, i), ExpectedParts: 1,
		})
	}
	return ns
}

func fileID(shareID string, i int) string {
	return fmt.Sprintf("%s-f%c", shareID, 'a'+byte(i)) //nolint:gosec // loop bound is 8, no overflow
}

func mustCreate(t *testing.T, s *Store, ns NewShare) {
	t.Helper()
	if err := s.CreateShare(t.Context(), ns); err != nil {
		t.Fatalf("create: %v", err)
	}
}

func mustFinalize(t *testing.T, s *Store, id string) {
	t.Helper()
	if err := s.FinalizeShare(t.Context(), id, Blobs{
		TitleCT: []byte("title-ct"), ManifestCT: []byte("manifest-ct"), CheckCT: make([]byte, 45),
	}); err != nil {
		t.Fatalf("finalise: %v", err)
	}
}

func closeSessions(t *testing.T, s *Store, shareID string) {
	t.Helper()
	_, err := s.Writer.ExecContext(t.Context(),
		"update upload_sessions set completed_at = 1 where share_id = ?", shareID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateFinalizeHappyPath(t *testing.T) {
	s := openStore(t)
	mustCreate(t, s, newShareBuilder(t, "sh1", "burn_on_ack", 2))
	closeSessions(t, s, "sh1")

	// pending shares answer status but refuse downloads
	sh, err := s.GetShare(t.Context(), "sh1")
	if err != nil || sh.Status != "pending" {
		t.Fatalf("want pending share, got %v %v", sh, err)
	}
	if _, err := s.BeginDownload(t.Context(), "sh1", fileID("sh1", 0)); !errors.Is(err, ErrShareNotReady) {
		t.Fatalf("pending download: want ErrShareNotReady, got %v", err)
	}

	mustFinalize(t, s, "sh1")
	sh, err = s.GetShare(t.Context(), "sh1")
	if err != nil || sh.Status != "active" {
		t.Fatalf("want active share after finalise, got %v %v", sh, err)
	}
}

func TestFinalizeGuards(t *testing.T) {
	s := openStore(t)
	mustCreate(t, s, newShareBuilder(t, "sh1", "burn_on_ack", 1))

	// open upload sessions block the finalise step
	err := s.FinalizeShare(t.Context(), "sh1", Blobs{TitleCT: []byte("t"), ManifestCT: []byte("m"), CheckCT: make([]byte, 45)})
	if !errors.Is(err, ErrWrongState) {
		t.Fatalf("finalise with open sessions: want ErrWrongState, got %v", err)
	}
	closeSessions(t, s, "sh1")

	mustFinalize(t, s, "sh1")
	// same blobs, idempotent
	if err := s.FinalizeShare(t.Context(), "sh1", Blobs{TitleCT: []byte("title-ct"), ManifestCT: []byte("manifest-ct"), CheckCT: make([]byte, 45)}); err != nil {
		t.Fatalf("idempotent finalise: %v", err)
	}
	// different blobs over an active share, refused
	if err := s.FinalizeShare(t.Context(), "sh1", Blobs{TitleCT: []byte("evil"), ManifestCT: []byte("m"), CheckCT: make([]byte, 45)}); !errors.Is(err, ErrWrongState) {
		t.Fatalf("re-seal over active: want ErrWrongState, got %v", err)
	}
	// unknown share
	if err := s.FinalizeShare(t.Context(), "nope", Blobs{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown finalise: want ErrNotFound, got %v", err)
	}
}

func TestBeginDownloadAttemptCaps(t *testing.T) {
	s := openStore(t)
	mustCreate(t, s, newShareBuilder(t, "sh1", "burn_on_ack", 1))
	closeSessions(t, s, "sh1")
	mustFinalize(t, s, "sh1")

	for i := 1; i <= 5; i++ {
		f, err := s.BeginDownload(t.Context(), "sh1", fileID("sh1", 0))
		if err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
		if f.Attempts != i {
			t.Fatalf("attempt counter %d, want %d", f.Attempts, i)
		}
	}
	if _, err := s.BeginDownload(t.Context(), "sh1", fileID("sh1", 0)); !errors.Is(err, ErrRefused) {
		t.Fatalf("sixth attempt: want ErrRefused, got %v", err)
	}
	// the refusal must not move the share wide counter
	sh, _ := s.GetShare(t.Context(), "sh1")
	if sh.DownloadsUsed != 5 {
		t.Fatalf("downloads_used %d after refusals, want 5", sh.DownloadsUsed)
	}
}

// A share with more files than max_attempts must be fully deliverable, the
// cap is per file.
func TestBeginDownloadManyFiles(t *testing.T) {
	s := openStore(t)
	mustCreate(t, s, newShareBuilder(t, "big", "burn_on_ack", 8))
	closeSessions(t, s, "big")
	mustFinalize(t, s, "big")
	for i := range 8 {
		if _, err := s.BeginDownload(t.Context(), "big", fileID("big", i)); err != nil {
			t.Fatalf("file %d: %v", i, err)
		}
	}
}

func TestBeginDownloadMaxDownloadsCap(t *testing.T) {
	s := openStore(t)
	ns := newShareBuilder(t, "sh1", "burn_on_ack", 2)
	mustCreate(t, s, ns)
	closeSessions(t, s, "sh1")
	if _, err := s.Writer.ExecContext(t.Context(), "update shares set max_downloads = 1 where id = 'sh1'"); err != nil {
		t.Fatal(err)
	}
	mustFinalize(t, s, "sh1")
	if _, err := s.BeginDownload(t.Context(), "sh1", fileID("sh1", 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BeginDownload(t.Context(), "sh1", fileID("sh1", 1)); !errors.Is(err, ErrRefused) {
		t.Fatalf("second file past max_downloads: want ErrRefused, got %v", err)
	}
}

func TestAckStateMachine(t *testing.T) {
	s := openStore(t)
	mustCreate(t, s, newShareBuilder(t, "sh1", "burn_on_ack", 3))
	closeSessions(t, s, "sh1")
	mustFinalize(t, s, "sh1")

	// ack file 0 of 3: no flip, others still downloadable
	if _, err := s.BeginDownload(t.Context(), "sh1", fileID("sh1", 0)); err != nil {
		t.Fatal(err)
	}
	flipped, err := s.AckFile(t.Context(), "sh1", fileID("sh1", 0))
	if err != nil || flipped {
		t.Fatalf("first ack flipped=%v err=%v", flipped, err)
	}
	if _, err := s.BeginDownload(t.Context(), "sh1", fileID("sh1", 1)); err != nil {
		t.Fatalf("file 1 must stay downloadable after partial ack: %v", err)
	}

	// ack the rest, the last one flips
	if _, err := s.BeginDownload(t.Context(), "sh1", fileID("sh1", 1)); err != nil {
		t.Fatal(err)
	}
	if flipped, err = s.AckFile(t.Context(), "sh1", fileID("sh1", 1)); err != nil || flipped {
		t.Fatalf("second ack flipped=%v err=%v", flipped, err)
	}
	if _, err := s.BeginDownload(t.Context(), "sh1", fileID("sh1", 2)); err != nil {
		t.Fatal(err)
	}
	flipped, err = s.AckFile(t.Context(), "sh1", fileID("sh1", 2))
	if err != nil || !flipped {
		t.Fatalf("final ack flipped=%v err=%v", flipped, err)
	}
	sh, _ := s.GetShare(t.Context(), "sh1")
	if sh.Status != "delivered" {
		t.Fatalf("status %s after full ack, want delivered", sh.Status)
	}
	// downloads refuse after delivery
	if _, err := s.BeginDownload(t.Context(), "sh1", fileID("sh1", 0)); !errors.Is(err, ErrRefused) {
		t.Fatalf("download after delivery: want ErrRefused, got %v", err)
	}
	// an already acked file acks idempotently
	if _, err := s.AckFile(t.Context(), "sh1", fileID("sh1", 2)); err != nil {
		t.Fatalf("idempotent ack: %v", err)
	}
}

// Two acks racing the last two files must flip the share exactly once.
func TestAckParallelFlipOnce(t *testing.T) {
	s := openStore(t)
	mustCreate(t, s, newShareBuilder(t, "sh1", "burn_on_ack", 2))
	closeSessions(t, s, "sh1")
	mustFinalize(t, s, "sh1")

	done := make(chan bool, 2)
	for i := range 2 {
		go func(i int) {
			flipped, err := s.AckFile(t.Context(), "sh1", fileID("sh1", i))
			done <- err == nil && flipped
		}(i)
	}
	flips := 0
	for range 2 {
		if <-done {
			flips++
		}
	}
	if flips != 1 {
		t.Fatalf("%d flips from parallel acks, want exactly 1", flips)
	}
}

// A ttl share records acks as receipts and dies at its clock, never on ack.
func TestAckTTLShareDoesNotFlip(t *testing.T) {
	s := openStore(t)
	mustCreate(t, s, newShareBuilder(t, "ttlsh", "ttl", 1))
	closeSessions(t, s, "ttlsh")
	mustFinalize(t, s, "ttlsh")
	if _, err := s.BeginDownload(t.Context(), "ttlsh", fileID("ttlsh", 0)); err != nil {
		t.Fatal(err)
	}
	flipped, err := s.AckFile(t.Context(), "ttlsh", fileID("ttlsh", 0))
	if err != nil {
		t.Fatal(err)
	}
	if flipped {
		t.Fatal("ttl share flipped on ack")
	}
	sh, _ := s.GetShare(t.Context(), "ttlsh")
	if sh.Status != "active" {
		t.Fatalf("ttl share status %s after ack, want active", sh.Status)
	}
}

func TestNotifyBound(t *testing.T) {
	s := openStore(t)
	mustCreate(t, s, newShareBuilder(t, "sh1", "burn_on_ack", 1))
	closeSessions(t, s, "sh1")
	mustFinalize(t, s, "sh1")

	if err := s.NotifyEnqueue(t.Context(), "sh1", "owner@example.com", time.Hour); err != nil {
		t.Fatalf("first notify: %v", err)
	}
	if err := s.NotifyEnqueue(t.Context(), "sh1", "anyone@example.com", time.Hour); !errors.Is(err, ErrNotifyThrottled) {
		t.Fatalf("second notify within the hour: want ErrNotifyThrottled, got %v", err)
	}

	id, shareID, to, ok, err := s.NotifyDue(t.Context())
	if err != nil || !ok || shareID != "sh1" || to != "owner@example.com" {
		t.Fatalf("notify due: ok=%v err=%v", ok, err)
	}
	if err := s.NotifySent(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	// sent rows blank the address, erasure is the settled state
	var addr sql.NullString
	if err := s.Reader.QueryRowContext(t.Context(), "select to_addr from outbox where id = ?", id).Scan(&addr); err != nil {
		t.Fatal(err)
	}
	if addr.Valid && addr.String != "" {
		t.Fatalf("address survived sending: %q", addr.String)
	}
	// the hourly bound counts sent rows too, a sent mail inside the window
	// still throttles the next one
	if err := s.NotifyEnqueue(t.Context(), "sh1", "owner@example.com", time.Hour); !errors.Is(err, ErrNotifyThrottled) {
		t.Fatalf("notify inside the window after send: want ErrNotifyThrottled, got %v", err)
	}
}

func TestRevokeByManagerToken(t *testing.T) {
	s := openStore(t)
	mustCreate(t, s, newShareBuilder(t, "sh1", "burn_on_ack", 1))
	closeSessions(t, s, "sh1")
	mustFinalize(t, s, "sh1")

	id, err := s.RevokeByManagerToken(t.Context(), "mgr-sh1")
	if err != nil || id != "sh1" {
		t.Fatalf("revoke: %v %v", id, err)
	}
	if _, err := s.BeginDownload(t.Context(), "sh1", fileID("sh1", 0)); !errors.Is(err, ErrRefused) {
		t.Fatalf("download after revoke: want ErrRefused, got %v", err)
	}
	if _, err := s.RevokeByManagerToken(t.Context(), "mgr-sh1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second revoke: want ErrNotFound, got %v", err)
	}
}

func TestExpiryToVersionDeleteToTombstone(t *testing.T) {
	s := openStore(t)
	ns := newShareBuilder(t, "old", "ttl", 1)
	ns.ExpiresAt = time.Now().Add(-time.Minute)
	mustCreate(t, s, ns)
	closeSessions(t, s, "old")
	mustFinalize(t, s, "old")
	// pretend versions were recorded
	_, err := s.Writer.ExecContext(t.Context(),
		"update share_files set b2_file_id = 'bv1' where share_id = 'old'")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InsertEvent(t.Context(), "old", "created", "203.0.113.9", "AU", "ua", 100); err != nil {
		t.Fatal(err)
	}

	ids, err := s.ExpireDue(t.Context(), time.Now())
	if err != nil || len(ids) != 1 || ids[0] != "old" {
		t.Fatalf("expire due: %v %v", ids, err)
	}
	// force the tombstone clock into the past, the sweep keys on it
	if _, err := s.Writer.ExecContext(t.Context(),
		"update shares set terminal_at = ? where id = 'old'", time.Now().Add(-2*time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	pending, err := s.TerminalSharesForVersionDelete(t.Context())
	if err != nil || len(pending["old"]) != 1 {
		t.Fatalf("version delete list: %v %v", pending, err)
	}
	if err := s.MarkVersionsDeleted(t.Context(), "old", []VersionRef{{Key: "f/2608/old", FileID: "bv1"}}); err != nil {
		t.Fatal(err)
	}

	// tombstone sweep past the window removes the row and cascades events
	n, err := s.SweepTombstones(t.Context(), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("tombstone sweep removed nothing")
	}
	var events int
	if err := s.Reader.QueryRowContext(t.Context(), "select count(*) from share_events").Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 0 {
		t.Fatalf("%d events survived their share", events)
	}
}

// The schema pins carried from the S0 review.
func TestSchemaCheckConstraints(t *testing.T) {
	s := openStore(t)
	mustCreate(t, s, newShareBuilder(t, "sh1", "burn_on_ack", 1))
	if _, err := s.Writer.ExecContext(t.Context(),
		"update shares set max_attempts = 0 where id = 'sh1'"); err == nil {
		t.Fatal("max_attempts = 0 accepted")
	}
	if _, err := s.Writer.ExecContext(t.Context(),
		"update shares set max_downloads = 0 where id = 'sh1'"); err == nil {
		t.Fatal("max_downloads = 0 accepted")
	}
	// case blind email uniqueness
	mustExec(t, s.Writer, `insert into admin_users(id, email, password_hash, created_at)
		values('u1','Owner@Example.com','x',0)`)
	if _, err := s.Writer.ExecContext(t.Context(), `insert into admin_users(id, email, password_hash, created_at)
		values('u2','owner@example.com','x',0)`); err == nil {
		t.Fatal("case folded duplicate email accepted")
	}
}

func TestBytesTodayByIP(t *testing.T) {
	s := openStore(t)
	// stored bytes are counted from the parts table through the session to
	// the creating share's ip, not from declared sizes
	mustCreate(t, s, newShareBuilder(t, "sh1", "burn_on_ack", 1))
	sess := "sess-" + fileID("sh1", 0)
	mustExec(t, s.Writer, `insert into upload_parts(sid, part_number, size) values('`+sess+`', 1, 500)`)
	if err := s.InsertEvent(t.Context(), "sh1", "downloaded", "198.51.100.4", "AU", "ua", 300); err != nil {
		t.Fatal(err)
	}
	up, err := s.BytesTodayByIP(t.Context(), "203.0.113.9", time.Now().Add(-time.Hour))
	if err != nil || up != 500 {
		t.Fatalf("uploader bytes %d %v, want 500", up, err)
	}
	down, err := s.BytesTodayByIP(t.Context(), "198.51.100.4", time.Now().Add(-time.Hour))
	if err != nil || down != 300 {
		t.Fatalf("downloader bytes %d %v, want 300", down, err)
	}
	// a re sent part replaces, it does not double count
	mustExec(t, s.Writer, `update upload_parts set size = 400 where sid = '`+sess+`' and part_number = 1`)
	up, err = s.BytesTodayByIP(t.Context(), "203.0.113.9", time.Now().Add(-time.Hour))
	if err != nil || up != 400 {
		t.Fatalf("after retry bytes %d %v, want 400", up, err)
	}
}
