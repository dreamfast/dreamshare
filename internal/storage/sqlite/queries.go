package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Typed refusals so handlers map them to status codes without string
// matching. Every one of these is an expected outcome, not an error in the
// bug sense.
var (
	// ErrNotFound means the capability token or file id is unknown or gone.
	ErrNotFound = errors.New("not found")
	// ErrShareNotReady means a pending share was addressed before the finalise step.
	ErrShareNotReady = errors.New("share is not ready")
	// ErrRefused means the share exists but the fetch was refused: expired,
	// attempts exhausted or the download cap was hit.
	ErrRefused = errors.New("refused")
	// ErrWrongState means an idempotent retry hit a different state.
	ErrWrongState = errors.New("wrong state")
	// ErrNotifyThrottled means the one unsent row per share and kind rule,
	// or the hourly window, refused the insert.
	ErrNotifyThrottled = errors.New("notify throttled")
)

// NewFile is one file of a share at creation time. Sizes only, names travel
// inside the encrypted manifest.
type NewFile struct {
	ID            string
	Position      int
	ObjectKey     string
	ByteSize      int64
	FrameCount    int
	FrameSize     int
	PartSize      int64
	SessionID     string
	ExpectedParts int
}

// NewShare carries everything the create call writes in one transaction.
type NewShare struct {
	ID               string
	FormatVersion    string
	FileCount        int
	TotalBytes       int64
	ExpiryMode       string
	ExpiresAt        time.Time
	MaxAttempts      int
	ManagerTokenHash string
	TurnstileOK      bool
	CreatedIP        string
	CreatedCountry   string
	CreatedASN       string
	CreatedUA        string
	ChunkSecret      []byte
	SessionTTL       time.Duration
	Files            []NewFile
}

// CreateShare writes the share, its files and the upload sessions in one
// transaction. Anything wrong leaves nothing behind.
func (s *Store) CreateShare(ctx context.Context, ns NewShare) error {
	tx, err := s.Writer.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().Unix()
	turnstile := 0
	if ns.TurnstileOK {
		turnstile = 1
	}
	_, err = tx.ExecContext(ctx, `insert into shares(
		id, format_version, file_count, total_bytes, expiry_mode, expires_at,
		max_attempts, manager_token_hash, turnstile_ok,
		created_ip, created_country, created_asn, created_ua, created_at, status)
		values(?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'pending')`,
		ns.ID, ns.FormatVersion, ns.FileCount, ns.TotalBytes, ns.ExpiryMode,
		ns.ExpiresAt.Unix(), ns.MaxAttempts, nullString(ns.ManagerTokenHash), turnstile,
		ns.CreatedIP, ns.CreatedCountry, ns.CreatedASN, ns.CreatedUA, now)
	if err != nil {
		return fmt.Errorf("insert share: %w", err)
	}

	for _, f := range ns.Files {
		_, err = tx.ExecContext(ctx, `insert into share_files(
			id, share_id, position, object_key, byte_size, frame_count, frame_size, part_size)
			values(?,?,?,?,?,?,?,?)`,
			f.ID, ns.ID, f.Position, f.ObjectKey, f.ByteSize, f.FrameCount, f.FrameSize, f.PartSize)
		if err != nil {
			return fmt.Errorf("insert file %s: %w", f.ID, err)
		}
		_, err = tx.ExecContext(ctx, `insert into upload_sessions(
			id, share_id, file_id, part_size, expected_parts, chunk_secret, created_at, expires_at)
			values(?,?,?,?,?,?,?,?)`,
			f.SessionID, ns.ID, f.ID, f.PartSize, f.ExpectedParts, ns.ChunkSecret,
			now, now+int64(ns.SessionTTL.Seconds()))
		if err != nil {
			return fmt.Errorf("insert session %s: %w", f.SessionID, err)
		}
	}
	return tx.Commit()
}

func nullString(v string) any {
	if v == "" {
		return nil
	}
	return v
}

// Share is the read model for status endpoints and the download gate.
type Share struct {
	ID            string
	FormatVersion string
	Status        string
	ExpiryMode    string
	ExpiresAt     time.Time
	AckedAt       sql.NullTime
	FileCount     int
	TotalBytes    int64
	MaxAttempts   int
	DownloadsUsed int
	MaxDownloads  sql.NullInt64
}

func scanShare(row interface{ Scan(...any) error }) (*Share, error) {
	var sh Share
	var expiresAt, ackedAt sql.NullInt64
	err := row.Scan(&sh.ID, &sh.FormatVersion, &sh.Status, &sh.ExpiryMode, &expiresAt,
		&ackedAt, &sh.FileCount, &sh.TotalBytes, &sh.MaxAttempts, &sh.DownloadsUsed, &sh.MaxDownloads)
	if err != nil {
		return nil, err
	}
	sh.ExpiresAt = time.Unix(expiresAt.Int64, 0)
	if ackedAt.Valid {
		sh.AckedAt = sql.NullTime{Time: time.Unix(ackedAt.Int64, 0), Valid: true}
	}
	return &sh, nil
}

const shareCols = `id, format_version, status, expiry_mode, expires_at, acked_at,
	file_count, total_bytes, max_attempts, downloads_used, max_downloads`

// GetShare reads one share by its capability id.
func (s *Store) GetShare(ctx context.Context, id string) (*Share, error) {
	sh, err := scanShare(s.Reader.QueryRowContext(ctx,
		"select "+shareCols+" from shares where id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return sh, err
}

// File is the read model the download handler streams.
type File struct {
	ID         string
	ShareID    string
	ObjectKey  string
	ByteSize   int64
	FrameCount int
	FrameSize  int
	Attempts   int
	AckedAt    sql.NullInt64
}

// BeginDownload is the step one transaction: the per file attempt counter
// moves only when the fetch is allowed, and the share wide counter follows.
// A refusal touches no counter at all.
func (s *Store) BeginDownload(ctx context.Context, shareID, fileID string) (*File, error) {
	tx, err := s.Writer.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var (
		f             File
		expiresAt     int64
		ackedAt       sql.NullInt64
		status        string
		maxAttempts   int
		downloadsUsed int
		maxDownloads  sql.NullInt64
	)
	err = tx.QueryRowContext(ctx, `select sf.id, sf.share_id, sf.object_key, sf.byte_size,
		sf.frame_count, sf.frame_size, sf.attempts, sf.acked_at,
		sh.status, sh.expires_at, sh.acked_at, sh.max_attempts,
		sh.downloads_used, sh.max_downloads
		from share_files sf join shares sh on sh.id = sf.share_id
		where sf.share_id = ? and sf.id = ?`, shareID, fileID).
		Scan(&f.ID, &f.ShareID, &f.ObjectKey, &f.ByteSize,
			&f.FrameCount, &f.FrameSize, &f.Attempts, &f.AckedAt,
			&status, &expiresAt, &ackedAt, &maxAttempts,
			&downloadsUsed, &maxDownloads)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	switch {
	case status == "pending":
		return nil, ErrShareNotReady
	case status != "active":
		return nil, ErrRefused
	case ackedAt.Valid:
		return nil, ErrRefused
	case time.Now().Unix() >= expiresAt:
		return nil, ErrRefused
	case maxDownloads.Valid && int64(downloadsUsed) >= maxDownloads.Int64:
		return nil, ErrRefused
	case f.AckedAt.Valid:
		// the file was already fetched and verified, re-fetching before the
		// share flips is refused rather than double counted
		return nil, ErrRefused
	}

	res, err := tx.ExecContext(ctx, `update share_files set attempts = attempts + 1
		where id = ? and share_id = ? and attempts < ?`,
		fileID, shareID, maxAttempts)
	if err != nil {
		return nil, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, ErrRefused // attempts exhausted, nothing moved
	}
	if _, err := tx.ExecContext(ctx,
		`update shares set downloads_used = downloads_used + 1 where id = ?`, shareID); err != nil {
		return nil, err
	}
	f.Attempts++
	return &f, tx.Commit()
}

// Blobs are the payloads of the finalise step, ciphertext straight from the browser.
type Blobs struct {
	TitleCT    []byte
	ManifestCT []byte
	CheckCT    []byte
}

// FinalizeShare flips pending to active and stores the sealed blobs. It is
// pending only and idempotent: a repeated call with the same blobs returns
// nil, anything else refuses.
func (s *Store) FinalizeShare(ctx context.Context, shareID string, blobs Blobs) error {
	tx, err := s.Writer.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var status string
	var haveTitle, haveCheck sql.NullInt64
	err = tx.QueryRowContext(ctx,
		"select status, length(title_ct), length(check_ct) from shares where id = ?", shareID).
		Scan(&status, &haveTitle, &haveCheck)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if status == "active" && haveTitle.Valid && haveCheck.Valid {
		// idempotent retry, accept only when the blobs are identical
		var existing Blobs
		err = tx.QueryRowContext(ctx,
			"select title_ct, manifest_ct, check_ct from shares where id = ?",
			shareID).Scan(&existing.TitleCT, &existing.ManifestCT, &existing.CheckCT)
		if err != nil {
			return err
		}
		if string(existing.TitleCT) == string(blobs.TitleCT) &&
			string(existing.ManifestCT) == string(blobs.ManifestCT) &&
			string(existing.CheckCT) == string(blobs.CheckCT) {
			return nil
		}
		return ErrWrongState
	}
	if status != "pending" {
		return ErrWrongState
	}

	var pendingParts, expectedParts int
	err = tx.QueryRowContext(ctx, `select
		(select count(*) from upload_sessions us where us.share_id = ? and us.completed_at is null),
		(select count(*) from upload_sessions us where us.share_id = ?)`, shareID, shareID).
		Scan(&pendingParts, &expectedParts)
	if err != nil {
		return err
	}
	if pendingParts != 0 {
		return fmt.Errorf("%w: %d upload sessions still open", ErrWrongState, pendingParts)
	}
	_ = expectedParts

	res, err := tx.ExecContext(ctx, `update shares set
		title_ct = ?, manifest_ct = ?, check_ct = ?, status = 'active'
		where id = ? and status = 'pending'`,
		blobs.TitleCT, blobs.ManifestCT, blobs.CheckCT, shareID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrWrongState
	}
	return tx.Commit()
}

// PeekFile gates a continuation fetch on share state without moving any
// counter. Only a fetch that starts at byte zero counts as a download.
func (s *Store) PeekFile(ctx context.Context, shareID, fileID string) (*File, error) {
	var (
		f           File
		expiresAt   int64
		ackedAt     sql.NullInt64
		status      string
		maxAttempts int
	)
	err := s.Reader.QueryRowContext(ctx, `select sf.id, sf.share_id, sf.object_key, sf.byte_size,
		sf.frame_count, sf.frame_size, sf.attempts, sf.acked_at,
		sh.status, sh.expires_at, sh.acked_at, sh.max_attempts
		from share_files sf join shares sh on sh.id = sf.share_id
		where sf.share_id = ? and sf.id = ?`, shareID, fileID).
		Scan(&f.ID, &f.ShareID, &f.ObjectKey, &f.ByteSize,
			&f.FrameCount, &f.FrameSize, &f.Attempts, &f.AckedAt,
			&status, &expiresAt, &ackedAt, &maxAttempts)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	switch {
	case status == "pending":
		return nil, ErrShareNotReady
	case status != "active":
		return nil, ErrRefused
	case ackedAt.Valid:
		return nil, ErrRefused
	case time.Now().Unix() >= expiresAt:
		return nil, ErrRefused
	case f.Attempts >= maxAttempts:
		return nil, ErrRefused
	}
	return &f, nil
}

// AckFile is the step two transaction: mark the file, then flip the share
// only in burn mode and only when nothing is left un acked. Returns whether
// this call flipped the share, the caller owns the wipe.
func (s *Store) AckFile(ctx context.Context, shareID, fileID string) (bool, error) {
	tx, err := s.Writer.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()

	if fileID != "" {
		res, err := tx.ExecContext(ctx,
			`update share_files set acked_at = ? where share_id = ? and id = ? and acked_at is null`,
			time.Now().Unix(), shareID, fileID)
		if err != nil {
			return false, err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			// already acked is fine, an idempotent retry must not error
			var acked sql.NullInt64
			err = tx.QueryRowContext(ctx,
				"select acked_at from share_files where share_id = ? and id = ?", shareID, fileID).Scan(&acked)
			if errors.Is(err, sql.ErrNoRows) {
				return false, ErrNotFound
			}
			if err != nil {
				return false, err
			}
			if !acked.Valid {
				return false, ErrWrongState
			}
		}
	}

	res, err := tx.ExecContext(ctx, `update shares set status = 'delivered', acked_at = ?, terminal_at = ?
		where id = ? and status = 'active' and acked_at is null
		and expires_at > ?
		and expiry_mode = 'burn_on_ack'
		and not exists (select 1 from share_files where share_id = ? and acked_at is null)`,
		time.Now().Unix(), time.Now().Unix(), shareID, time.Now().Unix(), shareID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n == 1 {
		return true, tx.Commit()
	}
	return false, tx.Commit()
}

// NotifyEnqueue inserts one outbox row. The partial unique index makes a
// second unsent row for the same share and kind fail at the database, which
// is the notify rate bound no restart can reset.
func (s *Store) NotifyEnqueue(ctx context.Context, shareID, toAddr string, hourlyWindow time.Duration) error {
	tx, err := s.Writer.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var count int
	err = tx.QueryRowContext(ctx,
		`select count(*) from outbox where share_id = ? and kind = 'downloaded' and created_at > ?`,
		shareID, time.Now().Add(-hourlyWindow).Unix()).Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		return ErrNotifyThrottled
	}
	_, err = tx.ExecContext(ctx,
		`insert into outbox(share_id, to_addr, kind, created_at) values(?,?,'downloaded',?)`,
		shareID, toAddr, time.Now().Unix())
	if err != nil {
		// the unique index is the backstop when two requests race
		if strings.Contains(err.Error(), "unique") {
			return ErrNotifyThrottled
		}
		return err
	}
	return tx.Commit()
}

// NotifyDue returns unsent rows older than a small settle delay.
func (s *Store) NotifyDue(ctx context.Context) (id int64, shareID, toAddr string, ok bool, err error) {
	err = s.Reader.QueryRowContext(ctx,
		`select id, share_id, coalesce(to_addr,'') from outbox
		where sent_at is null order by id limit 1`).Scan(&id, &shareID, &toAddr)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", "", false, nil
	}
	if err != nil {
		return 0, "", "", false, err
	}
	return id, shareID, toAddr, true, nil
}

// NotifySent marks a row sent and blanks the address, erasure is the
// settled state for the row.
func (s *Store) NotifySent(ctx context.Context, id int64) error {
	_, err := s.Writer.ExecContext(ctx,
		"update outbox set sent_at = ?, to_addr = null where id = ?", time.Now().Unix(), id)
	return err
}

// NotifyFailed records the failure, the reconciler retries.
func (s *Store) NotifyFailed(ctx context.Context, id int64, sendErr string) error {
	_, err := s.Writer.ExecContext(ctx,
		"update outbox set attempts = attempts + 1, last_error = ? where id = ?", sendErr, id)
	return err
}

// RevokeByManagerToken marks a share revoked. The token is hashed, so a
// database leak grants no revoke rights.
func (s *Store) RevokeByManagerToken(ctx context.Context, tokenHash string) (shareID string, err error) {
	err = s.Writer.QueryRowContext(ctx,
		`update shares set status = 'revoked', terminal_at = ?
		where manager_token_hash = ? and status in ('pending','active','delivered') returning id`,
		time.Now().Unix(), tokenHash).Scan(&shareID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return shareID, err
}

// ShareIDByManagerHash resolves a manager link to its share id without
// changing anything, for the confirm page.
func (s *Store) ShareIDByManagerHash(ctx context.Context, tokenHash string) (string, error) {
	var id string
	err := s.Reader.QueryRowContext(ctx,
		"select id from shares where manager_token_hash = ?", tokenHash).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return id, err
}

// ExpireDue flips active shares past their ceiling to expired and returns
// their ids. The caller deletes the B2 versions.
func (s *Store) ExpireDue(ctx context.Context, now time.Time) ([]string, error) {
	rows, err := s.Writer.QueryContext(ctx,
		`update shares set status = 'expired', terminal_at = ?
		where status in ('pending','active') and expires_at <= ? returning id`,
		now.Unix(), now.Unix())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// VersionRef is the storage identity of one stored file: the object key and
// the b2 file id, both needed for a version delete.
type VersionRef struct {
	Key    string
	FileID string
}

func (s *Store) TerminalSharesForVersionDelete(ctx context.Context) (map[string][]VersionRef, error) {
	rows, err := s.Reader.QueryContext(ctx, `select sf.share_id, sf.object_key, sf.b2_file_id
		from share_files sf join shares sh on sh.id = sf.share_id
		where sh.status in ('delivered','expired','revoked','wiped')
		and sf.b2_file_id is not null and sf.b2_file_id != ''`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string][]VersionRef{}
	for rows.Next() {
		var shareID string
		var ref VersionRef
		if err := rows.Scan(&shareID, &ref.Key, &ref.FileID); err != nil {
			return nil, err
		}
		out[shareID] = append(out[shareID], ref)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// MarkVersionsDeleted clears exactly the file ids this pass deleted, so a
// version id recorded by a racing upload is never silently dropped, and
// marks delivered shares wiped.
func (s *Store) MarkVersionsDeleted(ctx context.Context, shareID string, refs []VersionRef) error {
	tx, err := s.Writer.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, ref := range refs {
		if _, err := tx.ExecContext(ctx,
			"update share_files set b2_file_id = null where share_id = ? and b2_file_id = ?",
			shareID, ref.FileID); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx,
		"update shares set status = 'wiped' where id = ? and status = 'delivered'", shareID); err != nil {
		return err
	}
	return tx.Commit()
}

// SweepTombstones deletes rows whose terminal state outlived the window.
// Events and outbox rows follow through the cascades. The clock is
// terminal_at, not expires_at, so a revoked share does not linger for its
// whole ttl ceiling.
func (s *Store) SweepTombstones(ctx context.Context, olderThan time.Time) (int64, error) {
	res, err := s.Writer.ExecContext(ctx,
		`delete from shares where status in ('wiped','expired','revoked','delivered')
		and terminal_at is not null and terminal_at < ?`,
		olderThan.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// InsertEvent writes one telemetry row. It dies with the share.
func (s *Store) InsertEvent(ctx context.Context, shareID, event, ip, country, ua string, bytes int64) error {
	_, err := s.Writer.ExecContext(ctx,
		`insert into share_events(share_id, ts, event, ip, country, ua, bytes) values(?,?,?,?,?,?,?)`,
		shareID, time.Now().Unix(), event, ip, country, ua, nullInt64(bytes))
	return err
}

func nullInt64(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

// Session is the upload session view the part handlers need.
type Session struct {
	ID            string
	ShareID       string
	FileID        string
	ObjectKey     string
	UploadID      string
	PartSize      int64
	ExpectedParts int
	ChunkSecret   []byte
	Multipart     bool
	BytesReceived int64
	FileByteSize  int64
}

// LoadSession reads one upload session joined with its file.
func (s *Store) LoadSession(ctx context.Context, sid string) (*Session, error) {
	var sess Session
	var uploadID sql.NullString
	var completedAt sql.NullInt64
	var status string
	var expiresAt int64
	err := s.Reader.QueryRowContext(ctx, `select us.id, us.share_id, us.file_id,
		sf.object_key, us.b2_upload_id, us.part_size, us.expected_parts, us.chunk_secret,
		us.completed_at, sh.status, sh.expires_at,
		(select coalesce(sum(size),0) from upload_parts where sid = us.id)
		from upload_sessions us
		join share_files sf on sf.id = us.file_id
		join shares sh on sh.id = us.share_id
		where us.id = ?`, sid).
		Scan(&sess.ID, &sess.ShareID, &sess.FileID, &sess.ObjectKey, &uploadID,
			&sess.PartSize, &sess.ExpectedParts, &sess.ChunkSecret, &completedAt,
			&status, &expiresAt, &sess.BytesReceived)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	// a closed or terminal session accepts no traffic, a revoked share must
	// not keep accepting parts
	if completedAt.Valid {
		return nil, ErrWrongState
	}
	if status != "active" && status != "pending" {
		return nil, ErrRefused
	}
	if time.Now().Unix() >= expiresAt {
		return nil, ErrRefused
	}
	if uploadID.Valid {
		sess.UploadID = uploadID.String
	}
	sess.Multipart = sess.ExpectedParts > 1
	var fileSize sql.NullInt64
	_ = s.Reader.QueryRowContext(ctx,
		"select byte_size from share_files where id = ?", sess.FileID).Scan(&fileSize)
	sess.FileByteSize = fileSize.Int64
	return &sess, nil
}

// CurrentFileVersion returns the recorded b2 file id for a file, so a retry
// can delete the superseded version instead of orphaning it.
func (s *Store) CurrentFileVersion(ctx context.Context, fileID string) (string, error) {
	var v sql.NullString
	err := s.Reader.QueryRowContext(ctx,
		"select b2_file_id from share_files where id = ?", fileID).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return v.String, err
}

// StaleUploads lists open sessions past their ttl with their storage upload
// ids, so the reconciler can abort the parts and stop the billing.
func (s *Store) StaleUploads(ctx context.Context, now time.Time) ([]Session, error) {
	rows, err := s.Reader.QueryContext(ctx, `select us.id, us.b2_upload_id, sf.object_key
		from upload_sessions us
		join share_files sf on sf.id = us.file_id
		where us.completed_at is null and us.expires_at <= ?`, now.Unix())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Session
	for rows.Next() {
		var sess Session
		var uploadID sql.NullString
		if err := rows.Scan(&sess.ID, &uploadID, &sess.ObjectKey); err != nil {
			return nil, err
		}
		sess.UploadID = uploadID.String
		out = append(out, sess)
	}
	return out, rows.Err()
}

// CloseSession marks a session complete without completing its upload.
func (s *Store) CloseSession(ctx context.Context, sid string) error {
	_, err := s.Writer.ExecContext(ctx,
		"update upload_sessions set completed_at = ? where id = ?", time.Now().Unix(), sid)
	return err
}

// SetFileVersionBySession records the object identity for the single PUT
// path, where it is known the moment the object lands.
func (s *Store) SetFileVersionBySession(ctx context.Context, sid, etag, versionID string) error {
	_, err := s.Writer.ExecContext(ctx,
		`update share_files set b2_etag = ?, b2_file_id = ?
		where id = (select file_id from upload_sessions where id = ?)`,
		etag, versionID, sid)
	return err
}

// SetUploadID remembers the storage side upload id for resume.
func (s *Store) SetUploadID(ctx context.Context, sid, uploadID string) error {
	_, err := s.Writer.ExecContext(ctx,
		"update upload_sessions set b2_upload_id = ? where id = ?", uploadID, sid)
	return err
}

// RecordPart stores one landed part.
func (s *Store) RecordPart(ctx context.Context, sid string, number int, etag string, size int64, sha []byte) error {
	_, err := s.Writer.ExecContext(ctx,
		`insert into upload_parts(sid, part_number, etag, size, sha256) values(?,?,?,?,?)
		on conflict(sid, part_number) do update set etag = excluded.etag, size = excluded.size, sha256 = excluded.sha256`,
		sid, number, etag, size, sha)
	return err
}

// PartsFor lists the recorded parts of a session, ordered.
func (s *Store) PartsFor(ctx context.Context, sid string) ([]PartRow, error) {
	rows, err := s.Reader.QueryContext(ctx,
		"select part_number, etag, size from upload_parts where sid = ? order by part_number", sid)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []PartRow
	for rows.Next() {
		var p PartRow
		if err := rows.Scan(&p.Number, &p.ETag, &p.Size); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PartRow is one recorded part.
type PartRow struct {
	Number int
	ETag   string
	Size   int64
}

// CompleteSession closes the session and records the object identity.
func (s *Store) CompleteSession(ctx context.Context, sid, etag, versionID string) error {
	_, err := s.Writer.ExecContext(ctx,
		"update upload_sessions set completed_at = ? where id = ? and completed_at is null",
		time.Now().Unix(), sid)
	if err != nil {
		return err
	}
	if versionID != "" {
		_, err = s.Writer.ExecContext(ctx,
			"update share_files set b2_etag = ?, b2_file_id = ? where id = (select file_id from upload_sessions where id = ?)",
			etag, versionID, sid)
	}
	return err
}

// BytesTodayByIP sums this ip's stored and downloaded bytes for the daily
// quota. Ingress and egress are one budget. Stored bytes are counted from
// the parts table, actual bytes rather than declared ones, joined through
// the sessions to the creating share's ip, plus finalise blob bytes from the
// finalised events. Note the part side counts for as long as the share rows
// live, which overcounts and is the safe direction.
func (s *Store) BytesTodayByIP(ctx context.Context, ip string, since time.Time) (int64, error) {
	var up, down sql.NullInt64
	err := s.Reader.QueryRowContext(ctx, `select
		(select coalesce(sum(p.size),0)
		   from upload_parts p
		   join upload_sessions us on us.id = p.sid
		   join shares sh on sh.id = us.share_id
		  where sh.created_ip = ? and p.rowid in (
		    select max(rowid) from upload_parts group by sid, part_number)),
		(select coalesce(sum(bytes),0) from share_events where ip = ?
		   and event in ('finalised','downloaded') and ts >= ?)`,
		ip, ip, since.Unix()).Scan(&up, &down)
	if err != nil {
		return 0, err
	}
	return up.Int64 + down.Int64, nil
}
