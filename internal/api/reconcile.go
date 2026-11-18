package api

import (
	"context"
	"errors"
	"time"

	"github.com/dreamfast/dreamshare/internal/mailer"
	"github.com/dreamfast/dreamshare/internal/storage/b2"
)

// RunReconciler drives the background loop until the context is cancelled.
// It is the only writer of expired and wiped states besides requests.
func (s *Server) RunReconciler(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.ReconcileOnce(ctx); err != nil {
				s.log.Error("reconcile", "err", err)
			}
		}
	}
}

// ReconcileOnce is one pass: expire, delete versions, wipe delivered,
// tombstone sweep, drain the notification outbox.
func (s *Server) ReconcileOnce(ctx context.Context) error {
	ids, err := s.store.ExpireDue(ctx, time.Now())
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := s.store.InsertEvent(ctx, id, "expired", "", "", "", 0); err != nil {
			s.log.Error("event", "err", err)
		}
	}

	if err := s.deleteTerminalVersions(ctx); err != nil {
		return err
	}
	if err := s.abortStaleUploads(ctx); err != nil {
		return err
	}

	swept, err := s.store.SweepTombstones(ctx, time.Now().Add(-time.Duration(s.cfg.Limits.TombstoneHours)*time.Hour))
	if err != nil {
		return err
	}
	if swept > 0 {
		s.log.Info("tombstone sweep", "rows", swept)
	}

	// expired auto blocks die here, the kill switch query filters them
	// live but without this the table grows forever and every request
	// scans it
	if _, err := s.store.Writer.ExecContext(ctx,
		"delete from admin_ip_blocks where expires_at is not null and expires_at < ?",
		time.Now().Unix()); err != nil {
		s.log.Error("block sweep", "err", err)
	}

	if err := s.DrainOutbox(ctx); err != nil {
		s.log.Error("outbox", "err", err)
	}
	return nil
}

func (s *Server) deleteTerminalVersions(ctx context.Context) error {
	pending, err := s.store.TerminalSharesForVersionDelete(ctx)
	if err != nil {
		return err
	}
	for shareID, refs := range pending {
		// one stuck delete must not starve expiry, tombstones and the outbox
		// for every other share, the next pass retries what failed
		failed := false
		for _, ref := range refs {
			if err := s.objects.DeleteVersion(ctx, ref.Key, ref.FileID); err != nil && !errors.Is(err, b2.ErrNotFound) {
				s.log.Error("delete version", "share", shareID, "err", err)
				failed = true
			}
		}
		if failed {
			continue
		}
		if err := s.store.MarkVersionsDeleted(ctx, shareID, refs); err != nil {
			return err
		}
		s.log.Info("versions deleted", "share", shareID, "files", len(refs))
	}
	return nil
}

// abortStaleUploads cancels multipart uploads whose sessions outlived their
// ttl, abandoned parts bill forever otherwise.
func (s *Server) abortStaleUploads(ctx context.Context) error {
	stale, err := s.store.StaleUploads(ctx, time.Now())
	if err != nil {
		return err
	}
	for _, sess := range stale {
		if sess.UploadID != "" {
			if err := s.objects.AbortUpload(ctx, sess.ObjectKey, sess.UploadID); err != nil && !errors.Is(err, b2.ErrNotFound) {
				s.log.Error("abort upload", "err", err)
				continue
			}
		}
		if err := s.store.CloseSession(ctx, sess.ID); err != nil {
			s.log.Error("close session", "err", err)
		}
	}
	return nil
}

// wipeAsync is the immediacy path for ack and revoke. The reconciler is the
// backstop if this fails. It outlives the request on purpose, so it carries
// its own bounded context.
func (s *Server) wipeAsync(base context.Context, shareID string) {
	go func() {
		// keep the request's values, drop its cancellation, the wipe must
		// finish even if the client hangs up
		ctx, cancel := context.WithTimeout(context.WithoutCancel(base), 2*time.Minute)
		defer cancel()
		if err := s.deleteTerminalVersions(ctx); err != nil {
			s.log.Error("wipe", "share", shareID, "err", err)
		}
	}()
}

// DrainOutbox sends due notifications. The mail body is plain text, no link,
// no key.
func (s *Server) DrainOutbox(ctx context.Context) error {
	for {
		id, shareID, to, ok, err := s.store.NotifyDue(ctx)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		if to == "" {
			// address already blanked, treat as sent
			if err := s.store.NotifySent(ctx, id); err != nil {
				return err
			}
			continue
		}
		if err := s.sendMail(ctx, to, shareID); err != nil {
			s.log.Warn("notify send failed", "err", err)
			if err := s.store.NotifyFailed(ctx, id, err.Error()); err != nil {
				return err
			}
			return nil
		}
		if err := s.store.NotifySent(ctx, id); err != nil {
			return err
		}
	}
}

func (s *Server) sendMail(ctx context.Context, to, shareID string) error {
	if s.mailer == nil {
		return errors.New("no mailer configured")
	}
	subject, text, html := mailer.DownloadNotification(shareID)
	return s.mailer.Send(ctx, to, subject, text, html)
}

// sender is the seam for SMTP2GO.
type sender interface {
	Send(ctx context.Context, to, subject, text, html string) error
}

// SetMailer wires the SMTP2GO sender.
func (s *Server) SetMailer(m sender) { s.mailer = m }
