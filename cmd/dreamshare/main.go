// Wiring only: fail closed config, the store, object storage, the SPA
// bundle, the api server and the reconciler loop.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dreamfast/dreamshare/internal/adminauth"
	"github.com/dreamfast/dreamshare/internal/api"
	"github.com/dreamfast/dreamshare/internal/config"
	"github.com/dreamfast/dreamshare/internal/mailer"
	b2 "github.com/dreamfast/dreamshare/internal/storage/b2"
	"github.com/dreamfast/dreamshare/internal/storage/b2/fake"
	b2minio "github.com/dreamfast/dreamshare/internal/storage/b2/minio"
	"github.com/dreamfast/dreamshare/internal/storage/b2/native"
	"github.com/dreamfast/dreamshare/internal/storage/sqlite"
	"github.com/dreamfast/dreamshare/internal/token"
	"github.com/dreamfast/dreamshare/internal/webdist"
)

var adminPasswordFlag = flag.Bool("set-admin-password", false, "read a new admin password from stdin, hash it, store it, invalidate sessions")

func flagSetAdminPassword() bool { return *adminPasswordFlag }

func runSetAdminPassword(auth *adminauth.Service) error {
	pw, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	hash, err := adminauth.HashPassword(strings.TrimSpace(string(pw)))
	if err != nil {
		return err
	}
	email := os.Getenv("ADMIN_EMAIL")
	if email == "" {
		return errors.New("ADMIN_EMAIL required with -set-admin-password")
	}
	if err := auth.SetPassword(context.Background(), email, hash); err != nil {
		return err
	}
	fmt.Println("admin password updated, sessions invalidated")
	return nil
}

func main() {
	flag.Parse()
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(log)

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}

	store, err := sqlite.Open(cfg.SQLitePath)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	var objects b2.Store
	if cfg.Prod || os.Getenv("DREAMSHARE_FAKE_STORAGE") != "1" {
		nat, nerr := native.New(ctx, cfg.B2.KeyID, cfg.B2.AppKey)
		if nerr != nil {
			return fmt.Errorf("b2 authorise: %w", nerr)
		}
		secure := true
		endpoint := cfg.B2.Endpoint
		endpoint = strings.TrimPrefix(endpoint, "https://")
		endpoint = strings.TrimPrefix(endpoint, "http://")
		mc, merr := b2minio.New(ctx, b2minio.Config{
			Endpoint: endpoint,
			Region:   cfg.B2.Region,
			Bucket:   cfg.B2.Bucket,
			KeyID:    cfg.B2.KeyID,
			AppKey:   cfg.B2.AppKey,
			Secure:   &secure,
			Deleter:  nat,
		})
		if merr != nil {
			return fmt.Errorf("b2 s3 client: %w", merr)
		}
		objects = mc
	} else {
		// dev and tests only, never reachable in prod because the branch
		// above takes prod unconditionally
		log.Warn("object storage is the in memory fake, nothing persists")
		objects = fake.New()
	}

	server := api.NewServer(cfg, store, objects, log)

	// the staff area: allowlist in front, one admin user. The password hash
	// arrives via the operator shell with -set-admin-password, never env.
	var allow *adminauth.Allowlist
	if cfg.Admin.AllowlistOff {
		// the shell recovery hatch: the allowlist is genuinely off, this is
		// the one documented operator escape and it logs loudly
		log.Warn("admin allowlist is DISABLED, the login is protected by password only")
		allow = adminauth.AllowAll()
	} else if len(cfg.Admin.Allowlist) > 0 {
		allow = adminauth.NewAllowlist(cfg.Admin.Allowlist)
	}
	if allow != nil {
		auth := adminauth.NewService(store, adminauth.LockoutConfig{
			Attempts: cfg.Admin.LockoutAttempts,
			LockMins: cfg.Admin.LockoutMinutes,
		}, cfg.Admin.SessionIdleMins, cfg.Admin.SessionAbsMins)
		if k := os.Getenv("ADMIN_ENC_KEY"); k != "" {
			if err := auth.SetSealKey([]byte(k)); err != nil {
				slog.Error("admin seal key", "err", err)
				return err
			}
		}
		server.SetAdmin(auth, allow)
		if flagSetAdminPassword() {
			return runSetAdminPassword(auth)
		}
		if cfg.Admin.Email != "" {
			id, err := token.NewMint(22)
			if err != nil {
				return err
			}
			// bootstrap only when the table is empty, the real password is
			// set from the shell in prod
			_ = auth.EnsureAdmin(ctx, id, cfg.Admin.Email, "unset")
		}
	} else {
		log.Warn("admin area disabled, no allowlist configured")
	}

	if index, err := webdist.FS().Open("index.html"); err == nil {
		_ = index.Close()
		api.SetSPA(webdist.FS())
	} else {
		log.Warn("no embedded spa bundle, serving api only")
	}

	// notifications only send once a real mailer exists, dev may run
	// without it and the outbox simply records the failure
	if cfg.SMTP.Host != "" {
		server.SetMailer(&mailer.SMTP{
			Host:     cfg.SMTP.Host,
			Port:     cfg.SMTP.Port,
			User:     cfg.SMTP.User,
			Password: cfg.SMTP.Password,
			From:     cfg.SMTP.From,
		})
		log.Info("smtp mailer wired", "host", cfg.SMTP.Host, "port", cfg.SMTP.Port)
	} else {
		log.Warn("smtp mailer not configured, download notifications will fail")
	}

	reconcileCtx, reconcileStop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer reconcileStop()
	go server.RunReconciler(reconcileCtx, time.Minute)

	srv := &http.Server{
		Addr:              cfg.ListenOn,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    32 << 10,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case sig := <-reconcileCtx.Done():
		log.Info("shutting down", "signal", sig)
		serveCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		// close after the listeners drain so in flight downloads finish
		return errors.Join(srv.Shutdown(serveCtx), store.Close())
	}
}
