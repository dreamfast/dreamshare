// Package mailer sends the download notification through SMTP2GO.
// stdlib only: Dial, STARTTLS, plain auth, one message per call.
package mailer

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/smtp"
	"strconv"
	"time"
)

type SMTP struct {
	Host     string
	Port     int
	User     string
	Password string
	From     string
	// RootCAs nil means the system pool, tests inject their own signer
	RootCAs *x509.CertPool
}

// Send delivers one mail as multipart alternative, html and text carry
// the same words. The outbox owns retries, this call is a single attempt
// that either lands or reports why it did not.
func (m *SMTP) Send(ctx context.Context, to, subject, text, html string) error {
	addr := net.JoinHostPort(m.Host, strconv.Itoa(m.Port))
	type result struct {
		err error
	}
	done := make(chan result, 1)
	go func() {
		done <- result{err: m.deliver(addr, to, subject, text, html)}
	}()
	select {
	case r := <-done:
		return r.err
	case <-ctx.Done():
		return fmt.Errorf("smtp send cancelled: %w", ctx.Err())
	}
}

func (m *SMTP) deliver(addr, to, subject, text, html string) error {
	c, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	defer func() { _ = c.Close() }()

	// credentials never go out before the channel is encrypted
	tlsConf := &tls.Config{ServerName: m.Host}
	if m.RootCAs != nil {
		tlsConf.RootCAs = m.RootCAs
	}
	if err := c.StartTLS(tlsConf); err != nil {
		return fmt.Errorf("smtp starttls: %w", err)
	}
	auth := smtp.PlainAuth("", m.User, m.Password, m.Host)
	if err := c.Auth(auth); err != nil {
		return fmt.Errorf("smtp auth: %w", err)
	}
	if err := c.Mail(m.From); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("smtp rcpt: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if err := writeMultipart(w, m.From, to, subject, text, html); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp close data: %w", err)
	}
	return c.Quit()
}

// writeMultipart assembles the rfc 2046 alternative envelope so clients
// that refuse html still read the text twin.
func writeMultipart(w io.Writer, from, to, subject, text, html string) error {
	boundary := make([]byte, 16)
	if _, err := rand.Read(boundary); err != nil {
		return err
	}
	b := fmt.Sprintf("=_dreamshare_%x", boundary)
	headers := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\n"+
			"MIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=\"%s\"\r\n",
		from, to, subject, time.Now().Format(time.RFC1123Z), b,
	)
	parts := fmt.Sprintf(
		"\r\n--%s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n"+
			"--%s\r\nContent-Type: text/html; charset=utf-8\r\n\r\n%s\r\n--%s--\r\n",
		b, text, b, html, b,
	)
	_, err := w.Write([]byte(headers + parts))
	return err
}

// ErrUnconfigured lets callers tell a missing config from a live failure.
var ErrUnconfigured = errors.New("smtp host is empty")
