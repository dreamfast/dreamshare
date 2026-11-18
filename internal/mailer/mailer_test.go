package mailer

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// a mini smtp server speaking just enough protocol for the client to
// finish: ehlo, starttls, auth plain, mail, rcpt, data, quit. it records
// what arrived so the test asserts on real wire behaviour.
type miniServer struct {
	listener net.Listener
	gotAuth  chan string
	gotMail  chan string
}

func newMiniServer(t *testing.T) (*miniServer, tls.Certificate) {
	t.Helper()
	cert := selfSigned(t, "127.0.0.1")
	pl, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	m := &miniServer{
		listener: pl,
		gotAuth:  make(chan string, 1),
		gotMail:  make(chan string, 1),
	}
	go m.serve(context.Background(), cert)
	t.Cleanup(func() { _ = pl.Close() })
	return m, cert
}

func (m *miniServer) serve(ctx context.Context, cert tls.Certificate) {
	conn, err := m.listener.Accept()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	say := func(s string) {
		if _, err := conn.Write([]byte(s + "\r\n")); err != nil {
			return
		}
	}
	// the greeting must go out before the client will speak, forgetting
	// this line deadlocks both sides
	say("220 mini esmtp")
	upgrade := func() net.Conn {
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil
		}
		return tlsConn
	}
	var mail strings.Builder
	inData := false
	scan := func() string {
		line, err := r.ReadString('\n')
		if err != nil {
			return ""
		}
		return strings.TrimRight(line, "\r\n")
	}
	for {
		line := scan()
		if line == "" && !inData {
			return
		}
		if inData {
			if line == "." {
				inData = false
				say("250 ok")
				select {
				case m.gotMail <- mail.String():
				default:
				}
				continue
			}
			mail.WriteString(line + "\n")
			continue
		}
		switch {
		case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
			// continuation lines carry the dash, only the last uses a space
			say("250-mini")
			say("250-AUTH PLAIN")
			say("250 STARTTLS")
		case strings.HasPrefix(line, "STARTTLS"):
			say("220 go ahead")
			if next := upgrade(); next != nil {
				conn = next
				r = bufio.NewReader(next)
			} else {
				return
			}
		case strings.HasPrefix(line, "AUTH PLAIN"):
			select {
			case m.gotAuth <- line:
			default:
			}
			say("235 ok")
		case strings.HasPrefix(line, "MAIL FROM"), strings.HasPrefix(line, "RCPT TO"):
			say("250 ok")
		case strings.HasPrefix(line, "DATA"):
			say("354 go")
			inData = true
		case strings.HasPrefix(line, "QUIT"):
			say("221 bye")
			return
		}
	}
}

func selfSigned(t *testing.T, ip string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: ip},
		IPAddresses:  []net.IP{net.ParseIP(ip)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestSMTPSendFullDialogue(t *testing.T) {
	srv, cert := newMiniServer(t)
	addr := srv.listener.Addr().String()
	host, portStr, _ := net.SplitHostPort(addr)
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	m := &SMTP{Host: host, Port: port, User: "user", Password: "passpass", From: "from@example.com"}
	// the self signed signer goes in as the trust anchor for this test
	pool := x509.NewCertPool()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pool.AddCert(leaf)
	m.RootCAs = pool

	subject, textBody, htmlBody := DownloadNotification("abcdef1234")
	if err := m.Send(context.Background(), "to@example.com", subject, textBody, htmlBody); err != nil {
		t.Fatalf("send: %v", err)
	}
	select {
	case a := <-srv.gotAuth:
		if !strings.Contains(a, "PLAIN") {
			t.Fatalf("auth was not plain: %q", a)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no auth seen")
	}
	select {
	case mailBody := <-srv.gotMail:
		for _, want := range []string{
			"multipart/alternative",
			"text/plain",
			"text/html",
			"from@example.com",
			"to@example.com",
			"Your share was downloaded",
			"was downloaded",
			"#5c99ee",
		} {
			if !strings.Contains(mailBody, want) {
				t.Fatalf("mail missing %q in %q", want, mailBody)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no mail seen")
	}
}

func TestSendContextCancel(t *testing.T) {
	// port 1 on loopback refuses or hangs, either way the context must win
	m := &SMTP{Host: "127.0.0.1", Port: 1, User: "u", Password: "pppppppp", From: "f@example.com"}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := m.Send(ctx, "t@example.com", "s", "p", "<i>h</i>"); err == nil {
		t.Fatal("expected cancel error")
	}
}

func TestDownloadNotification(t *testing.T) {
	subject, text, html := DownloadNotification("abcdef1234567890")
	if subject != "Your share was downloaded" {
		t.Fatalf("subject: %q", subject)
	}
	// both bodies name the shortened reference, neither carries a link
	for name, body := range map[string]string{"text": text, "html": html} {
		if !strings.Contains(body, "abcdef12") {
			t.Fatalf("%s missing short id", name)
		}
		if strings.Contains(body, "http://") || strings.Contains(body, "https://") {
			t.Fatalf("%s leaks a url", name)
		}
	}
	for _, want := range []string{"#5c99ee", "#344761", "#f8f9ff", "DreamShare"} {
		if !strings.Contains(html, want) {
			t.Fatalf("html missing %q", want)
		}
	}
}
