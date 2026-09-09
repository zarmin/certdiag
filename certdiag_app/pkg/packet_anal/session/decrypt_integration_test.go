package session

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/tcp"
	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/tls"
)

type recordingConn struct {
	net.Conn
	reads, writes *bytes.Buffer
	mu            sync.Mutex
}

func (c *recordingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.mu.Lock()
		c.reads.Write(b[:n])
		c.mu.Unlock()
	}
	return n, err
}

func (c *recordingConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.writes.Write(b)
	c.mu.Unlock()
	return c.Conn.Write(b)
}

// captureTLS13Session runs a loopback TLS 1.3 handshake and returns the raw wire
// bytes each direction, the client keylog, and the server cert subject CN.
const tls13ServerMsg = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"

func captureTLS13Session(t *testing.T) (c2s, s2c, keylog []byte, cn string) {
	t.Helper()
	cn = "session-decrypt.local"

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{cn},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	serverCert := stdtls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		s := stdtls.Server(conn, &stdtls.Config{
			Certificates: []stdtls.Certificate{serverCert},
			MinVersion:   stdtls.VersionTLS13,
			MaxVersion:   stdtls.VersionTLS13,
		})
		if s.Handshake() == nil {
			s.Write([]byte(tls13ServerMsg))
			time.Sleep(50 * time.Millisecond)
		}
		s.Close()
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordingConn{Conn: raw, reads: &bytes.Buffer{}, writes: &bytes.Buffer{}}
	var klBuf bytes.Buffer
	client := stdtls.Client(rec, &stdtls.Config{
		InsecureSkipVerify: true,
		MinVersion:         stdtls.VersionTLS13,
		MaxVersion:         stdtls.VersionTLS13,
		KeyLogWriter:       &klBuf,
	})
	if err := client.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	buf := make([]byte, 256)
	client.Read(buf)
	time.Sleep(50 * time.Millisecond)
	client.Close()
	raw.Close()
	wg.Wait()

	return rec.writes.Bytes(), rec.reads.Bytes(), klBuf.Bytes(), cn
}

func trackerSession(t *testing.T, c2s, s2c []byte, kl *tls.KeyLog) *Session {
	t.Helper()
	conn := &tcp.Connection{
		ClientAddr: "127.0.0.1:12345",
		ServerAddr: "127.0.0.1:443",
		ClientData: c2s,
		ServerData: s2c,
		StartTime:  time.Now(),
		EndTime:    time.Now(),
	}
	tracker := &Tracker{KeyLog: kl}
	sessions := tracker.ProcessConnections([]*tcp.Connection{conn})
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	return sessions[0]
}

// captureTLS12Session runs a loopback TLS 1.2 handshake, exchanges a known
// application-data message from the server, and returns the wire bytes + keylog.
func captureTLS12Session(t *testing.T) (c2s, s2c, keylog []byte, serverMsg string) {
	t.Helper()
	serverMsg = "hello-from-tls12-server"

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tls12-session.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	serverCert := stdtls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		s := stdtls.Server(conn, &stdtls.Config{
			Certificates: []stdtls.Certificate{serverCert},
			MinVersion:   stdtls.VersionTLS12, MaxVersion: stdtls.VersionTLS12,
		})
		if s.Handshake() != nil {
			return
		}
		s.Write([]byte(serverMsg))
		time.Sleep(50 * time.Millisecond)
		s.Close()
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordingConn{Conn: raw, reads: &bytes.Buffer{}, writes: &bytes.Buffer{}}
	var klBuf bytes.Buffer
	client := stdtls.Client(rec, &stdtls.Config{
		InsecureSkipVerify: true,
		MinVersion:         stdtls.VersionTLS12, MaxVersion: stdtls.VersionTLS12,
		KeyLogWriter:       &klBuf,
	})
	if err := client.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	buf := make([]byte, 256)
	client.Read(buf)
	time.Sleep(50 * time.Millisecond)
	client.Close()
	raw.Close()
	wg.Wait()

	return rec.writes.Bytes(), rec.reads.Bytes(), klBuf.Bytes(), serverMsg
}

func TestTrackerTLS12Decryption(t *testing.T) {
	c2s, s2c, keylog, serverMsg := captureTLS12Session(t)
	kl, err := tls.ParseKeyLog(bytes.NewReader(keylog))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("with keylog decrypts app data", func(t *testing.T) {
		s := trackerSession(t, c2s, s2c, kl)
		if s.NegotiatedVersion == nil || *s.NegotiatedVersion != tls.VersionTLS12 {
			t.Fatalf("expected TLS 1.2, got %s", s.VersionString())
		}
		if !s.AppDataDecrypted {
			t.Fatalf("expected AppDataDecrypted; err=%q", s.DecryptError)
		}
		if !strings.Contains(string(s.DecryptedServerData), serverMsg) {
			t.Fatalf("server app data not recovered; got %q", s.DecryptedServerData)
		}
	})

	t.Run("without keylog leaves app data encrypted", func(t *testing.T) {
		s := trackerSession(t, c2s, s2c, nil)
		if s.AppDataDecrypted || len(s.DecryptedServerData) != 0 {
			t.Fatal("no keylog: must not decrypt app data")
		}
	})
}

func TestTrackerTLS13Decryption(t *testing.T) {
	c2s, s2c, keylog, cn := captureTLS13Session(t)
	kl, err := tls.ParseKeyLog(bytes.NewReader(keylog))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("with keylog extracts the cert", func(t *testing.T) {
		s := trackerSession(t, c2s, s2c, kl)
		if s.NegotiatedVersion == nil || *s.NegotiatedVersion != tls.VersionTLS13 {
			t.Fatalf("expected TLS 1.3, got %v", s.VersionString())
		}
		if !s.CertsDecrypted {
			t.Fatalf("expected CertsDecrypted; TLS13CertEncrypted=%v err=%q", s.TLS13CertEncrypted, s.DecryptError)
		}
		if s.Certificates == nil || len(s.Certificates.Certificates) == 0 {
			t.Fatal("no certificate extracted")
		}
		cert, err := x509.ParseCertificate(s.Certificates.Certificates[0])
		if err != nil {
			t.Fatal(err)
		}
		if cert.Subject.CommonName != cn {
			t.Fatalf("cert CN = %q, want %q", cert.Subject.CommonName, cn)
		}
		// TLS 1.3 application data is also decrypted (D2).
		if !s.AppDataDecrypted || !strings.Contains(string(s.DecryptedServerData), "HTTP/1.1 200 OK") {
			t.Fatalf("expected decrypted TLS 1.3 app data; got %q", s.DecryptedServerData)
		}
	})

	t.Run("without keylog reports encrypted (honest message)", func(t *testing.T) {
		s := trackerSession(t, c2s, s2c, nil)
		if s.Certificates != nil {
			t.Fatal("no keylog: must not extract a cert")
		}
		if !s.TLS13CertEncrypted {
			t.Fatal("no keylog: expected TLS13CertEncrypted flag")
		}
	})
}
