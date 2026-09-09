package tls

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
)

const (
	tls12ClientMsg = "GET /secret HTTP/1.1\r\nHost: t.local\r\n\r\n"
	tls12ServerMsg = "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nsecret-body"
)

// captureTLS12 performs a loopback TLS 1.2 handshake, exchanges known
// application data, and returns the raw wire bytes both directions plus the
// client keylog.
func captureTLS12(t *testing.T, suite uint16) (c2s, s2c, keylog []byte) {
	t.Helper()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tls12.local"},
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
			CipherSuites: []uint16{suite},
		})
		if s.Handshake() != nil {
			return
		}
		buf := make([]byte, 512)
		s.Read(buf)
		s.Write([]byte(tls12ServerMsg))
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
		CipherSuites:       []uint16{suite},
		KeyLogWriter:       &klBuf,
	})
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	client.Write([]byte(tls12ClientMsg))
	buf := make([]byte, 512)
	client.Read(buf)
	time.Sleep(50 * time.Millisecond)
	client.Close()
	raw.Close()
	wg.Wait()

	return rec.writes.Bytes(), rec.reads.Bytes(), klBuf.Bytes()
}

func serverHelloInfo(t *testing.T, s2c []byte) (random []byte, cipherSuite uint16) {
	t.Helper()
	recs, _, err := ParseRecords(s2c)
	if err != nil || len(recs) == 0 {
		t.Fatalf("parse server records: %v", err)
	}
	msgs, _ := ParseHandshakeMessages(recs[0].Payload)
	if len(msgs) == 0 || msgs[0].Type != HandshakeServerHello {
		t.Fatal("no ServerHello")
	}
	sh, err := ParseServerHello(msgs[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	return sh.Random, sh.CipherSuite
}

func TestDecryptTLS12(t *testing.T) {
	suites := map[string]uint16{
		"ECDHE_ECDSA_AES128_GCM": 0xc02b,
		"ECDHE_ECDSA_AES256_GCM": 0xc02c,
		"ECDHE_ECDSA_CHACHA20":   0xcca9,
	}
	for name, suite := range suites {
		t.Run(name, func(t *testing.T) {
			c2s, s2c, keylog := captureTLS12(t, suite)
			kl, err := ParseKeyLog(bytes.NewReader(keylog))
			if err != nil {
				t.Fatal(err)
			}
			if kl.Len() == 0 {
				t.Fatal("empty keylog")
			}
			clientRandom := clientRandomFrom(t, c2s)
			serverRandom, negotiated := serverHelloInfo(t, s2c)

			clientApp, serverApp, err := DecryptTLS12(c2s, s2c, clientRandom, serverRandom, negotiated, kl)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !strings.Contains(string(clientApp), tls12ClientMsg) {
				t.Errorf("client app data not recovered; got %q", clientApp)
			}
			if !strings.Contains(string(serverApp), tls12ServerMsg) {
				t.Errorf("server app data not recovered; got %q", serverApp)
			}
		})
	}
}

func TestDecryptTLS12WrongKeys(t *testing.T) {
	c2s, s2c, _ := captureTLS12(t, 0xc02b)
	clientRandom := clientRandomFrom(t, c2s)
	serverRandom, negotiated := serverHelloInfo(t, s2c)

	empty, _ := ParseKeyLog(bytes.NewReader(nil))
	if _, _, err := DecryptTLS12(c2s, s2c, clientRandom, serverRandom, negotiated, empty); err == nil {
		t.Fatal("expected missing-secret error")
	}
}
