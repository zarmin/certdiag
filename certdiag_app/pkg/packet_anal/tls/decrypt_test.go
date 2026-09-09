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
	"sync"
	"testing"
	"time"
)

// recordingConn tees the raw (encrypted) wire bytes in each direction so a test
// can replay what a passive pcap observer would see.
type recordingConn struct {
	net.Conn
	reads  *bytes.Buffer // bytes read by this side = peer -> this side
	writes *bytes.Buffer // bytes written by this side = this side -> peer
	mu     sync.Mutex
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

// captureTLS13 performs a real loopback TLS 1.3 handshake, capturing the raw
// wire bytes in both directions plus the client's SSLKEYLOGFILE. Returns the
// client->server bytes, server->client bytes, keylog contents, and the server
// leaf cert DER.
func captureTLS13(t *testing.T, forceSuite uint16) (c2s, s2c, keylog, certDER []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "decrypt-test.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"decrypt-test.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certDER = der
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
		scfg := &stdtls.Config{
			Certificates: []stdtls.Certificate{serverCert},
			MinVersion:   stdtls.VersionTLS13,
			MaxVersion:   stdtls.VersionTLS13,
		}
		s := stdtls.Server(conn, scfg)
		if err := s.Handshake(); err != nil {
			return
		}
		// Give the client time to read the handshake before teardown.
		time.Sleep(50 * time.Millisecond)
		s.Close()
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordingConn{Conn: raw, reads: &bytes.Buffer{}, writes: &bytes.Buffer{}}

	var keylogBuf bytes.Buffer
	ccfg := &stdtls.Config{
		InsecureSkipVerify: true,
		MinVersion:         stdtls.VersionTLS13,
		MaxVersion:         stdtls.VersionTLS13,
		KeyLogWriter:       &keylogBuf,
	}
	if forceSuite != 0 {
		ccfg.CipherSuites = []uint16{forceSuite}
	}
	client := stdtls.Client(rec, ccfg)
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	client.Close()
	raw.Close()
	wg.Wait()

	return rec.writes.Bytes(), rec.reads.Bytes(), keylogBuf.Bytes(), certDER
}

func clientRandomFrom(t *testing.T, c2s []byte) []byte {
	t.Helper()
	recs, _, err := ParseRecords(c2s)
	if err != nil || len(recs) == 0 {
		t.Fatalf("parse client records: %v", err)
	}
	msgs, _ := ParseHandshakeMessages(recs[0].Payload)
	if len(msgs) == 0 || msgs[0].Type != HandshakeClientHello {
		t.Fatal("no ClientHello in client->server bytes")
	}
	ch, err := ParseClientHello(msgs[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	return ch.Random
}

func cipherSuiteFrom(t *testing.T, s2c []byte) uint16 {
	t.Helper()
	recs, _, err := ParseRecords(s2c)
	if err != nil || len(recs) == 0 {
		t.Fatalf("parse server records: %v", err)
	}
	msgs, _ := ParseHandshakeMessages(recs[0].Payload)
	if len(msgs) == 0 || msgs[0].Type != HandshakeServerHello {
		t.Fatal("no ServerHello in server->client bytes")
	}
	sh, err := ParseServerHello(msgs[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	return sh.CipherSuite
}

func TestDecryptServerHandshake13(t *testing.T) {
	suites := map[string]uint16{
		"AES_128_GCM_SHA256":       0x1301,
		"AES_256_GCM_SHA384":       0x1302,
		"CHACHA20_POLY1305_SHA256": 0x1303,
	}
	for name, suite := range suites {
		t.Run(name, func(t *testing.T) {
			c2s, s2c, keylog, certDER := captureTLS13(t, suite)

			kl, err := ParseKeyLog(bytes.NewReader(keylog))
			if err != nil {
				t.Fatal(err)
			}
			if kl.Len() == 0 {
				t.Fatal("keylog is empty; TLS 1.3 KeyLogWriter produced nothing")
			}

			clientRandom := clientRandomFrom(t, c2s)
			negotiated := cipherSuiteFrom(t, s2c)

			handshake, err := DecryptServerHandshake13(s2c, clientRandom, negotiated, kl)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}

			msgs, _ := ParseHandshakeMessages(handshake)
			var certMsg *CertificateMsg
			for _, m := range msgs {
				if m.Type == HandshakeCertificate {
					certMsg, err = ParseCertificateTLS13(m.Payload)
					if err != nil {
						t.Fatalf("parse 1.3 cert: %v", err)
					}
					break
				}
			}
			if certMsg == nil || len(certMsg.Certificates) == 0 {
				t.Fatal("no Certificate message recovered from decrypted handshake")
			}
			if !bytes.Equal(certMsg.Certificates[0], certDER) {
				t.Fatal("decrypted leaf certificate does not match the served cert")
			}
			// Confirm it is a parseable X.509 cert.
			if _, err := x509.ParseCertificate(certMsg.Certificates[0]); err != nil {
				t.Fatalf("recovered cert not parseable: %v", err)
			}
		})
	}
}

func TestDecryptServerHandshake13WrongKeys(t *testing.T) {
	c2s, s2c, _, _ := captureTLS13(t, 0x1301)
	clientRandom := clientRandomFrom(t, c2s)
	negotiated := cipherSuiteFrom(t, s2c)

	// A keylog with the right client random but a bogus secret must fail cleanly.
	bogus := "SERVER_HANDSHAKE_TRAFFIC_SECRET " +
		hexString(clientRandom) + " " +
		"00000000000000000000000000000000000000000000000000000000000000\n"
	kl, _ := ParseKeyLog(bytes.NewReader([]byte(bogus)))
	if _, err := DecryptServerHandshake13(s2c, clientRandom, negotiated, kl); err == nil {
		t.Fatal("expected decryption failure with wrong secret")
	}

	// An empty keylog must report the missing-secret error.
	empty, _ := ParseKeyLog(bytes.NewReader(nil))
	if _, err := DecryptServerHandshake13(s2c, clientRandom, negotiated, empty); err == nil {
		t.Fatal("expected missing-secret error with empty keylog")
	}
}

func hexString(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0x0f]
	}
	return string(out)
}
