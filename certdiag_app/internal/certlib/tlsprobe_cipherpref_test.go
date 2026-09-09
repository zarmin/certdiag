package certlib

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func mustSelfSignedTLSCert(t *testing.T, key crypto.Signer) tls.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func startTLS12Server(t *testing.T, cert tls.Certificate, ciphers []uint16, preferServer bool) RemoteTarget {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	config := &tls.Config{
		Certificates:             []tls.Certificate{cert},
		MinVersion:               tls.VersionTLS12,
		MaxVersion:               tls.VersionTLS12,
		CipherSuites:             ciphers,
		PreferServerCipherSuites: preferServer,
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			tlsConn := tls.Server(conn, config)
			go func() {
				_ = tlsConn.Handshake()
				tlsConn.Close()
			}()
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return RemoteTarget{Host: "127.0.0.1", Port: addr.Port, SNI: "localhost", IsIP: true}
}

func TestDetectCipherPreferenceECDSAServer(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	cert := mustSelfSignedTLSCert(t, key)

	target := startTLS12Server(t, cert, []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	}, true)

	got := detectCipherPreference(context.Background(), target, StarttlsNone, 5*time.Second)
	if got != "server" {
		t.Fatalf("detectCipherPreference on ECDSA server = %q, want %q", got, "server")
	}
}

func TestDetectCipherPreferenceRSAServer(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	cert := mustSelfSignedTLSCert(t, key)

	target := startTLS12Server(t, cert, []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	}, true)

	got := detectCipherPreference(context.Background(), target, StarttlsNone, 5*time.Second)
	if got != "server" {
		t.Fatalf("detectCipherPreference on RSA server = %q, want %q", got, "server")
	}
}

func TestDetectCipherPreferenceSingleCipherUnknown(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	cert := mustSelfSignedTLSCert(t, key)

	target := startTLS12Server(t, cert, []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	}, true)

	got := detectCipherPreference(context.Background(), target, StarttlsNone, 5*time.Second)
	if got != "unknown" {
		t.Fatalf("detectCipherPreference on single-cipher server = %q, want %q", got, "unknown")
	}
}
