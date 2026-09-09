package certlib

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func startTLS13Server(t *testing.T, cert tls.Certificate) RemoteTarget {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
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

func TestProbeTLS13CiphersOmitsCCM(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	cert := mustSelfSignedTLSCert(t, key)

	target := startTLS13Server(t, cert)

	results := probeTLS13Ciphers(context.Background(), target, StarttlsNone, 5*time.Second)

	seen := map[uint16]bool{}
	for _, r := range results {
		seen[r.CipherSuite] = true
	}

	for _, ccm := range []uint16{0x1304, 0x1305} {
		if seen[ccm] {
			t.Errorf("probeTLS13Ciphers reported CCM suite %#04x, which utls cannot negotiate (false negative)", ccm)
		}
	}

	for _, want := range []uint16{0x1301, 0x1302, 0x1303} {
		if !seen[want] {
			t.Errorf("probeTLS13Ciphers missing expected TLS 1.3 suite %#04x", want)
		}
	}
}
