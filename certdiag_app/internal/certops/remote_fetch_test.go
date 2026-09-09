package certops

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"
)

func startTestTLSServer(t *testing.T) (net.Listener, *x509.Certificate, int) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test-server.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"test-server.local", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			tlsConn, ok := conn.(*tls.Conn)
			if ok {
				tlsConn.Handshake()
			}
			conn.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return listener, cert, port
}

func TestFetchRemoteCertSingle(t *testing.T) {
	listener, serverCert, port := startTestTLSServer(t)
	defer listener.Close()

	target := "127.0.0.1:" + strconv.Itoa(port)

	result, err := FetchRemoteCert(FetchRemoteCertOptions{
		Targets: []string{target},
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("FetchRemoteCert error: %v", err)
	}

	if result.Summary.Total != 1 {
		t.Errorf("expected 1 total, got %d", result.Summary.Total)
	}
	if result.Summary.Succeeded != 1 {
		t.Errorf("expected 1 succeeded, got %d", result.Summary.Succeeded)
	}
	if result.Summary.Failed != 0 {
		t.Errorf("expected 0 failed, got %d", result.Summary.Failed)
	}

	if len(result.TargetResults) != 1 {
		t.Fatalf("expected 1 target result, got %d", len(result.TargetResults))
	}

	tr := result.TargetResults[0]
	if tr.Error != "" {
		t.Fatalf("unexpected target error: %s", tr.Error)
	}
	if tr.Connection == nil {
		t.Fatal("connection info should not be nil")
	}
	if tr.Connection.TLSVersion == "" {
		t.Error("TLS version should not be empty")
	}
	if tr.Connection.CipherSuite == "" {
		t.Error("cipher suite should not be empty")
	}

	if len(tr.Certs) == 0 {
		t.Fatal("expected at least one cert")
	}
	if tr.Certs[0].Role != "leaf" {
		t.Errorf("first cert role = %q, want %q", tr.Certs[0].Role, "leaf")
	}
	if tr.Certs[0].Cert.Certificate == nil {
		t.Error("cert item should have certificate")
	}
	if !tr.Certs[0].Cert.Certificate.Equal(serverCert) {
		t.Error("returned cert doesn't match server cert")
	}
}

func TestFetchRemoteCertMultiTarget(t *testing.T) {
	listener1, _, port1 := startTestTLSServer(t)
	defer listener1.Close()
	listener2, _, port2 := startTestTLSServer(t)
	defer listener2.Close()

	targets := []string{
		"127.0.0.1:" + strconv.Itoa(port1),
		"127.0.0.1:" + strconv.Itoa(port2),
	}

	result, err := FetchRemoteCert(FetchRemoteCertOptions{
		Targets:  targets,
		Timeout:  5 * time.Second,
		Parallel: 2,
	})
	if err != nil {
		t.Fatalf("FetchRemoteCert error: %v", err)
	}

	if result.Summary.Total != 2 {
		t.Errorf("expected 2 total, got %d", result.Summary.Total)
	}
	if result.Summary.Succeeded != 2 {
		t.Errorf("expected 2 succeeded, got %d", result.Summary.Succeeded)
	}

	for i, tr := range result.TargetResults {
		if tr.Error != "" {
			t.Errorf("target %d error: %s", i, tr.Error)
		}
		if len(tr.Certs) == 0 {
			t.Errorf("target %d: no certs", i)
		}
	}
}

func TestFetchRemoteCertBadTarget(t *testing.T) {
	result, err := FetchRemoteCert(FetchRemoteCertOptions{
		Targets: []string{"127.0.0.1:1"},
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("FetchRemoteCert error: %v", err)
	}

	if result.Summary.Failed != 1 {
		t.Errorf("expected 1 failed, got %d", result.Summary.Failed)
	}
	if result.TargetResults[0].Error == "" {
		t.Error("expected error for unreachable target")
	}
}

func TestFetchRemoteCertNoTargets(t *testing.T) {
	_, err := FetchRemoteCert(FetchRemoteCertOptions{})
	if err == nil {
		t.Error("expected error for no targets")
	}
}

func TestFetchRemoteCertInvalidTarget(t *testing.T) {
	result, err := FetchRemoteCert(FetchRemoteCertOptions{
		Targets: []string{""},
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("FetchRemoteCert error: %v", err)
	}

	if result.TargetResults[0].Error == "" {
		t.Error("expected error for empty target")
	}
}

func TestFetchRemoteCertExpiryWarn(t *testing.T) {
	listener, _, port := startTestTLSServer(t)
	defer listener.Close()

	target := "127.0.0.1:" + strconv.Itoa(port)

	// Test cert expires in 24h, warn at 30 days should trigger
	result, err := FetchRemoteCert(FetchRemoteCertOptions{
		Targets:    []string{target},
		Timeout:    5 * time.Second,
		ExpiryWarn: 30,
	})
	if err != nil {
		t.Fatalf("FetchRemoteCert error: %v", err)
	}

	tr := result.TargetResults[0]
	if tr.ExpiryWarn == nil {
		t.Fatal("expected expiry warn info")
	}
	if !tr.ExpiryWarn.HasWarning {
		t.Error("expected HasWarning to be true for cert expiring within 30 days")
	}
}

func TestCheckExpiry(t *testing.T) {
	t.Run("expired cert", func(t *testing.T) {
		cert := &x509.Certificate{
			Subject:  pkix.Name{CommonName: "expired"},
			NotAfter: time.Now().Add(-24 * time.Hour),
		}
		info := checkExpiry([]*x509.Certificate{cert}, 30)
		if !info.HasExpired {
			t.Error("expected HasExpired")
		}
		if len(info.ExpiringCerts) != 1 {
			t.Errorf("expected 1 expiring cert, got %d", len(info.ExpiringCerts))
		}
		if !info.ExpiringCerts[0].Expired {
			t.Error("cert should be marked expired")
		}
	})

	t.Run("expiring soon", func(t *testing.T) {
		cert := &x509.Certificate{
			Subject:  pkix.Name{CommonName: "expiring"},
			NotAfter: time.Now().Add(7 * 24 * time.Hour),
		}
		info := checkExpiry([]*x509.Certificate{cert}, 30)
		if info.HasExpired {
			t.Error("should not be expired")
		}
		if !info.HasWarning {
			t.Error("expected HasWarning")
		}
	})

	t.Run("not expiring", func(t *testing.T) {
		cert := &x509.Certificate{
			Subject:  pkix.Name{CommonName: "valid"},
			NotAfter: time.Now().Add(365 * 24 * time.Hour),
		}
		info := checkExpiry([]*x509.Certificate{cert}, 30)
		if info.HasExpired {
			t.Error("should not be expired")
		}
		if info.HasWarning {
			t.Error("should not have warning")
		}
	})
}

func TestIsSelfSigned(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	selfSigned := &x509.Certificate{
		SerialNumber:   serial,
		Subject:        pkix.Name{CommonName: "Test"},
		Issuer:         pkix.Name{CommonName: "Test"},
		SubjectKeyId:   []byte{1, 2, 3},
		AuthorityKeyId: []byte{1, 2, 3},
	}
	if !certlib.IsSelfSigned(selfSigned) {
		t.Error("should be self-signed")
	}

	_ = key // used above to satisfy vet

	caIssued := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Leaf"},
		Issuer:       pkix.Name{CommonName: "CA"},
	}
	if certlib.IsSelfSigned(caIssued) {
		t.Error("should not be self-signed")
	}
}
