package pcapint

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/session"
	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/tls"
)

func generateTestCertDER(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return der
}

// ---------------------------------------------------------------------------
// ToCertStore()
// ---------------------------------------------------------------------------

func TestToCertStore_NilSessions(t *testing.T) {
	store := ToCertStore(nil)
	if store == nil {
		t.Fatal("expected non-nil store")
	}
	if len(store.Containers) != 0 {
		t.Errorf("expected 0 containers, got %d", len(store.Containers))
	}
}

func TestToCertStore_EmptySessions(t *testing.T) {
	store := ToCertStore([]*session.Session{})
	if store == nil {
		t.Fatal("expected non-nil store")
	}
	if len(store.Containers) != 0 {
		t.Errorf("expected 0 containers, got %d", len(store.Containers))
	}
}

func TestToCertStore_SessionNoCertificates(t *testing.T) {
	sessions := []*session.Session{
		{
			ClientAddr: "10.0.0.1:12345",
			ServerAddr: "10.0.0.2:443",
			ClientHello: &tls.ClientHelloMsg{SNI: "example.com"},
		},
	}
	store := ToCertStore(sessions)
	if store == nil {
		t.Fatal("expected non-nil store")
	}
	if len(store.Containers) != 0 {
		t.Errorf("expected 0 containers for session without certs, got %d", len(store.Containers))
	}
}

func TestToCertStore_SessionWithCertificate(t *testing.T) {
	certDER := generateTestCertDER(t, "test.example.com")

	sessions := []*session.Session{
		{
			ClientAddr: "10.0.0.1:12345",
			ServerAddr: "10.0.0.2:443",
			ClientHello: &tls.ClientHelloMsg{SNI: "test.example.com"},
			Certificates: &tls.CertificateMsg{
				Certificates: [][]byte{certDER},
			},
		},
	}

	store := ToCertStore(sessions)
	if store == nil {
		t.Fatal("expected non-nil store")
	}
	if len(store.Containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(store.Containers))
	}

	container := store.Containers[0]
	if len(container.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(container.Items))
	}
	if container.Items[0].Certificate == nil {
		t.Fatal("expected non-nil certificate")
	}
	if container.Items[0].Certificate.Subject.CommonName != "test.example.com" {
		t.Errorf("CN = %q, want %q", container.Items[0].Certificate.Subject.CommonName, "test.example.com")
	}
}

func TestToCertStore_MultipleSessions(t *testing.T) {
	cert1 := generateTestCertDER(t, "server1.example.com")
	cert2 := generateTestCertDER(t, "server2.example.com")

	sessions := []*session.Session{
		{
			ClientAddr:   "10.0.0.1:11111",
			ServerAddr:   "10.0.0.2:443",
			Certificates: &tls.CertificateMsg{Certificates: [][]byte{cert1}},
		},
		{
			ClientAddr: "10.0.0.1:22222",
			ServerAddr: "10.0.0.3:443",
			// No certificates
		},
		{
			ClientAddr:   "10.0.0.1:33333",
			ServerAddr:   "10.0.0.4:443",
			Certificates: &tls.CertificateMsg{Certificates: [][]byte{cert2}},
		},
	}

	store := ToCertStore(sessions)
	if len(store.Containers) != 2 {
		t.Fatalf("expected 2 containers (skipping session without certs), got %d", len(store.Containers))
	}
}

func TestToCertStore_InvalidCertDER(t *testing.T) {
	sessions := []*session.Session{
		{
			ClientAddr: "10.0.0.1:12345",
			ServerAddr: "10.0.0.2:443",
			Certificates: &tls.CertificateMsg{
				Certificates: [][]byte{[]byte("not-a-valid-certificate")},
			},
		},
	}

	store := ToCertStore(sessions)
	// Invalid cert DER should be skipped, no container added since no valid items
	if len(store.Containers) != 0 {
		t.Errorf("expected 0 containers for invalid cert, got %d", len(store.Containers))
	}
}
