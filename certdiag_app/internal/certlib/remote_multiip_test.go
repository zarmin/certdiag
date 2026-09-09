package certlib

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// Fix (A): TotalDuration must be measured from this IP's own TCPStart plus the
// one-time DNS duration, not from a shared DNSStart that already includes the
// time spent on earlier IPs.
func TestDialSingleIPPerIPTotalDuration(t *testing.T) {
	listener, _, port := startTestTLSServer(t)
	defer listener.Close()

	target := RemoteTarget{Host: "127.0.0.1", Port: port, IsIP: true}
	opts := TLSDialOptions{Timeout: 5 * time.Second}

	// Simulate a shared DNS timestamp from long ago plus 5s already spent on
	// earlier IPs in the loop.
	dnsTiming := ConnectionTiming{
		DNSStart:    time.Now().Add(-5 * time.Second),
		DNSDone:     time.Now().Add(-5*time.Second + 2*time.Millisecond),
		DNSDuration: 2 * time.Millisecond,
	}

	fr, err := dialSingleIP(context.Background(), target, "127.0.0.1", opts, dnsTiming)
	if err != nil {
		t.Fatalf("dialSingleIP error: %v", err)
	}
	if fr.Error != nil {
		t.Fatalf("FetchResult.Error: %v", fr.Error)
	}

	total := fr.TLSInfo.Timing.TotalDuration
	if total <= 0 {
		t.Fatalf("TotalDuration should be positive, got %v", total)
	}
	if total > time.Second {
		t.Errorf("TotalDuration inflated by shared DNSStart: got %v, want < 1s", total)
	}

	if total < fr.TLSInfo.Timing.TCPDuration+fr.TLSInfo.Timing.TLSDuration {
		t.Errorf("TotalDuration %v should be at least TCP+TLS", total)
	}
}

// Fix (A)+(B): with two IPs (dual-stack localhost) each result's TotalDuration
// must reflect its own attempt (not cumulative), and each IP gets its own
// timeout budget so both succeed. Best-effort: skipped when ::1 cannot be bound
// on the shared port or localhost does not resolve to two addresses.
func TestDialTLSMultiIPPerIPIndependent(t *testing.T) {
	tlsCert := newDualStackCert(t)
	config := &tls.Config{Certificates: []tls.Certificate{tlsCert}}

	v4, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	defer v4.Close()
	serveTLSAccept(v4)

	_, portStr, _ := net.SplitHostPort(v4.Addr().String())
	v6, err := tls.Listen("tcp", net.JoinHostPort("::1", portStr), config)
	if err != nil {
		t.Skipf("cannot bind ::1 on port %s: %v", portStr, err)
	}
	defer v6.Close()
	serveTLSAccept(v6)

	ips, err := net.DefaultResolver.LookupHost(context.Background(), "localhost")
	if err != nil {
		t.Skipf("localhost lookup failed: %v", err)
	}
	if !containsBoth(ips, "127.0.0.1", "::1") {
		t.Skipf("localhost does not resolve to both 127.0.0.1 and ::1: %v", ips)
	}

	port, _ := net.LookupPort("tcp", portStr)
	target := RemoteTarget{Host: "localhost", Port: port, SNI: "localhost"}
	res, err := DialTLSMultiIP(target, TLSDialOptions{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("DialTLSMultiIP error: %v", err)
	}
	if len(res.Results) < 2 {
		t.Fatalf("expected at least 2 results, got %d", len(res.Results))
	}

	for i, r := range res.Results {
		if r.Error != nil {
			t.Errorf("result %d error: %v", i, r.Error)
			continue
		}
		total := r.TLSInfo.Timing.TotalDuration
		if total <= 0 || total > 2*time.Second {
			t.Errorf("result %d TotalDuration not independent/per-IP: %v", i, total)
		}
	}

	// Both listeners serve the same cert, so the two chains are identical.
	if !res.AllIdentical {
		t.Error("two successful identical chains should report AllIdentical=true")
	}
}

func newDualStackCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "dualstack.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func serveTLSAccept(listener net.Listener) {
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if tlsConn, ok := conn.(*tls.Conn); ok {
				tlsConn.Handshake()
			}
			conn.Close()
		}
	}()
}

func containsBoth(list []string, a, b string) bool {
	var hasA, hasB bool
	for _, s := range list {
		if s == a {
			hasA = true
		}
		if s == b {
			hasB = true
		}
	}
	return hasA && hasB
}
