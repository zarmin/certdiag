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
	"strconv"
	"testing"
	"time"
)

// featureTestServer serves TLS on 127.0.0.1 with the given version bounds and
// returns the target to probe.
func featureTestServer(t *testing.T, minVersion, maxVersion uint16) (RemoteTarget, func()) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "feature.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"feature.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   minVersion,
		MaxVersion:   maxVersion,
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if tc, ok := c.(*tls.Conn); ok {
					tc.Handshake()
				}
				time.Sleep(50 * time.Millisecond)
				c.Close()
			}(c)
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return RemoteTarget{Host: "127.0.0.1", Port: port, SNI: "feature.test", IsIP: true}, func() { ln.Close() }
}

// TestProbeFeaturesAreMeasured guards H4: renegotiation_info and the
// compression method come from the ServerHello, and a TLS 1.3 server leaves
// renegotiation unanswered rather than defaulted.
func TestProbeFeaturesAreMeasured(t *testing.T) {
	t.Run("TLS 1.2 server sends renegotiation_info", func(t *testing.T) {
		target, stop := featureTestServer(t, tls.VersionTLS12, tls.VersionTLS12)
		defer stop()
		var result ProbeResult
		probeFeatures(context.Background(), target, StarttlsNone, 5*time.Second, &result)
		if result.FeaturesTLSVersion != tls.VersionTLS12 {
			t.Fatalf("feature connection negotiated %x, want TLS 1.2", result.FeaturesTLSVersion)
		}
		if result.SecureRenegotiation == nil || !*result.SecureRenegotiation {
			t.Errorf("Go's server always sends renegotiation_info; got %v", result.SecureRenegotiation)
		}
		if result.Compression == nil || *result.Compression {
			t.Errorf("compression must be measured as off; got %v", result.Compression)
		}
		if len(result.ALPNProtocols) != 1 || result.ALPNProtocols[0] != "h2" {
			t.Errorf("ALPN = %v, want [h2]", result.ALPNProtocols)
		}
	})

	t.Run("TLS 1.3 server leaves renegotiation unanswered", func(t *testing.T) {
		target, stop := featureTestServer(t, tls.VersionTLS13, tls.VersionTLS13)
		defer stop()
		var result ProbeResult
		probeFeatures(context.Background(), target, StarttlsNone, 5*time.Second, &result)
		if result.FeaturesTLSVersion != tls.VersionTLS13 {
			t.Fatalf("feature connection negotiated %x, want TLS 1.3", result.FeaturesTLSVersion)
		}
		if result.SecureRenegotiation != nil {
			t.Errorf("TLS 1.3 has no renegotiation; the field must stay nil, got %v", *result.SecureRenegotiation)
		}
		if result.Compression == nil || *result.Compression {
			t.Errorf("compression must be measured as off; got %v", result.Compression)
		}
	})

	t.Run("no connection means nothing measured", func(t *testing.T) {
		var result ProbeResult
		probeFeatures(context.Background(), RemoteTarget{Host: "127.0.0.1", Port: 1, IsIP: true}, StarttlsNone, time.Second, &result)
		if result.SecureRenegotiation != nil || result.Compression != nil {
			t.Error("a failed feature connection must leave both fields nil")
		}
	})
}

// TestALPNIsOfferedAndRecorded guards M1: the dialer offers what it was told,
// records the offer, and remote_no_alpn fires only on an unanswered offer.
func TestALPNIsOfferedAndRecorded(t *testing.T) {
	target, stop := featureTestServer(t, tls.VersionTLS12, tls.VersionTLS13)
	defer stop()

	withALPN, err := DialTLS(target, TLSDialOptions{Timeout: 5 * time.Second, ALPN: DefaultALPN})
	if err != nil {
		t.Fatal(err)
	}
	if withALPN.TLSInfo.NegotiatedProto != "h2" || len(withALPN.TLSInfo.ALPNOffered) != 2 {
		t.Errorf("offered DefaultALPN: negotiated %q, offered %v", withALPN.TLSInfo.NegotiatedProto, withALPN.TLSInfo.ALPNOffered)
	}

	without, err := DialTLS(target, TLSDialOptions{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if without.TLSInfo.NegotiatedProto != "" || len(without.TLSInfo.ALPNOffered) != 0 {
		t.Errorf("nothing offered: negotiated %q, offered %v", without.TLSInfo.NegotiatedProto, without.TLSInfo.ALPNOffered)
	}

	unanswered := RemoteCheckContext{Target: target, TLSInfo: TLSConnectionInfo{ALPNOffered: DefaultALPN}}
	if issues := checkNoALPN(unanswered, CheckOptions{}); len(issues) != 1 {
		t.Errorf("an unanswered offer must be reported, got %v", issues)
	}
	silent := RemoteCheckContext{Target: target, TLSInfo: TLSConnectionInfo{}}
	if issues := checkNoALPN(silent, CheckOptions{}); len(issues) != 0 {
		t.Errorf("no offer, no finding; got %v", issues)
	}

	// STARTTLS sessions never offer the HTTP identifiers
	cfg := buildTLSConfig(target, TLSDialOptions{ALPN: DefaultALPN, Starttls: StarttlsSMTP})
	if len(cfg.NextProtos) != 0 {
		t.Errorf("STARTTLS must not offer h2: %v", cfg.NextProtos)
	}
}
