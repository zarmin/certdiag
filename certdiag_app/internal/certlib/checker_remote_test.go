package certlib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

func makeCAAndLeaf(t *testing.T, leafCN string, leafSANs []string) (*x509.Certificate, *x509.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	caTmpl := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "Local Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	leafTmpl := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: leafCN},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     leafSANs,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafDER)
	return caCert, leafCert
}

func makeRemoteTestCert(t *testing.T, cn string, sans []string, isCA bool) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		DNSNames:              sans,
		IsCA:                  isCA,
		BasicConstraintsValid: isCA,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	if isCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	return cert
}

func TestRunRemoteChecks_NoIssues(t *testing.T) {
	leaf := makeRemoteTestCert(t, "example.com", []string{"example.com"}, false)
	ctx := RemoteCheckContext{
		Target: RemoteTarget{Host: "example.com", Port: 443},
		TLSInfo: TLSConnectionInfo{
			Version:         tls.VersionTLS13,
			VersionName:     "TLS 1.3",
			CipherSuiteName: "TLS_AES_256_GCM_SHA384",
			ServerName:      "example.com",
			NegotiatedProto: "h2",
			OCSPStapled:     true,
		},
		Certificates: []*x509.Certificate{leaf},
	}

	result := RunRemoteChecks(ctx, CheckOptions{})
	// Should have no critical/warning issues (chain_untrusted and self_signed may fire)
	for _, issue := range result.Issues {
		if issue.CheckID == "remote_hostname_mismatch" {
			t.Errorf("unexpected hostname mismatch issue")
		}
		if issue.CheckID == "remote_weak_tls" {
			t.Errorf("unexpected weak TLS issue")
		}
	}
}

func TestCheckHostnameMismatch(t *testing.T) {
	leaf := makeRemoteTestCert(t, "other.com", []string{"other.com"}, false)
	ctx := RemoteCheckContext{
		Target: RemoteTarget{Host: "example.com", Port: 443},
		TLSInfo: TLSConnectionInfo{
			ServerName: "example.com",
		},
		Certificates: []*x509.Certificate{leaf},
	}

	issues := checkHostnameMismatch(ctx, CheckOptions{})
	if len(issues) == 0 {
		t.Fatal("expected hostname mismatch issue")
	}
	if issues[0].CheckID != "remote_hostname_mismatch" {
		t.Errorf("expected check_id remote_hostname_mismatch, got %s", issues[0].CheckID)
	}
	if issues[0].Severity != SeverityCritical {
		t.Errorf("expected critical severity")
	}
}

func TestCheckHostnameMismatch_Match(t *testing.T) {
	leaf := makeRemoteTestCert(t, "example.com", []string{"example.com"}, false)
	ctx := RemoteCheckContext{
		Target: RemoteTarget{Host: "example.com", Port: 443},
		TLSInfo: TLSConnectionInfo{
			ServerName: "example.com",
		},
		Certificates: []*x509.Certificate{leaf},
	}

	issues := checkHostnameMismatch(ctx, CheckOptions{})
	if len(issues) != 0 {
		t.Errorf("expected no issues, got %d", len(issues))
	}
}

func TestCheckWeakTLS(t *testing.T) {
	tests := []struct {
		name    string
		version uint16
		want    bool
	}{
		{"TLS 1.0", tls.VersionTLS10, true},
		{"TLS 1.1", tls.VersionTLS11, true},
		{"TLS 1.2", tls.VersionTLS12, false},
		{"TLS 1.3", tls.VersionTLS13, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := RemoteCheckContext{
				Target: RemoteTarget{Host: "example.com", Port: 443},
				TLSInfo: TLSConnectionInfo{
					Version:     tt.version,
					VersionName: TLSVersionName(tt.version),
				},
			}
			issues := checkWeakTLS(ctx, CheckOptions{})
			got := len(issues) > 0
			if got != tt.want {
				t.Errorf("checkWeakTLS version=%v: got issue=%v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestChainUntrusted_NotConflatedWithHostname(t *testing.T) {
	ca, leaf := makeCAAndLeaf(t, "correct.example.com", []string{"correct.example.com"})
	ctx := RemoteCheckContext{
		Target:       RemoteTarget{Host: "wrong.example.com", Port: 443},
		TLSInfo:      TLSConnectionInfo{ServerName: "wrong.example.com"},
		Certificates: []*x509.Certificate{leaf, ca},
		// An explicit, empty anchor pool: the verdict is "no path to a root we
		// trust", decided by certdiag rather than by the host's own verifier
		// (M30a option A).
		Roots: x509.NewCertPool(),
	}

	hostIssues := checkHostnameMismatch(ctx, CheckOptions{})
	if len(hostIssues) == 0 {
		t.Fatal("expected a distinct hostname mismatch issue")
	}
	if hostIssues[0].CheckID != "remote_hostname_mismatch" || hostIssues[0].Severity != SeverityCritical {
		t.Errorf("expected critical remote_hostname_mismatch, got %s/%s", hostIssues[0].CheckID, hostIssues[0].Severity)
	}

	trustIssues := checkChainUntrusted(ctx, CheckOptions{})
	if len(trustIssues) == 0 {
		t.Fatal("expected a trust failure for a locally-signed chain")
	}
	if trustIssues[0].CheckID != "remote_chain_untrusted" {
		t.Errorf("expected remote_chain_untrusted, got %s", trustIssues[0].CheckID)
	}
	msg := trustIssues[0].Message + " " + fmt.Sprint(trustIssues[0].Details["verify_error"])
	if strings.Contains(msg, "valid for") {
		t.Errorf("trust check must not conflate a hostname mismatch: %q", msg)
	}
}

func TestChainUntrusted_TrustFailureIndependentOfHostname(t *testing.T) {
	ca, leaf := makeCAAndLeaf(t, "host.example.com", []string{"host.example.com"})
	ctx := RemoteCheckContext{
		Target:       RemoteTarget{Host: "host.example.com", Port: 443},
		TLSInfo:      TLSConnectionInfo{ServerName: "host.example.com"},
		Certificates: []*x509.Certificate{leaf, ca},
		Roots:        x509.NewCertPool(),
	}

	if issues := checkHostnameMismatch(ctx, CheckOptions{}); len(issues) != 0 {
		t.Errorf("hostname matches, expected no hostname mismatch, got %d", len(issues))
	}

	trustIssues := checkChainUntrusted(ctx, CheckOptions{})
	if len(trustIssues) == 0 {
		t.Fatal("expected a trust failure for a locally-signed chain")
	}
	if trustIssues[0].CheckID != "remote_chain_untrusted" {
		t.Errorf("expected remote_chain_untrusted, got %s", trustIssues[0].CheckID)
	}
}

func TestCheckWeakCipher(t *testing.T) {
	tests := []struct {
		cipher string
		weak   bool
	}{
		{"TLS_RSA_WITH_RC4_128_SHA", true},
		{"TLS_RSA_WITH_3DES_EDE_CBC_SHA", true},
		{"TLS_RSA_WITH_NULL_SHA", true},
		{"TLS_AES_256_GCM_SHA384", false},
		{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", false},
	}

	for _, tt := range tests {
		t.Run(tt.cipher, func(t *testing.T) {
			ctx := RemoteCheckContext{
				Target: RemoteTarget{Host: "example.com", Port: 443},
				TLSInfo: TLSConnectionInfo{
					CipherSuiteName: tt.cipher,
				},
			}
			issues := checkWeakCipher(ctx, CheckOptions{})
			got := len(issues) > 0
			if got != tt.weak {
				t.Errorf("checkWeakCipher(%s): got=%v, want=%v", tt.cipher, got, tt.weak)
			}
		})
	}
}

func TestCheckNoOCSPStaple(t *testing.T) {
	ctx := RemoteCheckContext{
		Target:  RemoteTarget{Host: "example.com", Port: 443},
		TLSInfo: TLSConnectionInfo{OCSPStapled: false},
	}
	issues := checkNoOCSPStaple(ctx, CheckOptions{})
	if len(issues) == 0 {
		t.Error("expected no OCSP staple issue")
	}

	ctx.TLSInfo.OCSPStapled = true
	issues = checkNoOCSPStaple(ctx, CheckOptions{})
	if len(issues) != 0 {
		t.Error("expected no issue when OCSP is stapled")
	}
}

func TestCheckNoALPN(t *testing.T) {
	// The finding describes the server only when the client offered ALPN and
	// got nothing back; a connection that never offered says nothing.
	ctx := RemoteCheckContext{
		Target:  RemoteTarget{Host: "example.com", Port: 443},
		TLSInfo: TLSConnectionInfo{NegotiatedProto: "", ALPNOffered: DefaultALPN},
	}
	issues := checkNoALPN(ctx, CheckOptions{})
	if len(issues) == 0 {
		t.Error("expected no ALPN issue")
	}

	ctx.TLSInfo.NegotiatedProto = "h2"
	issues = checkNoALPN(ctx, CheckOptions{})
	if len(issues) != 0 {
		t.Error("expected no issue when ALPN negotiated")
	}
}

func TestCheckSelfSigned(t *testing.T) {
	selfSigned := makeRemoteTestCert(t, "self.example.com", []string{"self.example.com"}, false)
	ctx := RemoteCheckContext{
		Target:       RemoteTarget{Host: "self.example.com", Port: 443},
		Certificates: []*x509.Certificate{selfSigned},
	}
	issues := checkSelfSigned(ctx, CheckOptions{})
	if len(issues) == 0 {
		t.Error("expected self-signed issue")
	}
}

func TestCheckSelfSigned_CATrueLeaf(t *testing.T) {
	// openssl req -x509 produces a self-signed leaf with CA:TRUE
	selfSignedCA := makeRemoteTestCert(t, "self-ca.example.com", []string{"self-ca.example.com"}, true)
	ctx := RemoteCheckContext{
		Target:       RemoteTarget{Host: "self-ca.example.com", Port: 443},
		Certificates: []*x509.Certificate{selfSignedCA},
	}
	issues := checkSelfSigned(ctx, CheckOptions{})
	if len(issues) == 0 {
		t.Error("expected self-signed issue for CA:TRUE self-signed leaf")
	}
}

func TestCheckSelfSigned_CAIssuedNotFlagged(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	caTmpl := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "Issuing CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	leafTmpl := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     []string{"leaf.example.com"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	ctx := RemoteCheckContext{
		Target:       RemoteTarget{Host: "leaf.example.com", Port: 443},
		Certificates: []*x509.Certificate{leafCert},
	}
	issues := checkSelfSigned(ctx, CheckOptions{})
	if len(issues) != 0 {
		t.Errorf("CA-issued leaf must not be flagged self-signed, got %d issues", len(issues))
	}
}

func TestCheckRemoteChainIncomplete(t *testing.T) {
	// Leaf only, non-self-signed would need a different issuer
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	caSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	caTmpl := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &key.PublicKey, key)
	caCert, _ := x509.ParseCertificate(caDER)

	leafTmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     []string{"leaf.example.com"},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &key.PublicKey, key)
	leafCert, _ := x509.ParseCertificate(leafDER)

	// Leaf only - should trigger incomplete
	ctx := RemoteCheckContext{
		Target:       RemoteTarget{Host: "leaf.example.com", Port: 443},
		Certificates: []*x509.Certificate{leafCert},
	}
	issues := checkRemoteChainIncomplete(ctx, CheckOptions{})
	if len(issues) == 0 {
		t.Error("expected chain incomplete issue")
	}

	// With CA - should not trigger
	ctx.Certificates = []*x509.Certificate{leafCert, caCert}
	issues = checkRemoteChainIncomplete(ctx, CheckOptions{})
	if len(issues) != 0 {
		t.Error("expected no chain incomplete issue when intermediates present")
	}
}

func TestCheckSNIMismatch(t *testing.T) {
	leaf := makeRemoteTestCert(t, "correct.com", []string{"correct.com"}, false)
	ctx := RemoteCheckContext{
		Target: RemoteTarget{Host: "correct.com", Port: 443},
		TLSInfo: TLSConnectionInfo{
			ServerName: "wrong.com",
		},
		Certificates: []*x509.Certificate{leaf},
	}
	// The SNI is the name the hostname check verifies, so the mismatch is
	// reported once, as remote_hostname_mismatch (M31 WP12).
	if issues := checkSNIMismatch(ctx, CheckOptions{}); len(issues) != 0 {
		t.Errorf("SNI check must defer to the hostname check, got %+v", issues)
	}
	if issues := checkHostnameMismatch(ctx, CheckOptions{}); len(issues) != 1 {
		t.Errorf("expected one hostname mismatch, got %+v", issues)
	}

	ctx.TLSInfo.ServerName = "correct.com"
	if issues := checkSNIMismatch(ctx, CheckOptions{}); len(issues) != 0 {
		t.Error("expected no SNI mismatch when matching")
	}
}

func TestRunRemoteChecks_DisabledCheck(t *testing.T) {
	ctx := RemoteCheckContext{
		Target:  RemoteTarget{Host: "example.com", Port: 443},
		TLSInfo: TLSConnectionInfo{OCSPStapled: false},
	}

	opts := CheckOptions{
		DisabledChecks: []string{"remote_no_ocsp_staple"},
	}
	result := RunRemoteChecks(ctx, opts)
	for _, issue := range result.Issues {
		if issue.CheckID == "remote_no_ocsp_staple" {
			t.Error("disabled check should not produce issues")
		}
	}
}

func TestRunRemoteChecks_CategoryFilter(t *testing.T) {
	ctx := RemoteCheckContext{
		Target:  RemoteTarget{Host: "example.com", Port: 443},
		TLSInfo: TLSConnectionInfo{OCSPStapled: false},
	}

	opts := CheckOptions{
		Categories: []string{"nonexistent"},
	}
	result := RunRemoteChecks(ctx, opts)
	if len(result.Issues) != 0 {
		t.Error("filtering by nonexistent category should yield no issues")
	}
}

func TestRunRemoteChecks_MinSeverity(t *testing.T) {
	ctx := RemoteCheckContext{
		Target: RemoteTarget{Host: "example.com", Port: 443},
		TLSInfo: TLSConnectionInfo{
			OCSPStapled:     false,
			NegotiatedProto: "",
		},
	}

	opts := CheckOptions{
		MinSeverity: SeverityWarning,
	}
	result := RunRemoteChecks(ctx, opts)
	for _, issue := range result.Issues {
		if issue.Severity == SeverityInfo {
			t.Error("info issues should be filtered out with MinSeverity=warning")
		}
	}
}

func TestAllRemoteChecks(t *testing.T) {
	checks := AllRemoteChecks()
	if len(checks) < 14 {
		t.Errorf("expected at least 14 remote checks, got %d", len(checks))
	}

	// M30a part V added the chain-shape checks and the platform's second
	// opinion; a check that stops being registered stops running silently.
	want := []string{
		"remote_chain_extraneous",
		"remote_chain_wrong_intermediate",
		"remote_chain_order",
		"remote_chain_sent_root",
		"remote_platform_rejects",
	}
	registered := make(map[string]bool)
	for _, c := range checks {
		registered[c.ID] = true
	}
	for _, id := range want {
		if !registered[id] {
			t.Errorf("check %s is not registered", id)
		}
	}

	ids := make(map[string]bool)
	for _, c := range checks {
		if ids[c.ID] {
			t.Errorf("duplicate check ID: %s", c.ID)
		}
		ids[c.ID] = true
		if c.Category != categoryRemote {
			t.Errorf("check %s has wrong category: %s", c.ID, c.Category)
		}
	}
}
