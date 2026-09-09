package truststore

import (
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCertFingerprint_Stable(t *testing.T) {
	a := newTestCA(t, "Fingerprint A")
	b := newTestCA(t, "Fingerprint B")

	if CertFingerprint(a.cert) != CertFingerprint(a.cert) {
		t.Error("fingerprint must be stable for the same certificate")
	}
	if CertFingerprint(a.cert) == CertFingerprint(b.cert) {
		t.Error("different certificates must not share a fingerprint")
	}
	if len(CertFingerprint(a.cert)) != 64 {
		t.Errorf("expected 64 hex chars for sha256, got %d", len(CertFingerprint(a.cert)))
	}
}

func TestGetTrust_NilMap(t *testing.T) {
	ca := newTestCA(t, "No Trust Map")
	sc := &StoreContents{}

	got := sc.GetTrust(ca.cert)
	if got.Overall != TrustUnset {
		t.Errorf("expected Unset for a nil trust map, got %q", got.Overall)
	}
}

func TestGetTrust_HitAndMiss(t *testing.T) {
	known := newTestCA(t, "Known")
	unknown := newTestCA(t, "Unknown")

	sc := &StoreContents{
		TrustMap: map[string]CertTrust{
			CertFingerprint(known.cert): {Overall: TrustDenied},
		},
	}

	if got := sc.GetTrust(known.cert); got.Overall != TrustDenied {
		t.Errorf("expected Denied for the known cert, got %q", got.Overall)
	}
	if got := sc.GetTrust(unknown.cert); got.Overall != TrustUnset {
		t.Errorf("expected Unset for an absent cert, got %q", got.Overall)
	}
}

func TestBuildCertPool_Empty(t *testing.T) {
	pool := BuildCertPool(nil)
	if pool == nil {
		t.Fatal("expected a usable pool, got nil")
	}
	// An empty pool must be usable and trust nothing.
	ca := newTestCA(t, "Not In Pool")
	leaf := ca.issue(t, "x.example.com", false, []string{"x.example.com"})
	vr := VerifyChain([]*x509.Certificate{leaf.cert}, storeInfoFixture(), pool, "")
	if vr.Trusted {
		t.Error("an empty pool must not trust anything")
	}
}

func TestBuildCertPool_Duplicates(t *testing.T) {
	ca := newTestCA(t, "Dup Root")
	pool := BuildCertPool([]*x509.Certificate{ca.cert, ca.cert})

	leaf := ca.issue(t, "dup.example.com", false, []string{"dup.example.com"})
	vr := VerifyChain([]*x509.Certificate{leaf.cert}, storeInfoFixture(), pool, "")
	if !vr.Trusted {
		t.Errorf("a duplicated root must not corrupt the pool: %v", vr.Reason)
	}
}

func TestClassifyVerifyError_Nil(t *testing.T) {
	reason, suggestions := ClassifyVerifyError(nil, "")
	if reason != "" || suggestions != nil {
		t.Errorf("nil error must classify to nothing, got %q / %v", reason, suggestions)
	}
}

func TestClassifyVerifyError_UnknownAuthority(t *testing.T) {
	reason, suggestions := ClassifyVerifyError(x509.UnknownAuthorityError{}, "")
	if !strings.Contains(reason, "unknown authority") {
		t.Errorf("expected unknown authority reason, got %q", reason)
	}
	if len(suggestions) == 0 {
		t.Error("expected suggestions for unknown authority")
	}
}

func TestClassifyVerifyError_Expired(t *testing.T) {
	ca := newTestCAValid(t, "Expired CA",
		time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))

	err := x509.CertificateInvalidError{Cert: ca.cert, Reason: x509.Expired}
	reason, suggestions := ClassifyVerifyError(err, "")

	if !strings.Contains(reason, "expired") {
		t.Errorf("expected expiry reason, got %q", reason)
	}
	if len(suggestions) == 0 {
		t.Error("expected a suggestion naming the expiry date")
	}
}

func TestClassifyVerifyError_NotYetValid(t *testing.T) {
	ca := newTestCAValid(t, "Future CA",
		time.Now().Add(24*time.Hour), time.Now().Add(48*time.Hour))

	err := x509.CertificateInvalidError{Cert: ca.cert, Reason: x509.Expired}
	reason, _ := ClassifyVerifyError(err, "")

	if !strings.Contains(reason, "not yet valid") {
		t.Errorf("expected not-yet-valid reason, got %q", reason)
	}
}

func TestClassifyVerifyError_Hostname(t *testing.T) {
	ca := newTestCA(t, "Host CA")
	leaf := ca.issue(t, "right.example.com", false, []string{"right.example.com"})

	err := x509.HostnameError{Certificate: leaf.cert, Host: "wrong.example.com"}
	reason, suggestions := ClassifyVerifyError(err, "wrong.example.com")

	if !strings.Contains(reason, "hostname mismatch") {
		t.Errorf("expected hostname reason, got %q", reason)
	}
	if len(suggestions) == 0 {
		t.Error("expected a suggestion naming the actual DNS names")
	}
}

func TestClassifyVerifyError_UnknownFallsBack(t *testing.T) {
	reason, suggestions := ClassifyVerifyError(errors.New("something odd"), "")
	if reason != "something odd" {
		t.Errorf("expected the raw error text, got %q", reason)
	}
	if len(suggestions) == 0 {
		t.Error("expected a generic suggestion")
	}
}
