package truststore

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"
)

func storeInfoFixture() StoreInfo {
	return StoreInfo{Type: StoreTypeCustom, Name: "Test Store"}
}

func TestVerifyChain_Trusted(t *testing.T) {
	root := newTestCA(t, "Test Root")
	inter := root.issue(t, "Test Intermediate", true, nil)
	leaf := inter.issue(t, "leaf.example.com", false, []string{"leaf.example.com"})

	pool := BuildCertPool([]*x509.Certificate{root.cert})
	vr := VerifyChain([]*x509.Certificate{leaf.cert, inter.cert}, storeInfoFixture(), pool, "")

	if !vr.Trusted {
		t.Fatalf("expected trusted, got not trusted: %v (%s)", vr.Error, vr.Reason)
	}
	if vr.TrustAnchor == nil || vr.TrustAnchor.Subject.CommonName != "Test Root" {
		t.Errorf("expected trust anchor Test Root, got %v", vr.TrustAnchor)
	}
}

func TestVerifyChain_AnchorIsLastInChain(t *testing.T) {
	root := newTestCA(t, "Anchor Root")
	leaf := root.issue(t, "leaf.example.com", false, []string{"leaf.example.com"})

	pool := BuildCertPool([]*x509.Certificate{root.cert})
	vr := VerifyChain([]*x509.Certificate{leaf.cert}, storeInfoFixture(), pool, "")

	if !vr.Trusted {
		t.Fatalf("expected trusted: %v", vr.Reason)
	}
	if len(vr.Chain) < 2 {
		t.Fatalf("expected chain of at least 2, got %d", len(vr.Chain))
	}
	last := vr.Chain[len(vr.Chain)-1]
	if last.Subject.CommonName != "Anchor Root" {
		t.Errorf("expected root last in chain, got %q", last.Subject.CommonName)
	}
	if vr.Chain[0].Subject.CommonName != "leaf.example.com" {
		t.Errorf("expected leaf first in chain, got %q", vr.Chain[0].Subject.CommonName)
	}
}

func TestVerifyChain_UntrustedRoot(t *testing.T) {
	root := newTestCA(t, "Untrusted Root")
	other := newTestCA(t, "Some Other Root")
	leaf := root.issue(t, "leaf.example.com", false, []string{"leaf.example.com"})

	pool := BuildCertPool([]*x509.Certificate{other.cert})
	vr := VerifyChain([]*x509.Certificate{leaf.cert}, storeInfoFixture(), pool, "")

	if vr.Trusted {
		t.Fatal("expected not trusted")
	}
	if vr.Reason == "" {
		t.Error("expected a reason for the failure")
	}
	if vr.Error == nil {
		t.Error("expected the underlying error to be preserved")
	}
}

func TestVerifyChain_Expired(t *testing.T) {
	root := newTestCA(t, "Expiry Root")
	leaf := root.issueValid(t, "old.example.com", false, []string{"old.example.com"},
		time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))

	pool := BuildCertPool([]*x509.Certificate{root.cert})
	vr := VerifyChain([]*x509.Certificate{leaf.cert}, storeInfoFixture(), pool, "")

	if vr.Trusted {
		t.Fatal("expected expired cert to be untrusted")
	}
	if !strings.Contains(strings.ToLower(vr.Reason), "expir") {
		t.Errorf("expected reason to mention expiry, got %q", vr.Reason)
	}
}

func TestVerifyChain_NotYetValid(t *testing.T) {
	root := newTestCA(t, "Future Root")
	leaf := root.issueValid(t, "future.example.com", false, []string{"future.example.com"},
		time.Now().Add(24*time.Hour), time.Now().Add(48*time.Hour))

	pool := BuildCertPool([]*x509.Certificate{root.cert})
	vr := VerifyChain([]*x509.Certificate{leaf.cert}, storeInfoFixture(), pool, "")

	if vr.Trusted {
		t.Fatal("expected not-yet-valid cert to be untrusted")
	}
	if vr.Reason == "" {
		t.Error("expected a reason")
	}
}

func TestVerifyChain_HostnameMismatch(t *testing.T) {
	root := newTestCA(t, "Host Root")
	leaf := root.issue(t, "right.example.com", false, []string{"right.example.com"})

	pool := BuildCertPool([]*x509.Certificate{root.cert})
	vr := VerifyChain([]*x509.Certificate{leaf.cert}, storeInfoFixture(), pool, "wrong.example.com")

	if vr.Trusted {
		t.Fatal("expected hostname mismatch to be untrusted")
	}
	if vr.Hostname != "wrong.example.com" {
		t.Errorf("expected hostname recorded, got %q", vr.Hostname)
	}
}

func TestVerifyChain_HostnameEmptySkipsDNSCheck(t *testing.T) {
	root := newTestCA(t, "NoHost Root")
	leaf := root.issue(t, "only.example.com", false, []string{"only.example.com"})

	pool := BuildCertPool([]*x509.Certificate{root.cert})
	vr := VerifyChain([]*x509.Certificate{leaf.cert}, storeInfoFixture(), pool, "")

	if !vr.Trusted {
		t.Fatalf("empty hostname must skip DNS validation, got %q", vr.Reason)
	}
}

func TestVerifyChain_MissingIntermediate(t *testing.T) {
	root := newTestCA(t, "Gap Root")
	inter := root.issue(t, "Gap Intermediate", true, nil)
	leaf := inter.issue(t, "gap.example.com", false, []string{"gap.example.com"})

	// Intermediate deliberately omitted from the presented chain.
	pool := BuildCertPool([]*x509.Certificate{root.cert})
	vr := VerifyChain([]*x509.Certificate{leaf.cert}, storeInfoFixture(), pool, "")

	if vr.Trusted {
		t.Fatal("expected missing intermediate to break the chain")
	}
	if len(vr.Suggestions) == 0 {
		t.Error("expected a suggestion for the incomplete chain")
	}
}

func TestVerifyChain_EmptyInput(t *testing.T) {
	vr := VerifyChain(nil, storeInfoFixture(), nil, "")
	if vr.Trusted {
		t.Fatal("expected empty input to be untrusted")
	}
	if vr.Reason == "" {
		t.Error("expected a reason for empty input")
	}
}

func TestVerifyChain_SelfSignedAgainstOwnPool(t *testing.T) {
	root := newTestCA(t, "Self Signed")
	pool := BuildCertPool([]*x509.Certificate{root.cert})
	vr := VerifyChain([]*x509.Certificate{root.cert}, storeInfoFixture(), pool, "")

	if !vr.Trusted {
		t.Fatalf("self-signed cert in its own pool should verify: %v", vr.Reason)
	}
	if vr.TrustAnchor == nil || vr.TrustAnchor.Subject.CommonName != "Self Signed" {
		t.Errorf("expected the cert itself as anchor, got %v", vr.TrustAnchor)
	}
}
