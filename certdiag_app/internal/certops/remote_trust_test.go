package certops

import (
	"crypto/x509"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

func trustSelOSOnly() RemoteTrustSelection { return RemoteTrustSelection{OS: true} }

// TestRemoteTrust_PerStoreVerdicts is the "would it work in Java" answer: the
// same served chain, one verdict per store, and the disagreement visible.
func TestRemoteTrust_PerStoreVerdicts(t *testing.T) {
	root, rootKey := verifyTestCert(t, "Per Store Root", true, nil, nil, nil)
	leaf, _ := verifyTestCert(t, "leaf.example", false, root, rootKey, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	otherRoot, _ := verifyTestCert(t, "Other Root", true, nil, nil, nil)

	readers := stubReaders(
		[]truststore.StoreContents{storeFixture("Stub OS Store", truststore.StoreTypeOS, "/os", root)},
		[]truststore.StoreContents{storeFixture("Java 21", truststore.StoreTypeJava, "/jdk", otherRoot)},
		nil,
	)

	sel := RemoteTrustSelection{OS: true, Java: true}
	loaded, err := LoadStoresForSelection(sel, hermeticOpts(readers))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	rows, _ := VerifyRemoteAgainstStores([]*x509.Certificate{leaf, root}, "leaf.example", sel, loaded.Stores)
	if len(rows) != 2 {
		t.Fatalf("expected one row per selected store, got %d: %+v", len(rows), rows)
	}

	byStore := make(map[string]RemoteStoreVerdict)
	for _, r := range rows {
		byStore[r.Store] = r
	}
	if os := byStore["Stub OS Store"]; !os.Trusted {
		t.Errorf("the OS store holds the root, so it must trust the chain: %q", os.Reason)
	} else if os.Anchor == "" {
		t.Error("a trusted verdict must name the anchor that terminated the chain")
	}
	if java := byStore["Java 21"]; java.Trusted {
		t.Error("the Java store does not hold the root, so it must not trust the chain")
	}
}

// TestRemoteTrust_HostnameIsChecked: a chain that is valid for another name is
// not a pass. Reporting it as one would be worse than saying nothing.
func TestRemoteTrust_HostnameIsChecked(t *testing.T) {
	root, rootKey := verifyTestCert(t, "Hostname Root", true, nil, nil, nil)
	leaf, _ := verifyTestCert(t, "right.example", false, root, rootKey, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

	readers := stubReaders(
		[]truststore.StoreContents{storeFixture("Stub OS Store", truststore.StoreTypeOS, "/os", root)}, nil, nil)

	loaded, err := LoadStoresForSelection(trustSelOSOnly(), hermeticOpts(readers))
	if err != nil {
		t.Fatal(err)
	}
	wrong, _ := VerifyRemoteAgainstStores([]*x509.Certificate{leaf, root}, "wrong.example", trustSelOSOnly(), loaded.Stores)
	if len(wrong) != 1 || wrong[0].Trusted {
		t.Errorf("a chain served for another name must not verify: %+v", wrong)
	}

	right, _ := VerifyRemoteAgainstStores([]*x509.Certificate{leaf, root}, "right.example", trustSelOSOnly(), loaded.Stores)
	if len(right) != 1 || !right[0].Trusted {
		t.Errorf("the matching name must verify: %+v", right)
	}
}

// TestRemoteTrust_UnselectedStoresAreSkipped: "not asked" and "does not trust"
// are different answers, and the table must not conflate them.
func TestRemoteTrust_UnselectedStoresAreSkipped(t *testing.T) {
	root, rootKey := verifyTestCert(t, "Skip Root", true, nil, nil, nil)
	leaf, _ := verifyTestCert(t, "leaf.example", false, root, rootKey, nil)

	readers := stubReaders(
		[]truststore.StoreContents{storeFixture("Stub OS Store", truststore.StoreTypeOS, "/os", root)},
		[]truststore.StoreContents{storeFixture("Java 21", truststore.StoreTypeJava, "/jdk", root)},
		nil,
	)

	loaded, err := LoadStoresForSelection(trustSelOSOnly(), hermeticOpts(readers))
	if err != nil {
		t.Fatal(err)
	}
	rows, _ := VerifyRemoteAgainstStores([]*x509.Certificate{leaf, root}, "leaf.example", trustSelOSOnly(), loaded.Stores)
	for _, r := range rows {
		if r.Store == "Java 21" {
			t.Error("a store that was not selected must not appear in the table")
		}
	}
}

// TestRemoteTrust_AgreesWithScan is the one-engine guarantee: the same bytes
// read from a socket and from a file must produce the same verdict.
func TestRemoteTrust_AgreesWithScan(t *testing.T) {
	root, rootKey := verifyTestCert(t, "Agree Root", true, nil, nil, nil)
	leaf, _ := verifyTestCert(t, "leaf.example", false, root, rootKey, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	stores := []truststore.StoreContents{storeFixture("Stub OS Store", truststore.StoreTypeOS, "/os", root)}

	remote := RemoteCertStore(&FetchRemoteCertResult{TargetResults: []TargetFetchResult{
		remoteResultFor("leaf.example:443", []string{"leaf", "root"}, []*x509.Certificate{leaf, root}),
	}})

	scanned := certlib.NewCertStore()
	scanned.AddContainer(certlib.CertContainer{
		FilePath: "/tmp/chain.pem",
		Format:   certlib.FormatPEM,
		Source:   certlib.SourceFile,
		Items: []certlib.CertItem{
			{Type: certlib.ContentCertificate, Certificate: leaf, RawBytes: leaf.Raw},
			{Type: certlib.ContentCertificate, Certificate: root, RawBytes: root.Raw},
		},
	})

	remoteIndex, err := EvaluateTrust(TrustEvalOptions{Store: remote, Stores: stores})
	if err != nil {
		t.Fatal(err)
	}
	scanIndex, err := EvaluateTrust(TrustEvalOptions{Store: scanned, Stores: stores})
	if err != nil {
		t.Fatal(err)
	}

	for _, cert := range []*x509.Certificate{leaf, root} {
		got, want := remoteIndex.Verdict(cert), scanIndex.Verdict(cert)
		if got != want {
			t.Errorf("%s: remote says %q, the scan says %q", cert.Subject.CommonName, got, want)
		}
		if got == "" {
			t.Errorf("%s: expected a verdict", cert.Subject.CommonName)
		}
	}
}
