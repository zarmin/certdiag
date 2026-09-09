package certops

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func rsCert(t *testing.T, cn string, parent *x509.Certificate, parentKey *rsa.PrivateKey, isCA bool) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func remoteResultFor(target string, roles []string, certs []*x509.Certificate) TargetFetchResult {
	tr := TargetFetchResult{
		Target:     target,
		Connection: &RemoteConnectionInfo{TLSVersion: "TLS 1.3", CipherSuite: "TLS_AES_128_GCM_SHA256"},
	}
	for i, c := range certs {
		tr.Certs = append(tr.Certs, RemoteCertInfo{
			Index: i,
			Role:  roles[i],
			Cert:  &certlib.CertItem{Type: certlib.ContentCertificate, Certificate: c, RawBytes: c.Raw},
		})
	}
	return tr
}

// TestRemoteCertStore_OneContainerPerTarget: two targets stay two containers and
// their relations never cross-link, so one server's chain cannot appear to
// complete through another server's certificates.
//
// Deviation from the test design, which asked for one container per resolved IP:
// FetchRemoteCert keeps a single chain per target (MultiIPInfo carries only the
// address list), so per-IP containers need a certops change first.
func TestRemoteCertStore_OneContainerPerTarget(t *testing.T) {
	rootA, keyA := rsCert(t, "Root A", nil, nil, true)
	leafA, _ := rsCert(t, "leaf-a.example", rootA, keyA, false)
	rootB, keyB := rsCert(t, "Root B", nil, nil, true)
	leafB, _ := rsCert(t, "leaf-b.example", rootB, keyB, false)

	result := &FetchRemoteCertResult{TargetResults: []TargetFetchResult{
		remoteResultFor("a.example:443", []string{"leaf", "root"}, []*x509.Certificate{leafA, rootA}),
		remoteResultFor("b.example:443", []string{"leaf", "root"}, []*x509.Certificate{leafB, rootB}),
	}}

	store := RemoteCertStore(result)
	if len(store.Containers) != 2 {
		t.Fatalf("expected one container per target, got %d", len(store.Containers))
	}
	if store.Containers[0].Label == store.Containers[1].Label {
		t.Error("containers must carry distinct labels")
	}

	for _, rel := range certlib.DetectRelations(store) {
		if rel.Source.ContainerIdx != rel.Target.ContainerIdx {
			t.Errorf("relation crosses targets: %v -> %v", rel.Source, rel.Target)
		}
	}
}

func TestRemoteCertStore_ServedOrderAndRoles(t *testing.T) {
	root, rootKey := rsCert(t, "Root", nil, nil, true)
	inter, interKey := rsCert(t, "Intermediate", root, rootKey, true)
	leaf, _ := rsCert(t, "leaf.example", inter, interKey, false)

	result := &FetchRemoteCertResult{TargetResults: []TargetFetchResult{
		remoteResultFor("h:443", []string{"leaf", "intermediate", "root"},
			[]*x509.Certificate{leaf, inter, root}),
	}}

	c := RemoteCertStore(result).Containers[0]
	wantCN := []string{"leaf.example", "Intermediate", "Root"}
	wantRole := []string{"leaf", "intermediate", "root"}
	if len(c.Items) != 3 {
		t.Fatalf("expected 3 items, got %d", len(c.Items))
	}
	for i, item := range c.Items {
		if item.Certificate.Subject.CommonName != wantCN[i] {
			t.Errorf("item %d: served order broken, want %s got %s", i, wantCN[i], item.Certificate.Subject.CommonName)
		}
		if item.Alias != wantRole[i] {
			t.Errorf("item %d: alias must carry the role, want %s got %s", i, wantRole[i], item.Alias)
		}
	}
}

func TestRemoteCertStore_SourceAndFormat(t *testing.T) {
	leaf, _ := rsCert(t, "leaf.example", nil, nil, false)
	result := &FetchRemoteCertResult{TargetResults: []TargetFetchResult{
		remoteResultFor("h:443", []string{"leaf"}, []*x509.Certificate{leaf}),
	}}

	c := RemoteCertStore(result).Containers[0]
	if c.Source != certlib.SourceRemote {
		t.Errorf("expected SourceRemote, got %q", c.Source)
	}
	if c.Format != certlib.FormatPEM {
		t.Errorf("expected PEM format, got %q", c.Format)
	}
	if c.FilePath != "h:443" {
		t.Errorf("the target is the ref key, got %q", c.FilePath)
	}
	if c.Label == "" {
		t.Error("a remote container must carry a human label")
	}
}

// TestRemoteCertStore_FailedTargetKeepsRow: a target that could not be reached
// stays visible with its reason, the way an unreadable file does.
func TestRemoteCertStore_FailedTargetKeepsRow(t *testing.T) {
	result := &FetchRemoteCertResult{TargetResults: []TargetFetchResult{
		{Target: "down.example:443", Error: "connection refused"},
	}}

	c := RemoteCertStore(result).Containers[0]
	if len(c.Items) != 0 {
		t.Errorf("a failed target has no certificates, got %d", len(c.Items))
	}
	if len(c.ParseErrors) != 1 || c.ParseErrors[0] != "connection refused" {
		t.Errorf("the failure must survive as a parse error, got %v", c.ParseErrors)
	}
}

func TestRemoteCertStore_NilResult(t *testing.T) {
	if got := RemoteCertStore(nil); got == nil || len(got.Containers) != 0 {
		t.Error("a nil result must give an empty store, not a nil one")
	}
}

// TestCheckFetchedTarget_MergesRemoteAndFileChecks: the TUI and the CLI both go
// through this, so a check that only one of them ran would be a drift bug.
func TestCheckFetchedTarget_MergesRemoteAndFileChecks(t *testing.T) {
	root, rootKey := rsCert(t, "Merge Root", nil, nil, true)
	leaf, _ := rsCert(t, "leaf.example", root, rootKey, false)
	stranger, _ := rsCert(t, "Unrelated CA", nil, nil, true)

	result := CheckFetchedTarget(CheckTargetInput{
		Target:       certlib.RemoteTarget{Host: "leaf.example", Port: 443},
		TLSInfo:      certlib.TLSConnectionInfo{ServerName: "leaf.example"},
		Certificates: []*x509.Certificate{leaf, root, stranger},
	}, certlib.CheckOptions{})

	ids := make(map[string]bool)
	for _, issue := range result.Issues {
		ids[issue.CheckID] = true
	}

	if !ids["remote_chain_extraneous"] {
		t.Error("the remote checks must run (expected remote_chain_extraneous)")
	}
	if len(result.Issues) == 0 {
		t.Fatal("expected findings")
	}
	if result.FilesScanned == 0 {
		t.Error("the file-level pass must run too, and report what it scanned")
	}
	if result.Summary.Warning == 0 {
		t.Error("the summary must count the merged issues")
	}
}

// TestCheckFetchedTarget_NoPoolSkipsTrust keeps the M29 rule: nothing
// trust-related happens unless a pool was handed in.
func TestCheckFetchedTarget_NoPoolSkipsTrust(t *testing.T) {
	root, rootKey := rsCert(t, "Quiet Root", nil, nil, true)
	leaf, _ := rsCert(t, "leaf.example", root, rootKey, false)

	result := CheckFetchedTarget(CheckTargetInput{
		Target:       certlib.RemoteTarget{Host: "leaf.example", Port: 443},
		Certificates: []*x509.Certificate{leaf, root},
	}, certlib.CheckOptions{})

	for _, issue := range result.Issues {
		if issue.CheckID == "remote_chain_untrusted" || issue.CheckID == "remote_platform_rejects" {
			t.Errorf("no anchor pool was supplied, so %s must not run", issue.CheckID)
		}
	}
}
