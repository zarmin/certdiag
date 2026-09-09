package output

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func TestBuildStructuredOutput_Empty(t *testing.T) {
	out := BuildStructuredOutput(nil, OutputOptions{})
	if out == nil {
		t.Fatal("expected non-nil output")
	}
	if len(out.Files) != 0 {
		t.Errorf("expected 0 files, got %d", len(out.Files))
	}
}

func TestBuildStructuredOutput_SingleCert(t *testing.T) {
	rsaKey := mustGenRSAKey(t)
	cert := mustSelfSignedCert(t, rsaKey)
	container := makeContainer("/tmp/test.pem", certlib.FormatPEM, makeCertItem(cert))
	container.FileSize = 1234

	out := BuildStructuredOutput([]*certlib.CertContainer{container}, OutputOptions{})
	if len(out.Files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(out.Files))
	}

	f := out.Files[0]
	if f.FilePath != "/tmp/test.pem" {
		t.Errorf("FilePath = %q", f.FilePath)
	}
	if f.Filename != "test.pem" {
		t.Errorf("Filename = %q", f.Filename)
	}
	if f.FileSize != 1234 {
		t.Errorf("FileSize = %d", f.FileSize)
	}
	if f.Format != "pem" {
		t.Errorf("Format = %q", f.Format)
	}
	if len(f.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(f.Items))
	}

	item := f.Items[0]
	if item.Certificate == nil {
		t.Fatal("expected certificate")
	}
	sc := item.Certificate
	if sc.Subject == "" {
		t.Error("Subject empty")
	}
	if sc.Issuer == "" {
		t.Error("Issuer empty")
	}
	if !sc.SelfSigned {
		t.Error("expected SelfSigned=true")
	}
	if sc.NotBefore == "" {
		t.Error("NotBefore empty")
	}
	if sc.NotAfter == "" {
		t.Error("NotAfter empty")
	}
	if sc.Serial == "" {
		t.Error("Serial empty")
	}
	if sc.Algorithm == "" {
		t.Error("Algorithm empty")
	}
	if sc.SHA1 == "" {
		t.Error("SHA1 empty")
	}
	if sc.SHA256 == "" {
		t.Error("SHA256 empty")
	}
	if sc.Version == 0 {
		t.Error("Version should not be 0")
	}
}

func TestBuildStructuredOutput_PrivateKey(t *testing.T) {
	rsaKey := mustGenRSAKey(t)
	container := makeContainer("/tmp/key.pem", certlib.FormatPEM, makeKeyItem(rsaKey))

	out := BuildStructuredOutput([]*certlib.CertContainer{container}, OutputOptions{})
	item := out.Files[0].Items[0]
	if item.PrivateKey == nil {
		t.Fatal("expected private key")
	}
	if item.PrivateKey.Algorithm == "" {
		t.Error("Algorithm empty")
	}
	if item.PrivateKey.Encrypted {
		t.Error("should not be encrypted")
	}
}

func TestBuildStructuredOutput_EncryptedKey(t *testing.T) {
	encItem := certlib.CertItem{
		Type:      certlib.ContentPrivateKey,
		Encrypted: true,
	}
	container := makeContainer("/tmp/enc.pem", certlib.FormatPEM, encItem)

	out := BuildStructuredOutput([]*certlib.CertContainer{container}, OutputOptions{})
	pk := out.Files[0].Items[0].PrivateKey
	if pk == nil {
		t.Fatal("expected private key")
	}
	if !pk.Encrypted {
		t.Error("should be encrypted")
	}
	if pk.Algorithm != "" {
		t.Errorf("Algorithm should be empty for nil key, got %q", pk.Algorithm)
	}
}

func TestBuildStructuredOutput_DifferentPassword(t *testing.T) {
	rsaKey := mustGenRSAKey(t)
	item := certlib.CertItem{
		Type:          certlib.ContentPrivateKey,
		PrivateKey:    rsaKey,
		EntryPassword: []byte("entry-pass"),
	}
	container := makeContainer("/tmp/jks.jks", certlib.FormatJKS, item)
	container.Password = []byte("store-pass")

	out := BuildStructuredOutput([]*certlib.CertContainer{container}, OutputOptions{})
	pk := out.Files[0].Items[0].PrivateKey
	if !pk.DifferentPassword {
		t.Error("expected DifferentPassword=true")
	}
}

func TestBuildStructuredOutput_CSR(t *testing.T) {
	ecKey := mustGenECKey(t)
	csr := mustCSR(t, ecKey, "test.example.com")
	container := makeContainer("/tmp/req.pem", certlib.FormatPEM, makeCSRItem(csr))

	out := BuildStructuredOutput([]*certlib.CertContainer{container}, OutputOptions{})
	item := out.Files[0].Items[0]
	if item.CSR == nil {
		t.Fatal("expected CSR")
	}
	if item.CSR.Subject == "" {
		t.Error("Subject empty")
	}
	if item.CSR.Algorithm == "" {
		t.Error("Algorithm empty")
	}
	if item.CSR.SignatureAlgo == "" {
		t.Error("SignatureAlgo empty")
	}
}

func TestBuildStructuredOutput_PublicKey(t *testing.T) {
	rsaKey := mustGenRSAKey(t)
	container := makeContainer("/tmp/pub.pem", certlib.FormatPEM, makePubKeyItem(&rsaKey.PublicKey))

	out := BuildStructuredOutput([]*certlib.CertContainer{container}, OutputOptions{})
	item := out.Files[0].Items[0]
	if item.PublicKey == nil {
		t.Fatal("expected public key")
	}
	if item.PublicKey.Algorithm == "" {
		t.Error("Algorithm empty")
	}
}

func TestBuildStructuredOutput_MultipleItems(t *testing.T) {
	rsaKey := mustGenRSAKey(t)
	cert := mustSelfSignedCert(t, rsaKey)
	container := makeContainer("/tmp/bundle.pem", certlib.FormatPEM,
		makeCertItem(cert), makeKeyItem(rsaKey))

	out := BuildStructuredOutput([]*certlib.CertContainer{container}, OutputOptions{})
	if len(out.Files[0].Items) != 2 {
		t.Errorf("expected 2 items, got %d", len(out.Files[0].Items))
	}
}

func TestBuildStructuredOutput_SkipsRelationsOnly(t *testing.T) {
	rsaKey := mustGenRSAKey(t)
	cert := mustSelfSignedCert(t, rsaKey)
	container := makeContainer("/tmp/rel.pem", certlib.FormatPEM, makeCertItem(cert))
	container.RelationsOnly = true

	out := BuildStructuredOutput([]*certlib.CertContainer{container}, OutputOptions{})
	if len(out.Files) != 0 {
		t.Errorf("expected 0 files for RelationsOnly, got %d", len(out.Files))
	}
}

func TestBuildStructuredOutput_PasswordStatus(t *testing.T) {
	t.Run("unlocked", func(t *testing.T) {
		c := &certlib.CertContainer{
			UnlockSources: []certlib.PasswordSource{certlib.PasswordSourceCLI},
		}
		ps := buildPasswordStatus(c)
		if !ps.Protected || !ps.Unlocked {
			t.Errorf("expected protected+unlocked, got %+v", ps)
		}
		if len(ps.Sources) != 1 {
			t.Errorf("expected 1 source, got %d", len(ps.Sources))
		}
	})

	t.Run("locked", func(t *testing.T) {
		c := &certlib.CertContainer{
			ParseErrors: []string{"password required"},
		}
		ps := buildPasswordStatus(c)
		if !ps.Protected || ps.Unlocked {
			t.Errorf("expected protected+locked, got %+v", ps)
		}
	})

	t.Run("not protected", func(t *testing.T) {
		c := &certlib.CertContainer{}
		ps := buildPasswordStatus(c)
		if ps.Protected || ps.Unlocked {
			t.Errorf("expected not protected, got %+v", ps)
		}
	})
}

func TestBuildStructuredOutput_FileTimes(t *testing.T) {
	now := time.Now()
	container := makeContainer("/tmp/timed.pem", certlib.FormatPEM)
	container.FileModTime = now
	container.FileAccessTime = now
	container.FileCreateTime = now

	out := BuildStructuredOutput([]*certlib.CertContainer{container}, OutputOptions{})
	f := out.Files[0]
	if f.Modified == "" {
		t.Error("Modified should be set")
	}
	if f.Accessed == "" {
		t.Error("Accessed should be set")
	}
	if f.Created == "" {
		t.Error("Created should be set")
	}

	// Zero times should be omitted
	container2 := makeContainer("/tmp/notime.pem", certlib.FormatPEM)
	out2 := BuildStructuredOutput([]*certlib.CertContainer{container2}, OutputOptions{})
	f2 := out2.Files[0]
	if f2.Modified != "" {
		t.Error("Modified should be empty for zero time")
	}
}

func TestBuildStructuredOutput_ParseErrors(t *testing.T) {
	container := makeContainer("/tmp/bad.pem", certlib.FormatPEM)
	container.ParseErrors = []string{"invalid PEM data"}

	out := BuildStructuredOutput([]*certlib.CertContainer{container}, OutputOptions{})
	f := out.Files[0]
	if len(f.Errors) != 1 || f.Errors[0] != "invalid PEM data" {
		t.Errorf("expected parse error, got %v", f.Errors)
	}
}

func TestBuildStructuredOutput_KeyCSRRelation(t *testing.T) {
	key := mustGenRSAKey(t)
	csr := mustCSR(t, key, "test.example.com")

	store := certlib.NewCertStore()
	store.AddContainer(certlib.CertContainer{
		FilePath: "/tmp/test.key",
		Format:   certlib.FormatPEM,
		Items:    []certlib.CertItem{makeKeyItem(key)},
	})
	store.AddContainer(certlib.CertContainer{
		FilePath: "/tmp/test.csr",
		Format:   certlib.FormatPEM,
		Items:    []certlib.CertItem{makeCSRItem(csr)},
	})

	relations := certlib.DetectRelations(store)
	index := certlib.BuildRelationIndex(relations, store)
	opts := OutputOptions{RelationIndex: index, Store: store}

	containers := []*certlib.CertContainer{&store.Containers[0], &store.Containers[1]}
	out := BuildStructuredOutput(containers, opts)

	keyRels := out.Files[0].Items[0].Relations
	found := false
	for _, r := range keyRels {
		if r.Type == "key_csr_pair" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("key item should have key_csr_pair relation, got %+v", keyRels)
	}

	csrRels := out.Files[1].Items[0].Relations
	found = false
	for _, r := range csrRels {
		if r.Type == "key_csr_pair" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("CSR item should have key_csr_pair relation, got %+v", csrRels)
	}
}

func TestBuildStructuredOutput_CSRCertRelation(t *testing.T) {
	key := mustGenRSAKey(t)
	csr := mustCSR(t, key, "test.example.com")
	cert := mustSelfSignedCert(t, key)

	store := certlib.NewCertStore()
	store.AddContainer(certlib.CertContainer{
		FilePath: "/tmp/test.csr",
		Format:   certlib.FormatPEM,
		Items:    []certlib.CertItem{makeCSRItem(csr)},
	})
	store.AddContainer(certlib.CertContainer{
		FilePath: "/tmp/test.pem",
		Format:   certlib.FormatPEM,
		Items:    []certlib.CertItem{makeCertItem(cert)},
	})

	relations := certlib.DetectRelations(store)
	index := certlib.BuildRelationIndex(relations, store)
	opts := OutputOptions{RelationIndex: index, Store: store}

	containers := []*certlib.CertContainer{&store.Containers[0], &store.Containers[1]}
	out := BuildStructuredOutput(containers, opts)

	csrRels := out.Files[0].Items[0].Relations
	found := false
	for _, r := range csrRels {
		if r.Type == "csr_cert_pair" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("CSR item should have csr_cert_pair relation, got %+v", csrRels)
	}

	certRels := out.Files[1].Items[0].Relations
	found = false
	for _, r := range certRels {
		if r.Type == "csr_cert_pair" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("cert item should have csr_cert_pair relation, got %+v", certRels)
	}
}

func TestFormatWriteSummary(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		got := FormatWriteSummary(nil)
		if got != "" {
			t.Errorf("expected empty, got %q", got)
		}
	})

	t.Run("empty items", func(t *testing.T) {
		got := FormatWriteSummary(&WriteSummary{Operation: "write"})
		if got != "" {
			t.Errorf("expected empty, got %q", got)
		}
	})

	t.Run("single item", func(t *testing.T) {
		s := &WriteSummary{
			Operation: "created",
			Items: []WriteSummaryItem{{
				Path:      "/tmp/out.pem",
				Format:    "pem",
				Type:      "certificate",
				Subject:   "example.com",
				Issuer:    "Test CA",
				Algorithm: "RSA-2048",
				Serial:    "01:02:03",
				NotBefore: "2025-01-01",
				NotAfter:  "2026-01-01",
			}},
		}
		got := FormatWriteSummary(s)
		if !strings.Contains(got, "Subject:") {
			t.Error("should contain Subject:")
		}
		if !strings.Contains(got, "Issuer:") {
			t.Error("should contain Issuer:")
		}
		if !strings.Contains(got, "Algorithm:") {
			t.Error("should contain Algorithm:")
		}
		if !strings.Contains(got, "Created") {
			t.Error("operation should be capitalized")
		}
	})

	t.Run("operation capitalized", func(t *testing.T) {
		s := &WriteSummary{
			Operation: "exported",
			Items: []WriteSummaryItem{{
				Path:   "/tmp/out.pem",
				Format: "pem",
				Type:   "key",
			}},
		}
		got := FormatWriteSummary(s)
		if !strings.Contains(got, "Exported") {
			t.Errorf("expected capitalized operation, got %q", got)
		}
	})
}

func TestResolveContainerIndices_DuplicatePaths(t *testing.T) {
	store := &certlib.CertStore{
		Containers: []certlib.CertContainer{
			{FilePath: "/tmp/dup.pem", Format: certlib.FormatPEM},
			{FilePath: "/tmp/dup.pem", Format: certlib.FormatPEM},
			{FilePath: "/tmp/other.pem", Format: certlib.FormatPEM},
		},
	}
	containers := []*certlib.CertContainer{
		&store.Containers[1],
		&store.Containers[2],
		&store.Containers[0],
	}

	got := resolveContainerIndices(containers, OutputOptions{Store: store})
	want := map[int]int{0: 1, 1: 2, 2: 0}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("index %d resolved to store %d, want %d", i, got[i], w)
		}
	}
}

func TestResolveContainerIndices_NoMatch(t *testing.T) {
	store := &certlib.CertStore{
		Containers: []certlib.CertContainer{{FilePath: "/tmp/dup.pem", Format: certlib.FormatPEM}},
	}
	orphan := makeContainer("/tmp/dup.pem", certlib.FormatPEM)

	got := resolveContainerIndices([]*certlib.CertContainer{orphan}, OutputOptions{Store: store})
	if got[0] != -1 {
		t.Errorf("orphan container resolved to store %d, want -1", got[0])
	}
}

// TestStructured_ChainRelationsLeafOnly: showing chains on every member is a
// display change (M30a part III). The published schema keeps chain relations on
// leaves, so a consumer that assumes "chain means leaf" is not broken by it.
func TestStructured_ChainRelationsLeafOnly(t *testing.T) {
	root, rootKey := structChainCert(t, "Schema Root", true, nil, nil)
	inter, interKey := structChainCert(t, "Schema Intermediate", true, root, rootKey)
	leaf, _ := structChainCert(t, "leaf.example", false, inter, interKey)

	store := certlib.NewCertStore()
	c := certlib.CertContainer{FilePath: "/tmp/chain.pem", Format: certlib.FormatPEM}
	for _, cert := range []*x509.Certificate{root, inter, leaf} {
		c.Items = append(c.Items, certlib.CertItem{Type: certlib.ContentCertificate, Certificate: cert, RawBytes: cert.Raw})
	}
	store.AddContainer(c)

	opts := OutputOptions{}
	relations := certlib.DetectRelations(store)
	opts.RelationIndex = certlib.BuildRelationIndex(relations, store)
	alts := certlib.AssembleChainAlternatives(opts.RelationIndex, store)
	opts.Chains = certlib.FirstChains(alts)
	opts.ChainsContaining = certlib.ChainsContaining(alts)
	opts.Store = store

	out := BuildStructuredOutput([]*certlib.CertContainer{&store.Containers[0]}, opts)

	for _, item := range out.Files[0].Items {
		if item.Certificate == nil {
			continue
		}
		isLeaf := item.Certificate.Subject == "leaf.example"
		for _, rel := range item.Relations {
			if rel.Type == "chain" && !isLeaf {
				t.Errorf("%s: chain relations stay on leaves in JSON, got %+v", item.Certificate.Subject, rel)
			}
		}
	}
}

func structChainCert(t *testing.T, cn string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: isCA,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	if isCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
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
