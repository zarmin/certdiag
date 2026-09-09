package output

import (
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func TestFormatListView_Certificate(t *testing.T) {
	disableColors(t)
	rsaKey := mustGenRSAKey(t)
	caKey := mustGenRSAKey(t)
	caCert := mustSelfSignedCert(t, caKey)
	leaf := mustLeafCert(t, rsaKey, caCert, caKey)
	container := makeContainer("/tmp/cert.pem", certlib.FormatPEM, makeCertItem(leaf))

	got := FormatListView(container, 0, OutputOptions{})
	for _, sub := range []string{"cert.pem", "[pem]", "Certificate", "Subject:", "Issuer:", "Validity:", "Serial:", "Algorithm:"} {
		if !strings.Contains(got, sub) {
			t.Errorf("output missing %q", sub)
		}
	}
}

func TestFormatListView_SelfSignedCA(t *testing.T) {
	disableColors(t)
	rsaKey := mustGenRSAKey(t)
	cert := mustSelfSignedCert(t, rsaKey)
	container := makeContainer("/tmp/ca.pem", certlib.FormatPEM, makeCertItem(cert))

	got := FormatListView(container, 0, OutputOptions{})
	if !strings.Contains(got, "Self-signed") {
		t.Error("should contain 'Self-signed'")
	}
	if !strings.Contains(got, "CA:") {
		t.Error("should contain 'CA:'")
	}
}

func TestFormatListView_PrivateKey(t *testing.T) {
	disableColors(t)
	rsaKey := mustGenRSAKey(t)
	container := makeContainer("/tmp/key.pem", certlib.FormatPEM, makeKeyItem(rsaKey))

	got := FormatListView(container, 0, OutputOptions{})
	if !strings.Contains(got, "Private Key") {
		t.Error("should contain 'Private Key'")
	}
	if !strings.Contains(got, "Algorithm:") {
		t.Error("should contain 'Algorithm:'")
	}
}

func TestFormatListView_EncryptedKey(t *testing.T) {
	disableColors(t)
	item := certlib.CertItem{Type: certlib.ContentPrivateKey, Encrypted: true}
	container := makeContainer("/tmp/enc.pem", certlib.FormatPEM, item)

	got := FormatListView(container, 0, OutputOptions{})
	if !strings.Contains(got, "encrypted, password required") {
		t.Error("should contain 'encrypted, password required'")
	}
}

func TestFormatListView_DifferentPassword(t *testing.T) {
	disableColors(t)
	rsaKey := mustGenRSAKey(t)
	item := certlib.CertItem{
		Type:          certlib.ContentPrivateKey,
		PrivateKey:    rsaKey,
		EntryPassword: []byte("entry"),
	}
	container := makeContainer("/tmp/store.jks", certlib.FormatJKS, item)
	container.Password = []byte("store")

	got := FormatListView(container, 0, OutputOptions{})
	if !strings.Contains(got, "different password") {
		t.Error("should contain 'different password'")
	}
}

func TestFormatListView_CSR(t *testing.T) {
	disableColors(t)
	ecKey := mustGenECKey(t)
	csr := mustCSR(t, ecKey, "req.example.com")
	container := makeContainer("/tmp/req.pem", certlib.FormatPEM, makeCSRItem(csr))

	got := FormatListView(container, 0, OutputOptions{})
	for _, sub := range []string{"Certificate Request", "Subject:", "Algorithm:", "Signature:"} {
		if !strings.Contains(got, sub) {
			t.Errorf("output missing %q", sub)
		}
	}
}

func TestFormatListView_PublicKey(t *testing.T) {
	disableColors(t)
	rsaKey := mustGenRSAKey(t)
	container := makeContainer("/tmp/pub.pem", certlib.FormatPEM, makePubKeyItem(&rsaKey.PublicKey))

	got := FormatListView(container, 0, OutputOptions{})
	if !strings.Contains(got, "Public Key") {
		t.Error("should contain 'Public Key'")
	}
	if !strings.Contains(got, "Algorithm:") {
		t.Error("should contain 'Algorithm:'")
	}
}

func TestFormatListView_PasswordInfo(t *testing.T) {
	t.Run("unlocked", func(t *testing.T) {
		c := &certlib.CertContainer{
			UnlockSources: []certlib.PasswordSource{certlib.PasswordSourceCLI},
		}
		got := formatPasswordInfo(c)
		if !strings.Contains(got, "unlocked via") {
			t.Errorf("got %q, want 'unlocked via'", got)
		}
	})

	t.Run("locked", func(t *testing.T) {
		c := &certlib.CertContainer{
			ParseErrors: []string{"password required"},
		}
		got := formatPasswordInfo(c)
		if !strings.Contains(got, "locked") {
			t.Errorf("got %q, want 'locked'", got)
		}
	})

	t.Run("not protected", func(t *testing.T) {
		c := &certlib.CertContainer{}
		got := formatPasswordInfo(c)
		if !strings.Contains(got, "not protected") {
			t.Errorf("got %q, want 'not protected'", got)
		}
	})
}

func TestFormatListView_Details(t *testing.T) {
	disableColors(t)
	rsaKey := mustGenRSAKey(t)
	cert := mustSelfSignedCert(t, rsaKey)
	container := makeContainer("/tmp/detail.pem", certlib.FormatPEM, makeCertItem(cert))

	got := FormatListView(container, 0, OutputOptions{DetailLevel: 2})
	for _, sub := range []string{"Version:", "Signature:", "SHA-1:", "SHA-256:", "PEM:"} {
		if !strings.Contains(got, sub) {
			t.Errorf("details output missing %q", sub)
		}
	}
}

func TestFormatListView_ParseErrors(t *testing.T) {
	disableColors(t)
	container := makeContainer("/tmp/bad.pem", certlib.FormatPEM)
	container.ParseErrors = []string{"invalid data"}

	got := FormatListView(container, 0, OutputOptions{})
	if !strings.Contains(got, "Error:") {
		t.Error("should contain 'Error:'")
	}
}

func TestFormatListView_SANs(t *testing.T) {
	disableColors(t)
	rsaKey := mustGenRSAKey(t)
	caKey := mustGenRSAKey(t)
	caCert := mustSelfSignedCert(t, caKey)
	leaf := mustLeafCert(t, rsaKey, caCert, caKey)
	container := makeContainer("/tmp/san.pem", certlib.FormatPEM, makeCertItem(leaf))

	got := FormatListView(container, 0, OutputOptions{})
	if !strings.Contains(got, "SANs:") {
		t.Error("should contain 'SANs:'")
	}
}

func TestFormatListView_WithAlias(t *testing.T) {
	disableColors(t)
	rsaKey := mustGenRSAKey(t)
	cert := mustSelfSignedCert(t, rsaKey)
	item := makeCertItem(cert)
	item.Alias = "myalias"
	container := makeContainer("/tmp/store.jks", certlib.FormatJKS, item)

	got := FormatListView(container, 0, OutputOptions{})
	if !strings.Contains(got, "[myalias]") {
		t.Error("should contain '[myalias]'")
	}
}

func TestFormatListView_NilCert(t *testing.T) {
	disableColors(t)
	item := certlib.CertItem{Type: certlib.ContentCertificate}
	container := makeContainer("/tmp/nil.pem", certlib.FormatPEM, item)

	got := FormatListView(container, 0, OutputOptions{})
	if !strings.Contains(got, "failed to parse") {
		t.Error("should contain 'failed to parse'")
	}
}

func TestFormatListView_KeyCSRRelation(t *testing.T) {
	disableColors(t)
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

	got := FormatListView(&store.Containers[0], 0, opts)
	if !strings.Contains(got, "Relations:") {
		t.Error("key output should contain 'Relations:'")
	}
	if !strings.Contains(got, "csr:") {
		t.Error("key output should contain 'csr:' relation label")
	}

	got = FormatListView(&store.Containers[1], 1, opts)
	if !strings.Contains(got, "Relations:") {
		t.Error("CSR output should contain 'Relations:'")
	}
	if !strings.Contains(got, "key:") {
		t.Error("CSR output should contain 'key:' relation label")
	}
}

func TestFormatListView_CSRCertRelation(t *testing.T) {
	disableColors(t)
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

	got := FormatListView(&store.Containers[0], 0, opts)
	if !strings.Contains(got, "Relations:") {
		t.Error("CSR output should contain 'Relations:'")
	}
	if !strings.Contains(got, "cert:") {
		t.Error("CSR output should contain 'cert:' relation label")
	}

	got = FormatListView(&store.Containers[1], 1, opts)
	if !strings.Contains(got, "Relations:") {
		t.Error("cert output should contain 'Relations:'")
	}
	if !strings.Contains(got, "csr:") {
		t.Error("cert output should contain 'csr:' relation label")
	}
}
