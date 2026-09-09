//go:build fulltest

package certlib

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestDetectRelations_SignedBy(t *testing.T) {
	caKey := mustGenerateRSAKey(t)
	caCert, caDer := mustCreateSelfSignedCA(t, caKey)

	leafKey := mustGenerateRSAKey(t)
	_, leafDer := mustCreateLeafCert(t, leafKey, caCert, caKey)

	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "ca.crt",
		Items: []CertItem{{
			Type:        ContentCertificate,
			Certificate: mustParseCert(t, caDer),
		}},
	})
	store.AddContainer(CertContainer{
		FilePath: "leaf.crt",
		Items: []CertItem{{
			Type:        ContentCertificate,
			Certificate: mustParseCert(t, leafDer),
		}},
	})

	relations := DetectRelations(store)
	found := false
	for _, r := range relations {
		if r.Type == RelationSignedBy {
			if r.Source.ContainerIdx == 1 && r.Target.ContainerIdx == 0 {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected signed_by relation from leaf to CA")
	}
}

func TestDetectRelations_SelfSignedNoRelation(t *testing.T) {
	caKey := mustGenerateRSAKey(t)
	_, caDer := mustCreateSelfSignedCA(t, caKey)

	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "ca.crt",
		Items: []CertItem{{
			Type:        ContentCertificate,
			Certificate: mustParseCert(t, caDer),
		}},
	})

	relations := DetectRelations(store)
	for _, r := range relations {
		if r.Type == RelationSignedBy {
			t.Fatal("self-signed cert should not have signed_by relation")
		}
	}
}

func TestDetectRelations_KeyCertPair(t *testing.T) {
	key := mustGenerateRSAKey(t)
	cert, certDer := mustCreateSelfSignedCA(t, key)
	_ = cert

	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "cert.crt",
		Items: []CertItem{{
			Type:        ContentCertificate,
			Certificate: mustParseCert(t, certDer),
		}},
	})
	store.AddContainer(CertContainer{
		FilePath: "cert.key",
		Items: []CertItem{{
			Type:       ContentPrivateKey,
			PrivateKey: key,
		}},
	})

	relations := DetectRelations(store)
	found := false
	for _, r := range relations {
		if r.Type == RelationKeyCert {
			found = true
		}
	}
	if !found {
		t.Fatal("expected key_cert_pair relation")
	}
}

func TestDetectRelations_KeyCertMismatch(t *testing.T) {
	rsaKey := mustGenerateRSAKey(t)
	_, certDer := mustCreateSelfSignedCA(t, rsaKey)

	ecKey := mustGenerateECKey(t)

	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "cert.crt",
		Items: []CertItem{{
			Type:        ContentCertificate,
			Certificate: mustParseCert(t, certDer),
		}},
	})
	store.AddContainer(CertContainer{
		FilePath: "other.key",
		Items: []CertItem{{
			Type:       ContentPrivateKey,
			PrivateKey: ecKey,
		}},
	})

	relations := DetectRelations(store)
	for _, r := range relations {
		if r.Type == RelationKeyCert {
			t.Fatal("mismatched key types should not produce key_cert_pair relation")
		}
	}
}

func TestDetectRelations_KeyCertDifferentFiles(t *testing.T) {
	key := mustGenerateRSAKey(t)
	_, certDer := mustCreateSelfSignedCA(t, key)

	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "server.crt",
		Items: []CertItem{{
			Type:        ContentCertificate,
			Certificate: mustParseCert(t, certDer),
		}},
	})
	store.AddContainer(CertContainer{
		FilePath: "server.key",
		Items: []CertItem{{
			Type:       ContentPrivateKey,
			PrivateKey: key,
		}},
	})

	relations := DetectRelations(store)
	found := false
	for _, r := range relations {
		if r.Type == RelationKeyCert {
			found = true
			if r.Source.FilePath != "server.key" || r.Target.FilePath != "server.crt" {
				t.Fatalf("unexpected key_cert_pair source/target: %s -> %s",
					r.Source.FilePath, r.Target.FilePath)
			}
		}
	}
	if !found {
		t.Fatal("expected key_cert_pair across different files")
	}
}

func TestDetectRelations_Duplicates(t *testing.T) {
	key := mustGenerateRSAKey(t)
	_, certDer := mustCreateSelfSignedCA(t, key)
	cert := mustParseCert(t, certDer)

	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "a.crt",
		Items:    []CertItem{{Type: ContentCertificate, Certificate: cert}},
	})
	store.AddContainer(CertContainer{
		FilePath: "b.crt",
		Items:    []CertItem{{Type: ContentCertificate, Certificate: cert}},
	})

	relations := DetectRelations(store)
	count := 0
	for _, r := range relations {
		if r.Type == RelationSameCert {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected 1 same_cert relation, got %d", count)
	}
}

func TestDetectRelations_TripleDuplicate(t *testing.T) {
	key := mustGenerateRSAKey(t)
	_, certDer := mustCreateSelfSignedCA(t, key)
	cert := mustParseCert(t, certDer)

	store := NewCertStore()
	for _, name := range []string{"a.crt", "b.crt", "c.crt"} {
		store.AddContainer(CertContainer{
			FilePath: name,
			Items:    []CertItem{{Type: ContentCertificate, Certificate: cert}},
		})
	}

	relations := DetectRelations(store)
	count := 0
	for _, r := range relations {
		if r.Type == RelationSameCert {
			count++
		}
	}
	// 3 items -> C(3,2) = 3 pairwise relations
	if count != 3 {
		t.Fatalf("expected 3 same_cert relations for triple duplicate, got %d", count)
	}
}

func TestDetectRelations_DifferentSerialNotDuplicate(t *testing.T) {
	key1 := mustGenerateRSAKey(t)
	_, der1 := mustCreateSelfSignedCA(t, key1)

	key2 := mustGenerateRSAKey(t)
	_, der2 := mustCreateSelfSignedCA(t, key2)

	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "a.crt",
		Items:    []CertItem{{Type: ContentCertificate, Certificate: mustParseCert(t, der1)}},
	})
	store.AddContainer(CertContainer{
		FilePath: "b.crt",
		Items:    []CertItem{{Type: ContentCertificate, Certificate: mustParseCert(t, der2)}},
	})

	relations := DetectRelations(store)
	for _, r := range relations {
		if r.Type == RelationSameCert {
			t.Fatal("different certs should not be detected as duplicates")
		}
	}
}

func TestIsSelfSigned(t *testing.T) {
	caKey := mustGenerateRSAKey(t)
	caCert, _ := mustCreateSelfSignedCA(t, caKey)

	if !IsSelfSigned(caCert) {
		t.Fatal("self-signed CA should return true")
	}

	leafKey := mustGenerateRSAKey(t)
	leafCert, _ := mustCreateLeafCert(t, leafKey, caCert, caKey)

	if IsSelfSigned(leafCert) {
		t.Fatal("CA-signed leaf should return false")
	}
}

func TestAssembleChains(t *testing.T) {
	rootKey := mustGenerateRSAKey(t)
	rootCert, rootDer := mustCreateSelfSignedCA(t, rootKey)

	intKey := mustGenerateRSAKey(t)
	intCert, intDer := mustCreateIntermediateCA(t, intKey, rootCert, rootKey)

	leafKey := mustGenerateRSAKey(t)
	_, leafDer := mustCreateLeafCert(t, leafKey, intCert, intKey)

	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "root.crt",
		Items:    []CertItem{{Type: ContentCertificate, Certificate: mustParseCert(t, rootDer)}},
	})
	store.AddContainer(CertContainer{
		FilePath: "int.crt",
		Items:    []CertItem{{Type: ContentCertificate, Certificate: mustParseCert(t, intDer)}},
	})
	store.AddContainer(CertContainer{
		FilePath: "leaf.crt",
		Items:    []CertItem{{Type: ContentCertificate, Certificate: mustParseCert(t, leafDer)}},
	})

	relations := DetectRelations(store)
	index := BuildRelationIndex(relations, store)
	chains := AssembleChains(index, store)

	leafRef := ItemRef{ContainerIdx: 2, ItemIdx: 0, FilePath: "leaf.crt"}
	chain, ok := chains[leafRef]
	if !ok {
		t.Fatal("expected chain starting from leaf")
	}
	if len(chain) != 3 {
		t.Fatalf("expected chain of length 3, got %d", len(chain))
	}
}

func TestAssembleChains_Partial(t *testing.T) {
	rootKey := mustGenerateRSAKey(t)
	rootCert, _ := mustCreateSelfSignedCA(t, rootKey)

	intKey := mustGenerateRSAKey(t)
	intCert, intDer := mustCreateIntermediateCA(t, intKey, rootCert, rootKey)

	leafKey := mustGenerateRSAKey(t)
	_, leafDer := mustCreateLeafCert(t, leafKey, intCert, intKey)

	// Only include intermediate and leaf, no root
	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "int.crt",
		Items:    []CertItem{{Type: ContentCertificate, Certificate: mustParseCert(t, intDer)}},
	})
	store.AddContainer(CertContainer{
		FilePath: "leaf.crt",
		Items:    []CertItem{{Type: ContentCertificate, Certificate: mustParseCert(t, leafDer)}},
	})

	relations := DetectRelations(store)
	index := BuildRelationIndex(relations, store)
	chains := AssembleChains(index, store)

	leafRef := ItemRef{ContainerIdx: 1, ItemIdx: 0, FilePath: "leaf.crt"}
	chain, ok := chains[leafRef]
	if !ok {
		t.Fatal("expected partial chain starting from leaf")
	}
	if len(chain) != 2 {
		t.Fatalf("expected chain of length 2, got %d", len(chain))
	}
}

func TestAssembleChains_LeafOnly(t *testing.T) {
	caKey := mustGenerateRSAKey(t)
	caCert, _ := mustCreateSelfSignedCA(t, caKey)

	leafKey := mustGenerateRSAKey(t)
	_, leafDer := mustCreateLeafCert(t, leafKey, caCert, caKey)

	// Only the leaf, no issuer present
	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "leaf.crt",
		Items:    []CertItem{{Type: ContentCertificate, Certificate: mustParseCert(t, leafDer)}},
	})

	relations := DetectRelations(store)
	index := BuildRelationIndex(relations, store)
	chains := AssembleChains(index, store)

	if len(chains) != 0 {
		t.Fatalf("expected no chains (minimum 2 required), got %d", len(chains))
	}
}

func TestBuildRelationIndex_Bidirectional(t *testing.T) {
	caKey := mustGenerateRSAKey(t)
	caCert, caDer := mustCreateSelfSignedCA(t, caKey)

	leafKey := mustGenerateRSAKey(t)
	_, leafDer := mustCreateLeafCert(t, leafKey, caCert, caKey)

	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "ca.crt",
		Items:    []CertItem{{Type: ContentCertificate, Certificate: mustParseCert(t, caDer)}},
	})
	store.AddContainer(CertContainer{
		FilePath: "leaf.crt",
		Items:    []CertItem{{Type: ContentCertificate, Certificate: mustParseCert(t, leafDer)}},
	})

	relations := DetectRelations(store)
	index := BuildRelationIndex(relations, store)

	leafRef := ItemRef{ContainerIdx: 1, ItemIdx: 0, FilePath: "leaf.crt"}
	caRef := ItemRef{ContainerIdx: 0, ItemIdx: 0, FilePath: "ca.crt"}

	// Leaf should have outgoing signed_by
	leafRels := index[leafRef]
	foundOutgoing := false
	for _, r := range leafRels {
		if r.Type == RelationSignedBy && r.Direction == DirectionOutgoing {
			foundOutgoing = true
		}
	}
	if !foundOutgoing {
		t.Fatal("leaf should have outgoing signed_by relation")
	}

	// CA should have incoming signed_by (issuer_of)
	caRels := index[caRef]
	foundIncoming := false
	for _, r := range caRels {
		if r.Type == RelationSignedBy && r.Direction == DirectionIncoming {
			foundIncoming = true
		}
	}
	if !foundIncoming {
		t.Fatal("CA should have incoming signed_by relation (issuer_of)")
	}
}

func TestDetectRelations_KeyCSRPair(t *testing.T) {
	key := mustGenerateRSAKey(t)
	csr := mustCreateCSR(t, key)

	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "test.key",
		Items:    []CertItem{{Type: ContentPrivateKey, PrivateKey: key}},
	})
	store.AddContainer(CertContainer{
		FilePath: "test.csr",
		Items:    []CertItem{{Type: ContentCSR, CSR: csr}},
	})

	relations := DetectRelations(store)
	found := false
	for _, r := range relations {
		if r.Type == RelationKeyCSR {
			if r.Source.FilePath == "test.key" && r.Target.FilePath == "test.csr" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected key_csr_pair relation")
	}
}

func TestDetectRelations_KeyCSRMismatch(t *testing.T) {
	rsaKey := mustGenerateRSAKey(t)
	ecKey := mustGenerateECKey(t)
	csr := mustCreateCSR(t, ecKey)

	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "rsa.key",
		Items:    []CertItem{{Type: ContentPrivateKey, PrivateKey: rsaKey}},
	})
	store.AddContainer(CertContainer{
		FilePath: "ec.csr",
		Items:    []CertItem{{Type: ContentCSR, CSR: csr}},
	})

	relations := DetectRelations(store)
	for _, r := range relations {
		if r.Type == RelationKeyCSR {
			t.Fatal("mismatched keys should not produce key_csr_pair relation")
		}
	}
}

func TestDetectRelations_CSRCertPair(t *testing.T) {
	key := mustGenerateRSAKey(t)
	csr := mustCreateCSR(t, key)
	cert, certDer := mustCreateSelfSignedCA(t, key)
	_ = cert

	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "test.csr",
		Items:    []CertItem{{Type: ContentCSR, CSR: csr}},
	})
	store.AddContainer(CertContainer{
		FilePath: "test.crt",
		Items:    []CertItem{{Type: ContentCertificate, Certificate: mustParseCert(t, certDer)}},
	})

	relations := DetectRelations(store)
	found := false
	for _, r := range relations {
		if r.Type == RelationCSRCert {
			if r.Source.FilePath == "test.csr" && r.Target.FilePath == "test.crt" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected csr_cert_pair relation")
	}
}

func TestDetectRelations_CSRCertMismatch(t *testing.T) {
	key1 := mustGenerateRSAKey(t)
	csr := mustCreateCSR(t, key1)

	key2 := mustGenerateRSAKey(t)
	_, certDer := mustCreateSelfSignedCA(t, key2)

	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "test.csr",
		Items:    []CertItem{{Type: ContentCSR, CSR: csr}},
	})
	store.AddContainer(CertContainer{
		FilePath: "test.crt",
		Items:    []CertItem{{Type: ContentCertificate, Certificate: mustParseCert(t, certDer)}},
	})

	relations := DetectRelations(store)
	for _, r := range relations {
		if r.Type == RelationCSRCert {
			t.Fatal("different keys should not produce csr_cert_pair relation")
		}
	}
}

func TestDetectRelations_FullLifecycle(t *testing.T) {
	key := mustGenerateRSAKey(t)
	csr := mustCreateCSR(t, key)
	_, certDer := mustCreateSelfSignedCA(t, key)

	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "test.key",
		Items:    []CertItem{{Type: ContentPrivateKey, PrivateKey: key}},
	})
	store.AddContainer(CertContainer{
		FilePath: "test.csr",
		Items:    []CertItem{{Type: ContentCSR, CSR: csr}},
	})
	store.AddContainer(CertContainer{
		FilePath: "test.crt",
		Items:    []CertItem{{Type: ContentCertificate, Certificate: mustParseCert(t, certDer)}},
	})

	relations := DetectRelations(store)
	foundKeyCert := false
	foundKeyCSR := false
	foundCSRCert := false
	for _, r := range relations {
		switch r.Type {
		case RelationKeyCert:
			foundKeyCert = true
		case RelationKeyCSR:
			foundKeyCSR = true
		case RelationCSRCert:
			foundCSRCert = true
		}
	}
	if !foundKeyCert {
		t.Fatal("expected key_cert_pair relation")
	}
	if !foundKeyCSR {
		t.Fatal("expected key_csr_pair relation")
	}
	if !foundCSRCert {
		t.Fatal("expected csr_cert_pair relation")
	}
}

func TestBuildRelationIndex_KeyCSRBidirectional(t *testing.T) {
	key := mustGenerateRSAKey(t)
	csr := mustCreateCSR(t, key)

	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "test.key",
		Items:    []CertItem{{Type: ContentPrivateKey, PrivateKey: key}},
	})
	store.AddContainer(CertContainer{
		FilePath: "test.csr",
		Items:    []CertItem{{Type: ContentCSR, CSR: csr}},
	})

	relations := DetectRelations(store)
	index := BuildRelationIndex(relations, store)

	keyRef := ItemRef{ContainerIdx: 0, ItemIdx: 0, FilePath: "test.key"}
	csrRef := ItemRef{ContainerIdx: 1, ItemIdx: 0, FilePath: "test.csr"}

	foundOutgoing := false
	for _, r := range index[keyRef] {
		if r.Type == RelationKeyCSR && r.Direction == DirectionOutgoing {
			foundOutgoing = true
		}
	}
	if !foundOutgoing {
		t.Fatal("key should have outgoing key_csr_pair relation")
	}

	foundIncoming := false
	for _, r := range index[csrRef] {
		if r.Type == RelationKeyCSR && r.Direction == DirectionIncoming {
			foundIncoming = true
		}
	}
	if !foundIncoming {
		t.Fatal("CSR should have incoming key_csr_pair relation")
	}
}

func TestAssembleChains_CircularPrevention(t *testing.T) {
	// Manually construct two certs and force circular signed_by relations
	key1 := mustGenerateRSAKey(t)
	_, der1 := mustCreateSelfSignedCA(t, key1)

	key2 := mustGenerateRSAKey(t)
	_, der2 := mustCreateSelfSignedCA(t, key2)

	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "a.crt",
		Items:    []CertItem{{Type: ContentCertificate, Certificate: mustParseCert(t, der1)}},
	})
	store.AddContainer(CertContainer{
		FilePath: "b.crt",
		Items:    []CertItem{{Type: ContentCertificate, Certificate: mustParseCert(t, der2)}},
	})

	refA := ItemRef{ContainerIdx: 0, ItemIdx: 0, FilePath: "a.crt"}
	refB := ItemRef{ContainerIdx: 1, ItemIdx: 0, FilePath: "b.crt"}

	// Manually create circular relations
	circularRelations := []CertRelation{
		{Type: RelationSignedBy, Source: refA, Target: refB},
		{Type: RelationSignedBy, Source: refB, Target: refA},
	}

	index := BuildRelationIndex(circularRelations, store)

	// AssembleChains should not infinite loop (visited set prevents it)
	// These are self-signed CAs so AssembleChains skips them, but the
	// important thing is it terminates without hanging.
	chains := AssembleChains(index, store)
	_ = chains
}

func TestAssembleChains_DuplicateRoot(t *testing.T) {
	rootKey := mustGenerateRSAKey(t)
	rootCert, rootDer := mustCreateSelfSignedCA(t, rootKey)

	intKey := mustGenerateRSAKey(t)
	intCert, intDer := mustCreateIntermediateCA(t, intKey, rootCert, rootKey)

	leafKey := mustGenerateRSAKey(t)
	_, leafDer := mustCreateLeafCert(t, leafKey, intCert, intKey)

	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "root.crt",
		Items:    []CertItem{{Type: ContentCertificate, Certificate: mustParseCert(t, rootDer)}},
	})
	store.AddContainer(CertContainer{
		FilePath: "int.crt",
		Items:    []CertItem{{Type: ContentCertificate, Certificate: mustParseCert(t, intDer)}},
	})
	store.AddContainer(CertContainer{
		FilePath: "leaf.crt",
		Items:    []CertItem{{Type: ContentCertificate, Certificate: mustParseCert(t, leafDer)}},
	})
	// Duplicate root in a separate container
	store.AddContainer(CertContainer{
		FilePath: "root_copy.crt",
		Items:    []CertItem{{Type: ContentCertificate, Certificate: mustParseCert(t, rootDer)}},
	})

	relations := DetectRelations(store)
	index := BuildRelationIndex(relations, store)
	chains := AssembleChains(index, store)

	leafRef := ItemRef{ContainerIdx: 2, ItemIdx: 0, FilePath: "leaf.crt"}
	chain, ok := chains[leafRef]
	if !ok {
		t.Fatal("expected chain starting from leaf")
	}
	if len(chain) != 3 {
		t.Fatalf("expected chain of length 3 (leaf+int+one root), got %d", len(chain))
	}
}

func mustParseCert(t interface {
	Helper()
	Fatal(...any)
}, der []byte) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// pemEncodeCert is a convenience for encoding DER to PEM (unused but available).
func pemEncodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
