//go:build fulltest

package certlib

import (
	"crypto"
	"crypto/dsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// --- Expiry checks ---

func TestCheck_Expired(t *testing.T) {
	tests := []struct {
		name      string
		item      func() *CertItem
		wantIssue bool
		checkDays bool
	}{
		{
			name: "expired yesterday",
			item: func() *CertItem {
				now := time.Now()
				return certWithExpiry(t, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
			},
			wantIssue: true,
		},
		{
			name: "expired 365 days ago",
			item: func() *CertItem {
				now := time.Now()
				return certWithExpiry(t, now.Add(-730*24*time.Hour), now.Add(-365*24*time.Hour))
			},
			wantIssue: true,
			checkDays: true,
		},
		{
			name: "valid cert with future NotAfter",
			item: func() *CertItem {
				now := time.Now()
				return certWithExpiry(t, now.Add(-24*time.Hour), now.Add(365*24*time.Hour))
			},
			wantIssue: false,
		},
		{
			name: "non-cert item (key)",
			item: func() *CertItem {
				return &CertItem{Type: ContentPrivateKey}
			},
			wantIssue: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			item := tt.item()
			container := containerWith(item)
			store := storeWith(container)
			issues := runCheck(t, "expired", container, item, store)

			if tt.wantIssue {
				assertIssue(t, issues, SeverityCritical, "expired")
				if tt.checkDays {
					if issues[0].Details == nil {
						t.Fatal("expected details with days_expired")
					}
					daysExpired, ok := issues[0].Details["days_expired"]
					if !ok {
						t.Fatal("expected days_expired in details")
					}
					if daysExpired.(int) < 364 {
						t.Errorf("expected days_expired >= 364, got %d", daysExpired.(int))
					}
				}
			} else {
				assertNoIssues(t, issues)
			}
		})
	}
}

func TestCheck_ExpiringSoonCritical(t *testing.T) {
	now := time.Now()

	t.Run("expires in exactly 7 days (critical threshold)", func(t *testing.T) {
		item := certWithExpiry(t, now.Add(-24*time.Hour), now.Add(time.Duration(DefaultExpiryCriticalDays)*24*time.Hour))
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "expiring_soon_critical", container, item, store)
		assertIssue(t, issues, SeverityCritical, "expiring_soon_critical")
	})

	t.Run("expires in 9 days (above critical)", func(t *testing.T) {
		// Use 9 days + buffer to ensure daysLeft computes > 7
		item := certWithExpiry(t, now.Add(-24*time.Hour), now.Add(9*24*time.Hour+time.Hour))
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "expiring_soon_critical", container, item, store)
		assertNoIssues(t, issues)
	})

	t.Run("expires in 31 days", func(t *testing.T) {
		item := certWithExpiry(t, now.Add(-24*time.Hour), now.Add(31*24*time.Hour+time.Hour))
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "expiring_soon_critical", container, item, store)
		assertNoIssues(t, issues)
	})
}

func TestCheck_ExpiringSoonWarning(t *testing.T) {
	now := time.Now()

	t.Run("expires in 9 days (within warning range)", func(t *testing.T) {
		// 9 days + buffer ensures daysLeft > 7 (critical) and <= 30 (warning)
		item := certWithExpiry(t, now.Add(-24*time.Hour), now.Add(9*24*time.Hour+time.Hour))
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "expiring_soon_warning", container, item, store)
		assertIssue(t, issues, SeverityWarning, "expiring_soon_warning")
	})

	t.Run("expires in 30 days (warning threshold)", func(t *testing.T) {
		item := certWithExpiry(t, now.Add(-24*time.Hour), now.Add(time.Duration(DefaultExpiryWarnDays)*24*time.Hour))
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "expiring_soon_warning", container, item, store)
		assertIssue(t, issues, SeverityWarning, "expiring_soon_warning")
	})

	t.Run("expires in 31 days (above warning)", func(t *testing.T) {
		// 31 days + buffer to ensure daysLeft > 30
		item := certWithExpiry(t, now.Add(-24*time.Hour), now.Add(31*24*time.Hour+time.Hour))
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "expiring_soon_warning", container, item, store)
		assertNoIssues(t, issues)
	})
}

func TestCheck_NotYetValid(t *testing.T) {
	tests := []struct {
		name      string
		notBefore time.Time
		wantIssue bool
	}{
		{"NotBefore is tomorrow", time.Now().Add(24 * time.Hour), true},
		{"already valid", time.Now().Add(-24 * time.Hour), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			item := certWithExpiry(t, tt.notBefore, time.Now().Add(365*24*time.Hour))
			container := containerWith(item)
			store := storeWith(container)
			issues := runCheck(t, "not_yet_valid", container, item, store)

			if tt.wantIssue {
				assertIssue(t, issues, SeverityWarning, "not_yet_valid")
			} else {
				assertNoIssues(t, issues)
			}
		})
	}
}

// --- Key strength checks ---

func TestCheck_VeryWeakRSA(t *testing.T) {
	tests := []struct {
		name      string
		bits      int
		wantIssue bool
	}{
		{"RSA 512-bit", 512, true},
		{"RSA 1023-bit (boundary)", 1023, true},
		{"RSA 1024-bit (no issue from this check)", 1024, false},
		{"RSA 2048-bit", 2048, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			item := mockRSACertItem(tt.bits)
			container := containerWith(item)
			store := storeWith(container)
			issues := runCheck(t, "very_weak_rsa", container, item, store)

			if tt.wantIssue {
				assertIssue(t, issues, SeverityCritical, "very_weak_rsa")
			} else {
				assertNoIssues(t, issues)
			}
		})
	}
}

func TestCheck_WeakRSA(t *testing.T) {
	tests := []struct {
		name      string
		bits      int
		wantIssue bool
	}{
		{"RSA 1024-bit", 1024, true},
		{"RSA 2047-bit (boundary)", 2047, true},
		{"RSA 2048-bit (no issue)", 2048, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			item := mockRSACertItem(tt.bits)
			container := containerWith(item)
			store := storeWith(container)
			issues := runCheck(t, "weak_rsa", container, item, store)

			if tt.wantIssue {
				assertIssue(t, issues, SeverityWarning, "weak_rsa")
			} else {
				assertNoIssues(t, issues)
			}
		})
	}
}

func TestCheck_WeakECCurve(t *testing.T) {
	tests := []struct {
		name      string
		curve     elliptic.Curve
		wantIssue bool
	}{
		{"P-224 (weak)", elliptic.P224(), true},
		{"P-256 (ok)", elliptic.P256(), false},
		{"P-384 (ok)", elliptic.P384(), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			item := mockECCertItem(tt.curve)
			container := containerWith(item)
			store := storeWith(container)
			issues := runCheck(t, "weak_ec_curve", container, item, store)

			if tt.wantIssue {
				assertIssue(t, issues, SeverityWarning, "weak_ec_curve")
			} else {
				assertNoIssues(t, issues)
			}
		})
	}
}

func TestCheck_RSAExponent(t *testing.T) {
	mockRSACertItemWithExponent := func(bits, exponent int) *CertItem {
		n := new(big.Int).Lsh(big.NewInt(1), uint(bits)-1)
		pub := &rsa.PublicKey{N: n, E: exponent}
		cert := &x509.Certificate{
			PublicKey:             pub,
			PublicKeyAlgorithm:    x509.RSA,
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "mock-rsa-exp"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			BasicConstraintsValid: true,
		}
		return &CertItem{Type: ContentCertificate, Certificate: cert}
	}

	tests := []struct {
		name      string
		exponent  int
		wantIssue bool
	}{
		{"exponent 3 (weak)", 3, true},
		{"exponent 65537 (standard)", 65537, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			item := mockRSACertItemWithExponent(2048, tt.exponent)
			container := containerWith(item)
			store := storeWith(container)
			issues := runCheck(t, "rsa_exponent", container, item, store)

			if tt.wantIssue {
				assertIssue(t, issues, SeverityWarning, "rsa_exponent")
			} else {
				assertNoIssues(t, issues)
			}
		})
	}
}

// --- Config checks ---

func TestCheck_UnprotectedKey(t *testing.T) {
	t.Run("private key in PEM not encrypted", func(t *testing.T) {
		item := &CertItem{Type: ContentPrivateKey, Encrypted: false}
		container := &CertContainer{
			FilePath: "/test/key.pem",
			Format:   FormatPEM,
			Items:    []CertItem{*item},
		}
		store := storeWith(container)
		issues := runCheck(t, "unprotected_key", container, item, store)
		assertIssue(t, issues, SeverityInfo, "unprotected_key")
	})

	t.Run("key in PKCS12 container", func(t *testing.T) {
		item := &CertItem{Type: ContentPrivateKey, Encrypted: false}
		container := &CertContainer{
			FilePath: "/test/store.p12",
			Format:   FormatPKCS12,
			Items:    []CertItem{*item},
		}
		store := storeWith(container)
		issues := runCheck(t, "unprotected_key", container, item, store)
		assertNoIssues(t, issues)
	})
}

func TestCheck_EmptyPassword(t *testing.T) {
	t.Run("container with empty password", func(t *testing.T) {
		item := &CertItem{Type: ContentPrivateKey}
		container := &CertContainer{
			FilePath: "/test/key.pem",
			Format:   FormatPEM,
			Password: []byte{},
			Items:    []CertItem{*item},
		}
		store := storeWith(container)
		issues := runCheck(t, "empty_password", container, item, store)
		assertIssue(t, issues, SeverityInfo, "empty_password")
	})

	t.Run("container with nil password", func(t *testing.T) {
		item := &CertItem{Type: ContentPrivateKey}
		container := &CertContainer{
			FilePath: "/test/key.pem",
			Format:   FormatPEM,
			Password: nil,
			Items:    []CertItem{*item},
		}
		store := storeWith(container)
		issues := runCheck(t, "empty_password", container, item, store)
		assertNoIssues(t, issues)
	})

	t.Run("container with non-empty password", func(t *testing.T) {
		item := &CertItem{Type: ContentPrivateKey}
		container := &CertContainer{
			FilePath: "/test/key.pem",
			Format:   FormatPEM,
			Password: []byte("secret"),
			Items:    []CertItem{*item},
		}
		store := storeWith(container)
		issues := runCheck(t, "empty_password", container, item, store)
		assertNoIssues(t, issues)
	})
}

func TestCheck_MissingSANs(t *testing.T) {
	t.Run("cert with CN but no SANs", func(t *testing.T) {
		item := certWithSANs(t, nil, nil)
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "missing_sans", container, item, store)
		assertIssue(t, issues, SeverityInfo, "missing_sans")
	})

	t.Run("cert with CN and DNS SANs", func(t *testing.T) {
		item := certWithSANs(t, []string{"example.com"}, nil)
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "missing_sans", container, item, store)
		assertNoIssues(t, issues)
	})

	t.Run("CA without SANs is normal, not flagged", func(t *testing.T) {
		item := certWithKeyUsage(t, true, x509.KeyUsageCertSign, nil)
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "missing_sans", container, item, store)
		assertNoIssues(t, issues)
	})
}

func TestCheck_CANoKeyUsage(t *testing.T) {
	t.Run("CA cert without keyCertSign", func(t *testing.T) {
		item := certWithKeyUsage(t, true, x509.KeyUsageDigitalSignature, nil)
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "ca_no_keyusage", container, item, store)
		assertIssue(t, issues, SeverityWarning, "ca_no_keyusage")
	})

	t.Run("CA cert with keyCertSign", func(t *testing.T) {
		item := certWithKeyUsage(t, true, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, nil)
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "ca_no_keyusage", container, item, store)
		assertNoIssues(t, issues)
	})

	t.Run("non-CA cert not triggered", func(t *testing.T) {
		item := certWithKeyUsage(t, false, x509.KeyUsageDigitalSignature, nil)
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "ca_no_keyusage", container, item, store)
		assertNoIssues(t, issues)
	})
}

// --- Chain checks ---

func TestCheck_ChainIncomplete(t *testing.T) {
	t.Run("non-self-signed cert with no signed_by relation", func(t *testing.T) {
		rootKey := mustGenerateECKey(t)
		leafKey := mustGenerateECKey(t)
		rootCert, _ := mustCreateSelfSignedCA(t, rootKey)
		leafCert, _ := mustCreateLeafCert(t, leafKey, rootCert, rootKey)

		item := &CertItem{Type: ContentCertificate, Certificate: leafCert}
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "chain_incomplete", container, item, store)
		assertIssue(t, issues, SeverityWarning, "chain_incomplete")
	})

	t.Run("self-signed cert (skipped)", func(t *testing.T) {
		key := mustGenerateECKey(t)
		cert, _ := mustCreateSelfSignedCA(t, key)

		item := &CertItem{Type: ContentCertificate, Certificate: cert}
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "chain_incomplete", container, item, store)
		assertNoIssues(t, issues)
	})

	t.Run("non-self-signed cert not trusted by system returns WARNING", func(t *testing.T) {
		// A leaf cert signed by a test CA that is NOT in the system root store
		// should still produce a WARNING (not downgraded to INFO).
		rootKey := mustGenerateECKey(t)
		leafKey := mustGenerateECKey(t)
		rootCert, _ := mustCreateSelfSignedCA(t, rootKey)
		leafCert, _ := mustCreateLeafCert(t, leafKey, rootCert, rootKey)

		item := &CertItem{Type: ContentCertificate, Certificate: leafCert}
		container := &CertContainer{
			FilePath: "/test/untrusted-chain-test.pem",
			Format:   FormatPEM,
			Items:    []CertItem{*item},
		}
		store := storeWith(container)
		issues := runCheck(t, "chain_incomplete", container, item, store)
		assertIssue(t, issues, SeverityWarning, "chain_incomplete")
	})

	// The platform-verifier helpers these sub-tests pinned were removed in M31
	// WP3; chain_incomplete now follows the trust index only, covered by
	// TestChainIncompleteFollowsTheTrustIndex.

	t.Run("cert with signed_by relation", func(t *testing.T) {
		rootKey := mustGenerateECKey(t)
		leafKey := mustGenerateECKey(t)
		rootCert, _ := mustCreateSelfSignedCA(t, rootKey)
		leafCert, _ := mustCreateLeafCert(t, leafKey, rootCert, rootKey)

		leafItem := &CertItem{Type: ContentCertificate, Certificate: leafCert}
		rootItem := &CertItem{Type: ContentCertificate, Certificate: rootCert}
		container := &CertContainer{
			FilePath: "/test/chain.pem",
			Format:   FormatPEM,
			Items:    []CertItem{*leafItem, *rootItem},
		}
		store := storeWith(container)
		leafRef := ItemRef{ContainerIdx: 0, ItemIdx: 0, FilePath: container.FilePath}
		rootRef := ItemRef{ContainerIdx: 0, ItemIdx: 1, FilePath: container.FilePath}
		store.Relations = append(store.Relations, CertRelation{
			Type:   RelationSignedBy,
			Source: leafRef,
			Target: rootRef,
		})
		relIndex := BuildRelationIndex(store.Relations, store)

		opts := CheckOptions{}.Defaults()
		var found bool
		for _, def := range allChecks {
			if def.ID == "chain_incomplete" {
				issues := def.check(container, leafItem, leafRef, opts, relIndex, store)
				if len(issues) == 0 {
					found = true
				}
				break
			}
		}
		if !found {
			t.Error("expected no issues for cert with signed_by relation")
		}
	})
}

// mkPathLenCA builds a CA cert. pathLen < 0 leaves the constraint absent
// (unlimited); pathLen >= 0 sets MaxPathLen (and MaxPathLenZero for 0).
// parent==nil produces a self-signed CA.
func mkPathLenCA(t *testing.T, cn string, pathLen int, parent *x509.Certificate, parentKey crypto.PrivateKey) (*x509.Certificate, crypto.PrivateKey) {
	t.Helper()
	key := mustGenerateECKey(t)
	now := time.Now()
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now,
		NotAfter:              now.Add(3650 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	if pathLen >= 0 {
		tmpl.MaxPathLen = pathLen
		tmpl.MaxPathLenZero = pathLen == 0
	}
	signerCert, signerKey := tmpl, crypto.PrivateKey(key)
	if parent != nil {
		signerCert, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, key.Public(), signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// runPathLengthCheck assembles a store from certs and signed-by edges (child ->
// issuer index pairs) and runs the path_length check against certs[targetIdx].
func runPathLengthCheck(t *testing.T, certs []*x509.Certificate, edges [][2]int, targetIdx int) []CheckIssue {
	t.Helper()
	container := &CertContainer{FilePath: "/test/chain.pem", Format: FormatPEM}
	for _, cert := range certs {
		container.Items = append(container.Items, CertItem{Type: ContentCertificate, Certificate: cert})
	}
	store := storeWith(container)
	ref := func(i int) ItemRef {
		return ItemRef{ContainerIdx: 0, ItemIdx: i, FilePath: container.FilePath}
	}
	for _, e := range edges {
		store.Relations = append(store.Relations, CertRelation{
			Type:   RelationSignedBy,
			Source: ref(e[0]),
			Target: ref(e[1]),
		})
	}
	relIndex := BuildRelationIndex(store.Relations, store)
	opts := CheckOptions{}.Defaults()
	for _, def := range allChecks {
		if def.ID == "path_length_violation" {
			return def.check(&store.Containers[0], &store.Containers[0].Items[targetIdx], ref(targetIdx), opts, relIndex, store)
		}
	}
	t.Fatal("path_length_violation check not found")
	return nil
}

func TestCheck_PathLength(t *testing.T) {
	// The check fires on the CA that sits too deep, naming the ancestor whose
	// constraint it breaks (path_length was folded into path_length_violation).
	t.Run("legal wide CA signs multiple leaves", func(t *testing.T) {
		root, rootKey := mkPathLenCA(t, "Root", 0, nil, nil)
		leaf1, _ := mustCreateLeafCert(t, mustGenerateECKey(t), root, rootKey)
		leaf2, _ := mustCreateLeafCert(t, mustGenerateECKey(t), root, rootKey)
		leaf3, _ := mustCreateLeafCert(t, mustGenerateECKey(t), root, rootKey)
		certs := []*x509.Certificate{root, leaf1, leaf2, leaf3}
		edges := [][2]int{{1, 0}, {2, 0}, {3, 0}}
		issues := runPathLengthCheck(t, certs, edges, 0)
		assertNoIssues(t, issues)
	})

	t.Run("pathLen=0 CA signs intermediate CA violates", func(t *testing.T) {
		root, rootKey := mkPathLenCA(t, "Root", 0, nil, nil)
		inter, interKey := mkPathLenCA(t, "Intermediate", -1, root, rootKey)
		leaf, _ := mustCreateLeafCert(t, mustGenerateECKey(t), inter, interKey)
		certs := []*x509.Certificate{root, inter, leaf}
		edges := [][2]int{{1, 0}, {2, 1}}
		issues := runPathLengthCheck(t, certs, edges, 1)
		assertIssue(t, issues, SeverityCritical, "path_length_violation")
	})

	t.Run("pathLen=1 with one intermediate below is OK", func(t *testing.T) {
		root, rootKey := mkPathLenCA(t, "Root", 1, nil, nil)
		inter, interKey := mkPathLenCA(t, "Intermediate", -1, root, rootKey)
		leaf, _ := mustCreateLeafCert(t, mustGenerateECKey(t), inter, interKey)
		certs := []*x509.Certificate{root, inter, leaf}
		edges := [][2]int{{1, 0}, {2, 1}}
		issues := runPathLengthCheck(t, certs, edges, 1)
		assertNoIssues(t, issues)
	})

	t.Run("pathLen=1 with two chained intermediates below violates on the second", func(t *testing.T) {
		root, rootKey := mkPathLenCA(t, "Root", 1, nil, nil)
		interA, interAKey := mkPathLenCA(t, "InterA", -1, root, rootKey)
		interB, interBKey := mkPathLenCA(t, "InterB", -1, interA, interAKey)
		leaf, _ := mustCreateLeafCert(t, mustGenerateECKey(t), interB, interBKey)
		certs := []*x509.Certificate{root, interA, interB, leaf}
		edges := [][2]int{{1, 0}, {2, 1}, {3, 2}}
		assertNoIssues(t, runPathLengthCheck(t, certs, edges, 1))
		assertIssue(t, runPathLengthCheck(t, certs, edges, 2), SeverityCritical, "path_length_violation")
	})

	t.Run("unlimited CA never flagged regardless of depth", func(t *testing.T) {
		root, rootKey := mkPathLenCA(t, "Root", -1, nil, nil)
		interA, interAKey := mkPathLenCA(t, "InterA", -1, root, rootKey)
		interB, interBKey := mkPathLenCA(t, "InterB", -1, interA, interAKey)
		leaf, _ := mustCreateLeafCert(t, mustGenerateECKey(t), interB, interBKey)
		certs := []*x509.Certificate{root, interA, interB, leaf}
		edges := [][2]int{{1, 0}, {2, 1}, {3, 2}}
		assertNoIssues(t, runPathLengthCheck(t, certs, edges, 2))
	})

	t.Run("CA without ancestors no issue", func(t *testing.T) {
		key := mustGenerateECKey(t)
		cert, _ := mustCreateSelfSignedCA(t, key)

		item := &CertItem{Type: ContentCertificate, Certificate: cert}
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "path_length_violation", container, item, store)
		assertNoIssues(t, issues)
	})
}

// --- Structure checks ---

func TestCheck_Serial(t *testing.T) {
	t.Run("serial zero", func(t *testing.T) {
		item := certWithSerial(t, big.NewInt(0))
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "serial", container, item, store)
		assertIssue(t, issues, SeverityWarning, "serial")
	})

	t.Run("serial negative", func(t *testing.T) {
		// x509.CreateCertificate rejects negative serials, so we construct directly
		cert := &x509.Certificate{
			SerialNumber:          big.NewInt(-1),
			Subject:               pkix.Name{CommonName: "neg-serial"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			BasicConstraintsValid: true,
		}
		item := &CertItem{Type: ContentCertificate, Certificate: cert}
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "serial", container, item, store)
		assertIssue(t, issues, SeverityWarning, "serial")
	})

	t.Run("serial positive", func(t *testing.T) {
		item := certWithSerial(t, big.NewInt(1))
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "serial", container, item, store)
		assertNoIssues(t, issues)
	})
}

func TestCheck_LongValidity(t *testing.T) {
	now := time.Now()
	limit, _ := LeafValidityLimit(now)

	t.Run("leaf cert one day over the current limit", func(t *testing.T) {
		item := certWithExpiry(t, now, now.Add(time.Duration(limit+1)*24*time.Hour))
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "long_validity", container, item, store)
		assertIssue(t, issues, SeverityInfo, "long_validity")
	})

	t.Run("leaf cert exactly at the current limit", func(t *testing.T) {
		item := certWithExpiry(t, now, now.Add(time.Duration(limit)*24*time.Hour))
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "long_validity", container, item, store)
		assertNoIssues(t, issues)
	})

	t.Run("half a day over is flagged via ceiling", func(t *testing.T) {
		item := certWithExpiry(t, now, now.Add(time.Duration(limit)*24*time.Hour+12*time.Hour))
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "long_validity", container, item, store)
		assertIssue(t, issues, SeverityInfo, "long_validity")
	})

	t.Run("a certificate issued under the 398-day rule keeps that limit", func(t *testing.T) {
		issued := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
		item := certWithExpiry(t, issued, issued.Add(398*24*time.Hour))
		container := containerWith(item)
		store := storeWith(container)
		assertNoIssues(t, runCheck(t, "long_validity", container, item, store))
		item = certWithExpiry(t, issued, issued.Add(399*24*time.Hour))
		container = containerWith(item)
		store = storeWith(container)
		assertIssue(t, runCheck(t, "long_validity", container, item, store), SeverityInfo, "long_validity")
	})

	t.Run("CA cert over the limit no issue", func(t *testing.T) {
		item := certWithKeyUsage(t, true, x509.KeyUsageCertSign, nil)
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "long_validity", container, item, store)
		assertNoIssues(t, issues)
	})
}

func TestCheck_SelfSignedLeaf(t *testing.T) {
	t.Run("non-CA self-signed", func(t *testing.T) {
		now := time.Now()
		item := certWithExpiry(t, now.Add(-time.Hour), now.Add(365*24*time.Hour))
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "self_signed_leaf", container, item, store)
		assertIssue(t, issues, SeverityInfo, "self_signed_leaf")
	})

	t.Run("CA self-signed no issue", func(t *testing.T) {
		item := certWithKeyUsage(t, true, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, nil)
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "self_signed_leaf", container, item, store)
		assertNoIssues(t, issues)
	})
}

func TestCheck_Wildcard(t *testing.T) {
	t.Run("cert with wildcard", func(t *testing.T) {
		item := certWithSANs(t, []string{"*.example.com"}, nil)
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "wildcard", container, item, store)
		assertIssue(t, issues, SeverityInfo, "wildcard")
	})

	t.Run("cert without wildcard", func(t *testing.T) {
		item := certWithSANs(t, []string{"example.com"}, nil)
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "wildcard", container, item, store)
		assertNoIssues(t, issues)
	})
}

// --- Multi-issue and edge case checks ---

func TestCheck_MultipleSimultaneousIssues(t *testing.T) {
	// A cert that triggers multiple checks simultaneously.
	// Verifies that RunChecks accumulates ALL issues, not short-circuiting.
	now := time.Now()

	// Expired + weak RSA 512-bit + self-signed leaf (no SANs, has CN)
	item := certWithExpiry(t, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	item.Certificate.PublicKey = &rsa.PublicKey{
		N: new(big.Int).Lsh(big.NewInt(1), 511),
		E: 65537,
	}

	container := containerWith(item)
	store := storeWith(container)
	relIndex := BuildRelationIndex(store.Relations, store)

	result := RunChecks(store, relIndex, CheckOptions{})

	// Should have at least: expired (CRITICAL), very_weak_rsa (CRITICAL),
	// self_signed_leaf (INFO), missing_sans (INFO)
	foundChecks := make(map[string]bool)
	for _, issue := range result.Issues {
		foundChecks[issue.CheckID] = true
	}

	for _, expected := range []string{"expired", "very_weak_rsa", "self_signed_leaf", "missing_sans"} {
		if !foundChecks[expected] {
			t.Errorf("expected check %q to fire, but it was missing. Got checks: %v", expected, foundChecks)
		}
	}

	if len(result.Issues) < 4 {
		t.Errorf("expected at least 4 issues, got %d", len(result.Issues))
	}
}

func TestCheck_ImpossibleValidityWindow(t *testing.T) {
	// NotBefore in the future AND NotAfter in the past.
	// Both "not_yet_valid" and "expired" should fire.
	now := time.Now()

	// Craft directly since x509.CreateCertificate won't reject this
	item := certWithExpiry(t, now.Add(24*time.Hour), now.Add(-24*time.Hour))

	container := containerWith(item)
	store := storeWith(container)

	expiredIssues := runCheck(t, "expired", container, item, store)
	assertIssue(t, expiredIssues, SeverityCritical, "expired")

	notYetValidIssues := runCheck(t, "not_yet_valid", container, item, store)
	assertIssue(t, notYetValidIssues, SeverityWarning, "not_yet_valid")
}

// --- RunChecks integration ---

func TestRunChecks_Integration(t *testing.T) {
	now := time.Now()

	// Expired cert with weak RSA key
	expiredItem := certWithExpiry(t, now.Add(-730*24*time.Hour), now.Add(-24*time.Hour))
	expiredItem.Certificate.PublicKey = &rsa.PublicKey{
		N: new(big.Int).Lsh(big.NewInt(1), 511),
		E: 65537,
	}

	container := containerWith(expiredItem)
	store := storeWith(container)
	relIndex := BuildRelationIndex(store.Relations, store)

	result := RunChecks(store, relIndex, CheckOptions{})

	if len(result.Issues) == 0 {
		t.Fatal("expected issues for expired + weak cert")
	}

	hasCritical := false
	for _, issue := range result.Issues {
		if issue.Severity == SeverityCritical {
			hasCritical = true
			break
		}
	}
	if !hasCritical {
		t.Error("expected at least one CRITICAL issue")
	}

	if result.Summary.Critical == 0 {
		t.Error("expected Summary.Critical > 0")
	}
	if result.FilesScanned != 1 {
		t.Errorf("expected FilesScanned=1, got %d", result.FilesScanned)
	}
}

func TestRunChecks_MinSeverity(t *testing.T) {
	now := time.Now()

	// Create a cert that triggers both INFO and CRITICAL issues:
	// - expired (CRITICAL)
	// - self_signed_leaf (INFO)
	item := certWithExpiry(t, now.Add(-48*time.Hour), now.Add(-24*time.Hour))

	container := containerWith(item)
	store := storeWith(container)
	relIndex := BuildRelationIndex(store.Relations, store)

	result := RunChecks(store, relIndex, CheckOptions{
		MinSeverity: SeverityCritical,
	})

	for _, issue := range result.Issues {
		if issue.Severity != SeverityCritical {
			t.Errorf("expected only CRITICAL issues with MinSeverity=critical, got %s (%s)", issue.Severity, issue.CheckID)
		}
	}
}

func TestRunChecks_EmptyStore(t *testing.T) {
	store := NewCertStore()
	relIndex := BuildRelationIndex(store.Relations, store)

	result := RunChecks(store, relIndex, CheckOptions{})

	if len(result.Issues) != 0 {
		t.Errorf("expected no issues for empty store, got %d", len(result.Issues))
	}
	if result.FilesScanned != 0 {
		t.Errorf("expected FilesScanned=0, got %d", result.FilesScanned)
	}
}

// ---------------------------------------------------------------------------
// Remaining 12 untested checker checks
// ---------------------------------------------------------------------------

// --- Algorithm checks ---

func TestCheck_MD5Sig(t *testing.T) {
	t.Run("MD5WithRSA", func(t *testing.T) {
		cert := &x509.Certificate{
			SignatureAlgorithm:    x509.MD5WithRSA,
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "md5-test"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			BasicConstraintsValid: true,
		}
		item := &CertItem{Type: ContentCertificate, Certificate: cert}
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "md5_sig", container, item, store)
		assertIssue(t, issues, SeverityCritical, "md5_sig")
	})

	t.Run("MD2WithRSA", func(t *testing.T) {
		cert := &x509.Certificate{
			SignatureAlgorithm:    x509.MD2WithRSA,
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "md2-test"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			BasicConstraintsValid: true,
		}
		item := &CertItem{Type: ContentCertificate, Certificate: cert}
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "md5_sig", container, item, store)
		assertIssue(t, issues, SeverityCritical, "md5_sig")
	})

	t.Run("SHA256WithRSA no issue", func(t *testing.T) {
		cert := &x509.Certificate{
			SignatureAlgorithm:    x509.SHA256WithRSA,
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "sha256-test"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			BasicConstraintsValid: true,
		}
		item := &CertItem{Type: ContentCertificate, Certificate: cert}
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "md5_sig", container, item, store)
		assertNoIssues(t, issues)
	})

	t.Run("non-cert item", func(t *testing.T) {
		item := &CertItem{Type: ContentPrivateKey}
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "md5_sig", container, item, store)
		assertNoIssues(t, issues)
	})
}

func TestCheck_SHA1Sig(t *testing.T) {
	t.Run("SHA1WithRSA", func(t *testing.T) {
		cert := &x509.Certificate{
			SignatureAlgorithm:    x509.SHA1WithRSA,
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "sha1-test"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			BasicConstraintsValid: true,
		}
		item := &CertItem{Type: ContentCertificate, Certificate: cert}
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "sha1_sig", container, item, store)
		assertIssue(t, issues, SeverityWarning, "sha1_sig")
	})

	t.Run("ECDSAWithSHA1", func(t *testing.T) {
		cert := &x509.Certificate{
			SignatureAlgorithm:    x509.ECDSAWithSHA1,
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "ecdsa-sha1-test"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			BasicConstraintsValid: true,
		}
		item := &CertItem{Type: ContentCertificate, Certificate: cert}
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "sha1_sig", container, item, store)
		assertIssue(t, issues, SeverityWarning, "sha1_sig")
	})

	t.Run("SHA256WithRSA no issue", func(t *testing.T) {
		cert := &x509.Certificate{
			SignatureAlgorithm:    x509.SHA256WithRSA,
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "sha256-test"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			BasicConstraintsValid: true,
		}
		item := &CertItem{Type: ContentCertificate, Certificate: cert}
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "sha1_sig", container, item, store)
		assertNoIssues(t, issues)
	})
}

func TestCheck_SigMismatch(t *testing.T) {
	t.Run("normal cert no mismatch", func(t *testing.T) {
		// A real cert always has matching outer and TBS signature algorithms.
		key := mustGenerateECKey(t)
		cert, _ := mustCreateSelfSignedCA(t, key)

		item := &CertItem{Type: ContentCertificate, Certificate: cert, RawBytes: cert.Raw}
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "sig_mismatch", container, item, store)
		assertNoIssues(t, issues)
	})

	t.Run("nil cert", func(t *testing.T) {
		item := &CertItem{Type: ContentCertificate, Certificate: nil}
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "sig_mismatch", container, item, store)
		assertNoIssues(t, issues)
	})

	t.Run("empty raw bytes", func(t *testing.T) {
		cert := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "test"},
			BasicConstraintsValid: true,
		}
		item := &CertItem{Type: ContentCertificate, Certificate: cert}
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "sig_mismatch", container, item, store)
		assertNoIssues(t, issues)
	})
}

// --- Key strength checks ---

func TestCheck_DeprecatedKey(t *testing.T) {
	t.Run("DSA public key in cert", func(t *testing.T) {
		cert := &x509.Certificate{
			PublicKey:             &dsa.PublicKey{},
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "dsa-test"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			BasicConstraintsValid: true,
		}
		item := &CertItem{Type: ContentCertificate, Certificate: cert}
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "deprecated_key", container, item, store)
		assertIssue(t, issues, SeverityWarning, "deprecated_key")
	})

	t.Run("RSA key no issue", func(t *testing.T) {
		item := mockRSACertItem(2048)
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "deprecated_key", container, item, store)
		assertNoIssues(t, issues)
	})

	t.Run("ECDSA key no issue", func(t *testing.T) {
		item := mockECCertItem(elliptic.P256())
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "deprecated_key", container, item, store)
		assertNoIssues(t, issues)
	})

	t.Run("non-cert item", func(t *testing.T) {
		item := &CertItem{Type: ContentPrivateKey}
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "deprecated_key", container, item, store)
		assertNoIssues(t, issues)
	})
}

// --- Config checks ---

func TestCheck_CANoBC(t *testing.T) {
	t.Run("keyCertSign but no BasicConstraints", func(t *testing.T) {
		cert := &x509.Certificate{
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: false,
			IsCA:                  false,
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "no-bc-test"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		}
		item := &CertItem{Type: ContentCertificate, Certificate: cert}
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "ca_no_bc", container, item, store)
		assertIssue(t, issues, SeverityWarning, "ca_no_bc")
	})

	t.Run("keyCertSign with BasicConstraints", func(t *testing.T) {
		item := certWithKeyUsage(t, true, x509.KeyUsageCertSign, nil)
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "ca_no_bc", container, item, store)
		assertNoIssues(t, issues)
	})

	t.Run("no keyCertSign", func(t *testing.T) {
		item := certWithKeyUsage(t, false, x509.KeyUsageDigitalSignature, nil)
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "ca_no_bc", container, item, store)
		assertNoIssues(t, issues)
	})
}

func TestCheck_LeafCertSign(t *testing.T) {
	t.Run("non-CA with keyCertSign", func(t *testing.T) {
		cert := &x509.Certificate{
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  false,
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "leaf-certsign"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		}
		item := &CertItem{Type: ContentCertificate, Certificate: cert}
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "leaf_certsign", container, item, store)
		assertIssue(t, issues, SeverityWarning, "leaf_certsign")
	})

	t.Run("CA with keyCertSign no issue", func(t *testing.T) {
		item := certWithKeyUsage(t, true, x509.KeyUsageCertSign, nil)
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "leaf_certsign", container, item, store)
		assertNoIssues(t, issues)
	})

	t.Run("non-CA without keyCertSign no issue", func(t *testing.T) {
		item := certWithKeyUsage(t, false, x509.KeyUsageDigitalSignature, nil)
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "leaf_certsign", container, item, store)
		assertNoIssues(t, issues)
	})
}

func TestCheck_IPInCN(t *testing.T) {
	t.Run("IP in CN no IP SAN", func(t *testing.T) {
		key := mustGenerateECKey(t)
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		template := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: "192.168.1.1"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		item := &CertItem{Type: ContentCertificate, Certificate: cert}
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "ip_in_cn", container, item, store)
		assertIssue(t, issues, SeverityInfo, "ip_in_cn")
	})

	t.Run("IP in CN with matching IP SAN", func(t *testing.T) {
		key := mustGenerateECKey(t)
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		template := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: "192.168.1.1"},
			IPAddresses:           []net.IP{net.ParseIP("192.168.1.1")},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		item := &CertItem{Type: ContentCertificate, Certificate: cert}
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "ip_in_cn", container, item, store)
		assertNoIssues(t, issues)
	})

	t.Run("hostname in CN no issue", func(t *testing.T) {
		item := certWithSANs(t, nil, nil)
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "ip_in_cn", container, item, store)
		assertNoIssues(t, issues)
	})

	t.Run("empty CN", func(t *testing.T) {
		cert := &x509.Certificate{
			Subject:               pkix.Name{},
			SerialNumber:          big.NewInt(1),
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			BasicConstraintsValid: true,
		}
		item := &CertItem{Type: ContentCertificate, Certificate: cert}
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "ip_in_cn", container, item, store)
		assertNoIssues(t, issues)
	})
}

func TestCheck_EntryPasswordMismatch(t *testing.T) {
	t.Run("different entry password", func(t *testing.T) {
		item := &CertItem{
			Type:          ContentPrivateKey,
			Alias:         "my-key",
			EntryPassword: []byte("entry-pass"),
		}
		container := &CertContainer{
			FilePath: "/test/store.jks",
			Format:   FormatJKS,
			Password: []byte("store-pass"),
			Items:    []CertItem{*item},
		}
		store := storeWith(container)
		issues := runCheck(t, "entry_password_mismatch", container, item, store)
		assertIssue(t, issues, SeverityInfo, "entry_password_mismatch")
	})

	t.Run("same password no issue", func(t *testing.T) {
		item := &CertItem{
			Type:          ContentPrivateKey,
			Alias:         "my-key",
			EntryPassword: []byte("same-pass"),
		}
		container := &CertContainer{
			FilePath: "/test/store.jks",
			Format:   FormatJKS,
			Password: []byte("same-pass"),
			Items:    []CertItem{*item},
		}
		store := storeWith(container)
		issues := runCheck(t, "entry_password_mismatch", container, item, store)
		assertNoIssues(t, issues)
	})

	t.Run("nil entry password no issue", func(t *testing.T) {
		item := &CertItem{
			Type:  ContentPrivateKey,
			Alias: "my-key",
		}
		container := &CertContainer{
			FilePath: "/test/store.jks",
			Format:   FormatJKS,
			Password: []byte("store-pass"),
			Items:    []CertItem{*item},
		}
		store := storeWith(container)
		issues := runCheck(t, "entry_password_mismatch", container, item, store)
		assertNoIssues(t, issues)
	})

	t.Run("non-key item no issue", func(t *testing.T) {
		item := &CertItem{
			Type:          ContentCertificate,
			EntryPassword: []byte("different"),
		}
		container := &CertContainer{
			FilePath: "/test/store.jks",
			Format:   FormatJKS,
			Password: []byte("store-pass"),
			Items:    []CertItem{*item},
		}
		store := storeWith(container)
		issues := runCheck(t, "entry_password_mismatch", container, item, store)
		assertNoIssues(t, issues)
	})
}

// --- Chain checks ---

func TestCheck_ChainOrder(t *testing.T) {
	t.Run("intermediate CA first leaf second", func(t *testing.T) {
		rootKey := mustGenerateECKey(t)
		rootCert, _ := mustCreateSelfSignedCA(t, rootKey)

		intKey := mustGenerateECKey(t)
		intCert, _ := mustCreateIntermediateCA(t, intKey, rootCert, rootKey)

		leafKey := mustGenerateECKey(t)
		leafCert, _ := mustCreateLeafCert(t, leafKey, intCert, intKey)

		// Wrong order: intermediate first, leaf second
		intItem := &CertItem{Type: ContentCertificate, Certificate: intCert}
		leafItem := &CertItem{Type: ContentCertificate, Certificate: leafCert}
		container := &CertContainer{
			FilePath: "/test/chain.pem",
			Format:   FormatPEM,
			Items:    []CertItem{*intItem, *leafItem},
		}
		store := storeWith(container)

		ref := ItemRef{ContainerIdx: 0, ItemIdx: 0}
		opts := CheckOptions{}.Defaults()
		relIndex := BuildRelationIndex(store.Relations, store)

		var issues []CheckIssue
		for _, def := range allChecks {
			if def.ID == "chain_order" {
				issues = def.check(container, intItem, ref, opts, relIndex, store)
				break
			}
		}
		assertIssue(t, issues, SeverityInfo, "chain_order")
	})

	t.Run("leaf first correct order", func(t *testing.T) {
		rootKey := mustGenerateECKey(t)
		rootCert, _ := mustCreateSelfSignedCA(t, rootKey)

		leafKey := mustGenerateECKey(t)
		leafCert, _ := mustCreateLeafCert(t, leafKey, rootCert, rootKey)

		leafItem := &CertItem{Type: ContentCertificate, Certificate: leafCert}
		rootItem := &CertItem{Type: ContentCertificate, Certificate: rootCert}
		container := &CertContainer{
			FilePath: "/test/chain.pem",
			Format:   FormatPEM,
			Items:    []CertItem{*leafItem, *rootItem},
		}
		store := storeWith(container)
		issues := runCheck(t, "chain_order", container, leafItem, store)
		assertNoIssues(t, issues)
	})

	t.Run("single cert no issue", func(t *testing.T) {
		item := certWithSANs(t, []string{"example.com"}, nil)
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "chain_order", container, item, store)
		assertNoIssues(t, issues)
	})

	t.Run("non-PEM format no issue", func(t *testing.T) {
		rootKey := mustGenerateECKey(t)
		rootCert, _ := mustCreateSelfSignedCA(t, rootKey)

		intKey := mustGenerateECKey(t)
		intCert, _ := mustCreateIntermediateCA(t, intKey, rootCert, rootKey)

		leafKey := mustGenerateECKey(t)
		leafCert, _ := mustCreateLeafCert(t, leafKey, intCert, intKey)

		intItem := &CertItem{Type: ContentCertificate, Certificate: intCert}
		leafItem := &CertItem{Type: ContentCertificate, Certificate: leafCert}
		container := &CertContainer{
			FilePath: "/test/store.p12",
			Format:   FormatPKCS12,
			Items:    []CertItem{*intItem, *leafItem},
		}
		store := storeWith(container)
		issues := runCheck(t, "chain_order", container, intItem, store)
		assertNoIssues(t, issues)
	})
}

func TestCheck_KeyCertMismatch(t *testing.T) {
	t.Run("key and cert with different public keys", func(t *testing.T) {
		certKey := mustGenerateECKey(t)
		cert, _ := mustCreateSelfSignedCA(t, certKey)

		otherKey := mustGenerateECKey(t)

		certItem := &CertItem{Type: ContentCertificate, Certificate: cert}
		keyItem := &CertItem{Type: ContentPrivateKey, PrivateKey: otherKey}
		container := &CertContainer{
			FilePath: "/test/bundle.pem",
			Format:   FormatPEM,
			Items:    []CertItem{*certItem, *keyItem},
		}
		store := storeWith(container)
		// DetectRelations won't create a key_cert relation since keys don't match.
		store.Relations = DetectRelations(store)
		relIndex := BuildRelationIndex(store.Relations, store)

		ref := ItemRef{ContainerIdx: 0, ItemIdx: 0, FilePath: container.FilePath}
		opts := CheckOptions{}.Defaults()

		var issues []CheckIssue
		for _, def := range allChecks {
			if def.ID == "key_cert_mismatch" {
				issues = def.check(container, keyItem, ref, opts, relIndex, store)
				break
			}
		}
		assertIssue(t, issues, SeverityWarning, "key_cert_mismatch")
	})

	t.Run("matching key and cert no issue", func(t *testing.T) {
		key := mustGenerateECKey(t)
		cert, _ := mustCreateSelfSignedCA(t, key)

		certItem := &CertItem{Type: ContentCertificate, Certificate: cert}
		keyItem := &CertItem{Type: ContentPrivateKey, PrivateKey: key}
		container := &CertContainer{
			FilePath: "/test/bundle.pem",
			Format:   FormatPEM,
			Items:    []CertItem{*certItem, *keyItem},
		}
		store := storeWith(container)
		store.Relations = DetectRelations(store)
		relIndex := BuildRelationIndex(store.Relations, store)

		ref := ItemRef{ContainerIdx: 0, ItemIdx: 0, FilePath: container.FilePath}
		opts := CheckOptions{}.Defaults()

		var issues []CheckIssue
		for _, def := range allChecks {
			if def.ID == "key_cert_mismatch" {
				issues = def.check(container, keyItem, ref, opts, relIndex, store)
				break
			}
		}
		assertNoIssues(t, issues)
	})

	t.Run("no key in container no issue", func(t *testing.T) {
		key := mustGenerateECKey(t)
		cert, _ := mustCreateSelfSignedCA(t, key)
		item := &CertItem{Type: ContentCertificate, Certificate: cert}
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "key_cert_mismatch", container, item, store)
		assertNoIssues(t, issues)
	})
}

// --- Structure checks ---

func TestCheck_Version(t *testing.T) {
	t.Run("v1 cert with extensions", func(t *testing.T) {
		cert := &x509.Certificate{
			Version:               1,
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "v1-with-ext"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			BasicConstraintsValid: true,
			Extensions: []pkix.Extension{
				{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 0x00}},
			},
		}
		item := &CertItem{Type: ContentCertificate, Certificate: cert}
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "version", container, item, store)
		assertIssue(t, issues, SeverityInfo, "version")
	})

	t.Run("v1 cert without extensions", func(t *testing.T) {
		cert := &x509.Certificate{
			Version:               1,
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "v1-no-ext"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			BasicConstraintsValid: true,
		}
		item := &CertItem{Type: ContentCertificate, Certificate: cert}
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "version", container, item, store)
		assertIssue(t, issues, SeverityWarning, "version")
	})

	t.Run("v3 cert no issue", func(t *testing.T) {
		key := mustGenerateECKey(t)
		cert, _ := mustCreateSelfSignedCA(t, key)
		item := &CertItem{Type: ContentCertificate, Certificate: cert}
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "version", container, item, store)
		assertNoIssues(t, issues)
	})
}

func TestCheck_UnknownExt(t *testing.T) {
	t.Run("critical unknown extension", func(t *testing.T) {
		cert := &x509.Certificate{
			Version:               3,
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "unknown-ext"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			BasicConstraintsValid: true,
			Extensions: []pkix.Extension{
				{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7}, Critical: true, Value: []byte{0x05, 0x00}},
			},
		}
		item := &CertItem{Type: ContentCertificate, Certificate: cert}
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "unknown_ext", container, item, store)
		assertIssue(t, issues, SeverityInfo, "unknown_ext")
	})

	t.Run("non-critical unknown extension no issue", func(t *testing.T) {
		cert := &x509.Certificate{
			Version:               3,
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "non-critical-ext"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			BasicConstraintsValid: true,
			Extensions: []pkix.Extension{
				{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7}, Critical: false, Value: []byte{0x05, 0x00}},
			},
		}
		item := &CertItem{Type: ContentCertificate, Certificate: cert}
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "unknown_ext", container, item, store)
		assertNoIssues(t, issues)
	})

	t.Run("well-known critical extension no issue", func(t *testing.T) {
		key := mustGenerateECKey(t)
		cert, _ := mustCreateSelfSignedCA(t, key)
		item := &CertItem{Type: ContentCertificate, Certificate: cert}
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "unknown_ext", container, item, store)
		assertNoIssues(t, issues)
	})
}

func TestCheck_SerialTooLong(t *testing.T) {
	t.Run("serial exactly 20 octets no issue", func(t *testing.T) {
		// 20 octets = 160 bits. Create a serial that is exactly 20 bytes.
		serial := new(big.Int).Lsh(big.NewInt(1), 159) // 160-bit number, 20 bytes
		item := certWithSerial(t, serial)
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "serial", container, item, store)
		assertNoIssues(t, issues)
	})

	t.Run("serial 21 octets too long", func(t *testing.T) {
		// 21 octets = 168 bits.
		serial := new(big.Int).Lsh(big.NewInt(1), 167) // 168-bit number, 21 bytes
		cert := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: "long-serial"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			BasicConstraintsValid: true,
		}
		item := &CertItem{Type: ContentCertificate, Certificate: cert}
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "serial", container, item, store)
		assertIssue(t, issues, SeverityWarning, "serial")
	})

	t.Run("serial nil", func(t *testing.T) {
		cert := &x509.Certificate{
			SerialNumber:          nil,
			Subject:               pkix.Name{CommonName: "nil-serial"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			BasicConstraintsValid: true,
		}
		item := &CertItem{Type: ContentCertificate, Certificate: cert}
		container := containerWith(item)
		store := storeWith(container)
		issues := runCheck(t, "serial", container, item, store)
		assertIssue(t, issues, SeverityWarning, "serial")
	})
}

// --- Integration checks ---

func TestRunChecks_CustomThresholds(t *testing.T) {
	now := time.Now()
	// Cert expires in 12 days -- with default thresholds (critical=7, warn=30) it's WARNING.
	// With custom thresholds (critical=14, warn=60) it's CRITICAL.
	item := certWithExpiry(t, now.Add(-24*time.Hour), now.Add(12*24*time.Hour+time.Hour))
	container := containerWith(item)
	store := storeWith(container)
	relIndex := BuildRelationIndex(store.Relations, store)

	result := RunChecks(store, relIndex, CheckOptions{
		ExpiryCriticalDays: 14,
		ExpiryWarnDays:     60,
	})

	foundCriticalExpiry := false
	for _, issue := range result.Issues {
		if issue.CheckID == "expiring_soon_critical" && issue.Severity == SeverityCritical {
			foundCriticalExpiry = true
		}
	}
	if !foundCriticalExpiry {
		t.Error("expected CRITICAL expiring_soon_critical with custom threshold of 14 days")
	}
}

func TestRunChecks_CategoryFilter(t *testing.T) {
	now := time.Now()
	// Expired cert -- triggers expiry checks
	item := certWithExpiry(t, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	container := containerWith(item)
	store := storeWith(container)
	relIndex := BuildRelationIndex(store.Relations, store)

	// Categories is an include-filter: only run checks in the listed categories.
	// By requesting only "key_strength", expiry checks should not appear.
	result := RunChecks(store, relIndex, CheckOptions{
		Categories: []string{"key_strength"},
	})

	for _, issue := range result.Issues {
		if issue.Category == "expiry" {
			t.Errorf("expected no expiry issues when category not included, got %s", issue.CheckID)
		}
	}
}

func TestRunChecks_OnlyKeysNoIssues(t *testing.T) {
	key := mustGenerateECKey(t)
	item := &CertItem{Type: ContentPrivateKey, PrivateKey: key, Encrypted: true}
	container := &CertContainer{
		FilePath: "/test/key.p12",
		Format:   FormatPKCS12,
		Items:    []CertItem{*item},
	}
	store := storeWith(container)
	relIndex := BuildRelationIndex(store.Relations, store)

	result := RunChecks(store, relIndex, CheckOptions{})

	// Keys in PKCS12 format (encrypted) should not trigger unprotected_key
	for _, issue := range result.Issues {
		if issue.CheckID == "unprotected_key" {
			t.Errorf("expected no unprotected_key for encrypted PKCS12 key")
		}
	}
}

// ---------------------------------------------------------------------------
// cfssl-inspired checker edge cases
// ---------------------------------------------------------------------------

// TestCheck_IntermediateExpiresBeforeLeaf verifies the behavior when an
// intermediate CA certificate expires before the leaf it signed. cfssl#1208.
// Currently no dedicated checker check exists for this, so this documents
// that only the intermediate's own expiry warnings are reported.
func TestCheck_IntermediateExpiresBeforeLeaf(t *testing.T) {
	now := time.Now()

	// Leaf: valid for 2 years
	leafKey := mustGenerateECKey(t)
	leafSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	leafTemplate := &x509.Certificate{
		SerialNumber:          leafSerial,
		Subject:               pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(2 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		DNSNames:              []string{"leaf.example.com"},
	}

	// Intermediate CA: expires in 5 days (before the leaf)
	intKey := mustGenerateECKey(t)
	intSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	intTemplate := &x509.Certificate{
		SerialNumber:          intSerial,
		Subject:               pkix.Name{CommonName: "Intermediate CA"},
		NotBefore:             now.Add(-365 * 24 * time.Hour),
		NotAfter:              now.Add(5 * 24 * time.Hour), // expires in 5 days
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	intDER, err := x509.CreateCertificate(rand.Reader, intTemplate, intTemplate, intKey.Public(), intKey)
	if err != nil {
		t.Fatal(err)
	}
	intCert, _ := x509.ParseCertificate(intDER)

	// Sign leaf with intermediate
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intCert, leafKey.Public(), intKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, _ := x509.ParseCertificate(leafDER)

	leafItem := &CertItem{Type: ContentCertificate, Certificate: leafCert}
	intItem := &CertItem{Type: ContentCertificate, Certificate: intCert}

	container := &CertContainer{
		FilePath: "/test/chain.pem",
		Format:   FormatPEM,
		Items:    []CertItem{*leafItem, *intItem},
	}
	store := storeWith(container)
	store.Relations = DetectRelations(store)
	relIndex := BuildRelationIndex(store.Relations, store)

	result := RunChecks(store, relIndex, CheckOptions{})

	// The intermediate should trigger expiring_soon_critical (5 days < 7 day threshold)
	foundIntExpiry := false
	for _, issue := range result.Issues {
		if issue.CheckID == "expiring_soon_critical" && strings.Contains(issue.DN, "Intermediate CA") {
			foundIntExpiry = true
		}
	}
	if !foundIntExpiry {
		t.Error("expected intermediate CA to trigger expiring_soon_critical (expires in 5 days)")
	}

	// The leaf should NOT trigger expiry warnings (valid for 2 years)
	for _, issue := range result.Issues {
		if (issue.CheckID == "expiring_soon_critical" || issue.CheckID == "expiring_soon_warning") &&
			strings.Contains(issue.DN, "leaf.example.com") {
			t.Errorf("leaf should not have expiry warning, got %s", issue.CheckID)
		}
	}
}

// TestCheck_SelfSignedMissingAKI verifies that a self-signed root CA without
// AuthorityKeyIdentifier does not trigger unexpected issues. cfssl#1385.
func TestCheck_SelfSignedMissingAKI(t *testing.T) {
	key := mustGenerateECKey(t)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	// Minimal self-signed cert
	cert := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		AuthorityKeyId:        nil, // explicitly no AKI
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := x509.ParseCertificate(der)

	item := &CertItem{Type: ContentCertificate, Certificate: parsed}
	container := containerWith(item)
	store := storeWith(container)
	relIndex := BuildRelationIndex(store.Relations, store)

	result := RunChecks(store, relIndex, CheckOptions{})

	// A self-signed root with no AKI is perfectly valid.
	// Verify no critical issues are raised about the AKI.
	for _, issue := range result.Issues {
		if issue.Severity == SeverityCritical {
			t.Errorf("self-signed root CA should not have critical issues, got: %s (%s)", issue.CheckID, issue.Message)
		}
	}
}

// TestCheck_LongValidityLeaf verifies that a leaf cert valid for > 398 days
// triggers the long_validity info check.
func TestCheck_LongValidityLeaf(t *testing.T) {
	now := time.Now()
	item := certWithExpiry(t, now.Add(-time.Hour), now.Add(500*24*time.Hour)) // ~500 days
	// certWithExpiry creates a cert with BasicConstraintsValid but IsCA=false
	container := containerWith(item)
	store := storeWith(container)

	issues := runCheck(t, "long_validity", container, item, store)
	assertIssue(t, issues, SeverityInfo, "long_validity")
}

// TestCheck_LongValidityCACert verifies that a CA cert with long validity
// does NOT trigger long_validity (the check is for leaf certs only).
func TestCheck_LongValidityCACert(t *testing.T) {
	item := certWithKeyUsage(t, true, x509.KeyUsageCertSign, nil)
	// certWithKeyUsage creates a CA cert valid for 365 days, but let's create
	// one with longer validity to be sure.
	item.Certificate.NotAfter = time.Now().Add(500 * 24 * time.Hour)
	item.Certificate.IsCA = true

	container := containerWith(item)
	store := storeWith(container)

	issues := runCheck(t, "long_validity", container, item, store)
	assertNoIssues(t, issues)
}

// ---------------------------------------------------------------------------
// extras_by_codes: checker edge cases
// ---------------------------------------------------------------------------

// TestRunChecks_SkipsRelationsOnly verifies that containers marked
// RelationsOnly=true are not checked (no issues emitted for them).
func TestRunChecks_SkipsRelationsOnly(t *testing.T) {
	now := time.Now()
	// Expired cert that would normally trigger issues
	expiredItem := certWithExpiry(t, now.Add(-365*24*time.Hour), now.Add(-24*time.Hour))
	container := &CertContainer{
		FilePath:      "/test/sibling.pem",
		Format:        FormatPEM,
		Items:         []CertItem{*expiredItem},
		RelationsOnly: true,
	}
	store := storeWith(container)
	relIndex := BuildRelationIndex(store.Relations, store)

	result := RunChecks(store, relIndex, CheckOptions{})

	if len(result.Issues) != 0 {
		t.Errorf("expected 0 issues for RelationsOnly container, got %d: %v", len(result.Issues), result.Issues)
	}
}

// TestCheck_KeyCertMismatch_MixedBundle verifies that when a container has
// one key + two certs where only one cert matches the key, only the
// non-matching cert gets key_cert_mismatch.
func TestCheck_KeyCertMismatch_MixedBundle(t *testing.T) {
	// Key 1 and its matching cert
	key1 := mustGenerateECKey(t)
	cert1, _ := mustCreateSelfSignedCA(t, key1)

	// Key 2 and its cert (different key)
	key2 := mustGenerateECKey(t)
	cert2, _ := mustCreateSelfSignedCA(t, key2)

	// Bundle: key1 + cert1 (match) + cert2 (no match)
	container := &CertContainer{
		FilePath: "/test/mixed.pem",
		Format:   FormatPEM,
		Items: []CertItem{
			{Type: ContentPrivateKey, PrivateKey: key1},
			{Type: ContentCertificate, Certificate: cert1},
			{Type: ContentCertificate, Certificate: cert2},
		},
	}
	store := NewCertStore()
	store.AddContainer(*container)
	store.Relations = DetectRelations(store)
	relIndex := BuildRelationIndex(store.Relations, store)

	result := RunChecks(store, relIndex, CheckOptions{})

	// Key-centric behaviour: key1 matches cert1, so it matches at least one cert
	// in the bundle - there must be NO key_cert_mismatch. cert2 is simply an
	// additional (unrelated) cert in the bundle and must not be flagged.
	for _, issue := range result.Issues {
		if issue.CheckID == "key_cert_mismatch" {
			t.Errorf("unexpected key_cert_mismatch (key1 matches cert1): item %d", issue.ItemRef.ItemIdx)
		}
	}
}

// TestCheck_KeyCertMismatch_OrphanKey verifies a key that matches NO cert in the
// bundle is flagged.
func TestCheck_KeyCertMismatch_OrphanKey(t *testing.T) {
	key1 := mustGenerateECKey(t)
	cert1, _ := mustCreateSelfSignedCA(t, key1)
	orphan := mustGenerateECKey(t)

	container := &CertContainer{
		FilePath: "/test/orphan.pem",
		Format:   FormatPEM,
		Items: []CertItem{
			{Type: ContentCertificate, Certificate: cert1},
			{Type: ContentPrivateKey, PrivateKey: orphan},
		},
	}
	store := NewCertStore()
	store.AddContainer(*container)
	store.Relations = DetectRelations(store)
	relIndex := BuildRelationIndex(store.Relations, store)

	result := RunChecks(store, relIndex, CheckOptions{})
	found := false
	for _, issue := range result.Issues {
		if issue.CheckID == "key_cert_mismatch" {
			found = true
		}
	}
	if !found {
		t.Error("orphan key (matches no cert) should be flagged key_cert_mismatch")
	}
}

// TestCheck_KeyCertMismatch_KeyFullchainNoFalsePositive is the core regression
// for the false-positive bug: a HAProxy-style key+fullchain bundle (leaf key +
// leaf cert + issuer CA) must NOT raise key_cert_mismatch on the CA cert.
func TestCheck_KeyCertMismatch_KeyFullchainNoFalsePositive(t *testing.T) {
	rootKey := mustGenerateECKey(t)
	rootCert, _ := mustCreateSelfSignedCA(t, rootKey)
	leafKey := mustGenerateECKey(t)
	leafCert, _ := mustCreateLeafCert(t, leafKey, rootCert, rootKey)

	container := &CertContainer{
		FilePath: "/test/fullchain.pem",
		Format:   FormatPEM,
		Items: []CertItem{
			{Type: ContentPrivateKey, PrivateKey: leafKey},
			{Type: ContentCertificate, Certificate: leafCert},
			{Type: ContentCertificate, Certificate: rootCert},
		},
	}
	store := NewCertStore()
	store.AddContainer(*container)
	store.Relations = DetectRelations(store)
	relIndex := BuildRelationIndex(store.Relations, store)

	result := RunChecks(store, relIndex, CheckOptions{})
	for _, issue := range result.Issues {
		if issue.CheckID == "key_cert_mismatch" {
			t.Errorf("false-positive key_cert_mismatch on key+fullchain bundle: item %d", issue.ItemRef.ItemIdx)
		}
	}
}

// TestCheck_ChainOrder_PrivateKeyMixedIn verifies chain_order behavior when
// a PEM bundle starts with a PRIVATE KEY block followed by certs.
// The check only fires at ItemIdx==0 and only if the first cert is a
// non-self-signed CA.
func TestCheck_ChainOrder_PrivateKeyMixedIn(t *testing.T) {
	key := mustGenerateECKey(t)
	caCert, _ := mustCreateSelfSignedCA(t, key)

	leafKey := mustGenerateECKey(t)
	leafCert, _ := mustCreateLeafCert(t, leafKey, caCert, key)

	// Bundle: key, leaf, CA (key first, correct cert order after)
	container := &CertContainer{
		FilePath: "/test/key-first.pem",
		Format:   FormatPEM,
		Items: []CertItem{
			{Type: ContentPrivateKey, PrivateKey: leafKey},
			{Type: ContentCertificate, Certificate: leafCert},
			{Type: ContentCertificate, Certificate: caCert},
		},
	}
	store := storeWith(container)

	// The first item is a key (not a cert), so checkChainOrder at idx=0
	// sees item.Certificate==nil and returns nil.
	keyItem := &container.Items[0]
	issues := runCheck(t, "chain_order", container, keyItem, store)
	assertNoIssues(t, issues)
}

// TestCheck_EmptyPassword_BothEmpty verifies that when both the store password
// and entry password are empty, only one empty_password issue is emitted per key.
func TestCheck_EmptyPassword_BothEmpty(t *testing.T) {
	key := mustGenerateECKey(t)
	emptyPass := []byte{}
	item := &CertItem{
		Type:          ContentPrivateKey,
		PrivateKey:    key,
		Encrypted:     true,
		EntryPassword: emptyPass,
	}
	container := &CertContainer{
		FilePath: "/test/empty-pass.p12",
		Format:   FormatPKCS12,
		Items:    []CertItem{*item},
		Password: emptyPass,
	}
	store := storeWith(container)

	issues := runCheck(t, "empty_password", container, item, store)

	// The check first tests c.Password (empty) and returns immediately.
	// So we should get exactly 1 issue, not 2.
	if len(issues) != 1 {
		t.Errorf("expected exactly 1 empty_password issue, got %d", len(issues))
	}
}

// TestEnabledCheckCount verifies the total/enabled/disabled counts.
func TestEnabledCheckCount(t *testing.T) {
	total, enabled, disabled := EnabledCheckCount(nil)
	if total != len(allChecks) {
		t.Errorf("total=%d, want %d", total, len(allChecks))
	}
	if enabled != total {
		t.Errorf("enabled=%d, want %d (no disabled)", enabled, total)
	}
	if disabled != 0 {
		t.Errorf("disabled=%d, want 0", disabled)
	}

	// Disable 2 checks
	total2, enabled2, disabled2 := EnabledCheckCount([]string{"expired", "weak_rsa"})
	if total2 != total {
		t.Errorf("total should not change: got %d", total2)
	}
	if disabled2 != 2 {
		t.Errorf("disabled=%d, want 2", disabled2)
	}
	if enabled2 != total-2 {
		t.Errorf("enabled=%d, want %d", enabled2, total-2)
	}
}

// TestSafeItem_OutOfBounds verifies SafeItem returns nil for invalid refs.
func TestSafeItem_OutOfBounds(t *testing.T) {
	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "/test/a.pem",
		Format:   FormatPEM,
		Items:    []CertItem{{Type: ContentCertificate}},
	})

	tests := []struct {
		name string
		ref  ItemRef
	}{
		{"negative_container", ItemRef{ContainerIdx: -1, ItemIdx: 0}},
		{"negative_item", ItemRef{ContainerIdx: 0, ItemIdx: -1}},
		{"container_oob", ItemRef{ContainerIdx: 5, ItemIdx: 0}},
		{"item_oob", ItemRef{ContainerIdx: 0, ItemIdx: 5}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if store.SafeItem(tt.ref) != nil {
				t.Error("expected nil for out-of-bounds ref")
			}
		})
	}

	// Valid ref should work
	valid := store.SafeItem(ItemRef{ContainerIdx: 0, ItemIdx: 0})
	if valid == nil {
		t.Error("expected non-nil for valid ref")
	}
}

// Ensure unused imports are satisfied.
var _ = net.IPv4
var _ = pkix.Name{}
var _ = dsa.PublicKey{}
var _ = asn1.ObjectIdentifier{}
var _ = rand.Reader
