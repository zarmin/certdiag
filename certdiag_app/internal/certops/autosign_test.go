package certops

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func mustGenECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustMakeCA(t *testing.T, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	cert, _, err := certlib.CreateSelfSignedCert(key, certlib.CertGenOptions{
		Subject:    pkix.Name{CommonName: "Test CA"},
		Days:       3650,
		IsCA:       true,
		KeyUsage:   x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PathLength: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func mustMakeLeaf(t *testing.T, key *ecdsa.PrivateKey, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	cert, _, err := certlib.CreateSignedCert(key, certlib.CertGenOptions{
		Subject:    pkix.Name{CommonName: "leaf.local"},
		Days:       365,
		SignerCert: caCert,
		SignerKey:  caKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func writePEMFile(t *testing.T, dir, name string, items []certlib.CertItem) string {
	t.Helper()
	data, err := certlib.EncodePEM(items)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFindCA(t *testing.T) {
	t.Run("SingleCAFound", func(t *testing.T) {
		dir := t.TempDir()
		caKey := mustGenECKey(t)
		caCert := mustMakeCA(t, caKey)

		writePEMFile(t, dir, "ca.crt", []certlib.CertItem{
			{Type: certlib.ContentCertificate, Certificate: caCert},
		})
		writePEMFile(t, dir, "ca.key", []certlib.CertItem{
			{Type: certlib.ContentPrivateKey, PrivateKey: caKey},
		})

		result, err := FindCA(FindCAOptions{SearchDirs: []string{dir}})
		if err != nil {
			t.Fatalf("FindCA: %v", err)
		}
		if !result.CACert.IsCA {
			t.Error("expected IsCA = true")
		}
	})

	t.Run("NoCA", func(t *testing.T) {
		dir := t.TempDir()
		caKey := mustGenECKey(t)
		caCert := mustMakeCA(t, caKey)
		leafKey := mustGenECKey(t)
		leafCert := mustMakeLeaf(t, leafKey, caCert, caKey)

		writePEMFile(t, dir, "leaf.crt", []certlib.CertItem{
			{Type: certlib.ContentCertificate, Certificate: leafCert},
		})
		writePEMFile(t, dir, "leaf.key", []certlib.CertItem{
			{Type: certlib.ContentPrivateKey, PrivateKey: leafKey},
		})

		_, err := FindCA(FindCAOptions{SearchDirs: []string{dir}})
		if err == nil {
			t.Fatal("expected error for no CA, got nil")
		}
	})

	t.Run("CAWithoutKey", func(t *testing.T) {
		dir := t.TempDir()
		caKey := mustGenECKey(t)
		caCert := mustMakeCA(t, caKey)

		writePEMFile(t, dir, "ca.crt", []certlib.CertItem{
			{Type: certlib.ContentCertificate, Certificate: caCert},
		})
		// no key file written

		_, err := FindCA(FindCAOptions{SearchDirs: []string{dir}})
		if err == nil {
			t.Fatal("expected error for CA without key, got nil")
		}
	})

	t.Run("SelfSignedNonCALeafRejected", func(t *testing.T) {
		dir := t.TempDir()
		leafKey := mustGenECKey(t)
		leafCert, _, err := certlib.CreateSelfSignedCert(leafKey, certlib.CertGenOptions{
			Subject:  pkix.Name{CommonName: "leaf.local"},
			Days:     365,
			IsCA:     false,
			KeyUsage: x509.KeyUsageDigitalSignature,
		})
		if err != nil {
			t.Fatal(err)
		}

		writePEMFile(t, dir, "leaf.crt", []certlib.CertItem{
			{Type: certlib.ContentCertificate, Certificate: leafCert},
		})
		writePEMFile(t, dir, "leaf.key", []certlib.CertItem{
			{Type: certlib.ContentPrivateKey, PrivateKey: leafKey},
		})

		_, err = FindCA(FindCAOptions{SearchDirs: []string{dir}})
		if err == nil {
			t.Fatal("expected error: self-signed non-CA leaf must not be accepted as signer")
		}
	})

	t.Run("CAWithoutCertSignRejected", func(t *testing.T) {
		dir := t.TempDir()
		caKey := mustGenECKey(t)
		caCert, _, err := certlib.CreateSelfSignedCert(caKey, certlib.CertGenOptions{
			Subject:    pkix.Name{CommonName: "Weak CA"},
			Days:       3650,
			IsCA:       true,
			KeyUsage:   x509.KeyUsageDigitalSignature,
			PathLength: -1,
		})
		if err != nil {
			t.Fatal(err)
		}

		writePEMFile(t, dir, "ca.crt", []certlib.CertItem{
			{Type: certlib.ContentCertificate, Certificate: caCert},
		})
		writePEMFile(t, dir, "ca.key", []certlib.CertItem{
			{Type: certlib.ContentPrivateKey, PrivateKey: caKey},
		})

		_, err = FindCA(FindCAOptions{SearchDirs: []string{dir}})
		if err == nil {
			t.Fatal("expected error: CA asserting KeyUsage without certSign must be rejected")
		}
	})

	t.Run("PrefersIntermediate", func(t *testing.T) {
		dir := t.TempDir()
		rootKey := mustGenECKey(t)
		rootCert := mustMakeCA(t, rootKey)

		interKey := mustGenECKey(t)
		interCert, _, err := certlib.CreateSignedCert(interKey, certlib.CertGenOptions{
			Subject:    pkix.Name{CommonName: "Intermediate CA"},
			Days:       3650,
			IsCA:       true,
			KeyUsage:   x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			PathLength: 0,
			SignerCert: rootCert,
			SignerKey:  rootKey,
		})
		if err != nil {
			t.Fatal(err)
		}

		writePEMFile(t, dir, "root.crt", []certlib.CertItem{
			{Type: certlib.ContentCertificate, Certificate: rootCert},
		})
		writePEMFile(t, dir, "root.key", []certlib.CertItem{
			{Type: certlib.ContentPrivateKey, PrivateKey: rootKey},
		})
		writePEMFile(t, dir, "inter.crt", []certlib.CertItem{
			{Type: certlib.ContentCertificate, Certificate: interCert},
		})
		writePEMFile(t, dir, "inter.key", []certlib.CertItem{
			{Type: certlib.ContentPrivateKey, PrivateKey: interKey},
		})

		result, err := FindCA(FindCAOptions{SearchDirs: []string{dir}})
		if err != nil {
			t.Fatalf("FindCA: %v", err)
		}
		if result.CACert.Subject.CommonName != "Intermediate CA" {
			t.Errorf("selected CA = %q, want %q", result.CACert.Subject.CommonName, "Intermediate CA")
		}
	})

	t.Run("NonRecursive", func(t *testing.T) {
		dir := t.TempDir()
		subdir := filepath.Join(dir, "subdir")
		if err := os.Mkdir(subdir, 0755); err != nil {
			t.Fatal(err)
		}

		caKey := mustGenECKey(t)
		caCert := mustMakeCA(t, caKey)

		// Put CA in subdir only
		writePEMFile(t, subdir, "ca.crt", []certlib.CertItem{
			{Type: certlib.ContentCertificate, Certificate: caCert},
		})
		writePEMFile(t, subdir, "ca.key", []certlib.CertItem{
			{Type: certlib.ContentPrivateKey, PrivateKey: caKey},
		})

		_, err := FindCA(FindCAOptions{SearchDirs: []string{dir}})
		if err == nil {
			t.Fatal("expected error (CA in subdir should not be found non-recursively)")
		}
	})
}
