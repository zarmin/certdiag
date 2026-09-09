package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func mustGenKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func writeCertPEM(t *testing.T, dir, name string, cert *x509.Certificate) string {
	t.Helper()
	data, err := certlib.EncodePEM([]certlib.CertItem{
		{Type: certlib.ContentCertificate, Certificate: cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestBundleChainDisplayRootFirst(t *testing.T) {
	dir := t.TempDir()

	rootKey := mustGenKey(t)
	rootCert, _, err := certlib.CreateSelfSignedCert(rootKey, certlib.CertGenOptions{
		Subject:    pkix.Name{CommonName: "Root CA"},
		Days:       3650,
		IsCA:       true,
		KeyUsage:   x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PathLength: -1,
	})
	if err != nil {
		t.Fatal(err)
	}

	interKey := mustGenKey(t)
	interCert, _, err := certlib.CreateSignedCert(interKey, certlib.CertGenOptions{
		Subject:    pkix.Name{CommonName: "Intermediate CA"},
		Days:       3650,
		IsCA:       true,
		KeyUsage:   x509.KeyUsageCertSign,
		PathLength: 0,
		SignerCert: rootCert,
		SignerKey:  rootKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	leafKey := mustGenKey(t)
	leafCert, _, err := certlib.CreateSignedCert(leafKey, certlib.CertGenOptions{
		Subject:    pkix.Name{CommonName: "Leaf"},
		Days:       365,
		SignerCert: interCert,
		SignerKey:  interKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	leafPath := writeCertPEM(t, dir, "leaf.pem", leafCert)
	interPath := writeCertPEM(t, dir, "inter.pem", interCert)
	rootPath := writeCertPEM(t, dir, "root.pem", rootCert)

	outPath := filepath.Join(dir, "bundle.pem")

	cmd := exec.Command(remoteTestBinary,
		"bundle", leafPath, interPath, rootPath,
		"--auto-chain", "-o", outPath, "--no-confirm")
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "CERTDIAG_CONFIG=")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("bundle failed: %v\nstderr: %s", err, stderr.String())
	}

	var chainLine string
	for _, line := range strings.Split(stderr.String(), "\n") {
		if strings.Contains(line, "chain:") {
			chainLine = line
			break
		}
	}
	if chainLine == "" {
		t.Fatalf("no chain line in output:\n%s", stderr.String())
	}

	wantDisplay := "Root CA -> Intermediate CA -> Leaf"
	if !strings.Contains(chainLine, wantDisplay) {
		t.Errorf("display chain = %q, want to contain %q", chainLine, wantDisplay)
	}

	rootIdx := strings.Index(chainLine, "Root CA")
	leafIdx := strings.Index(chainLine, "Leaf")
	if rootIdx == -1 || leafIdx == -1 || rootIdx > leafIdx {
		t.Errorf("displayed chain must read root before leaf: %q", chainLine)
	}

	// PEM content order must remain leaf-first (unchanged by the display fix).
	pemBytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var cns []string
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		cns = append(cns, c.Subject.CommonName)
	}
	if len(cns) != 3 {
		t.Fatalf("expected 3 certs in bundle, got %d: %v", len(cns), cns)
	}
	if cns[0] != "Leaf" || cns[len(cns)-1] != "Root CA" {
		t.Errorf("PEM content order changed: got %v, want leaf-first (Leaf ... Root CA)", cns)
	}
}
