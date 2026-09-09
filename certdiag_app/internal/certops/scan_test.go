package certops

import (
	"path/filepath"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func TestScan(t *testing.T) {
	t.Run("RelationsAndChains", func(t *testing.T) {
		dir := t.TempDir()
		caKey := mustGenECKey(t)
		caCert := mustMakeCA(t, caKey)
		leafKey := mustGenECKey(t)
		leafCert := mustMakeLeaf(t, leafKey, caCert, caKey)

		caPath := writePEMFile(t, dir, "ca.crt", []certlib.CertItem{
			{Type: certlib.ContentCertificate, Certificate: caCert},
		})
		leafPath := writePEMFile(t, dir, "leaf.crt", []certlib.CertItem{
			{Type: certlib.ContentCertificate, Certificate: leafCert},
		})

		res := Scan(ScanOptions{
			Paths:          []string{caPath, leafPath},
			AssembleChains: true,
		})

		if len(res.PathErrors) != 0 || len(res.ParseErrors) != 0 {
			t.Fatalf("unexpected errors: path=%v parse=%v", res.PathErrors, res.ParseErrors)
		}
		if res.Store.TotalItems() != 2 {
			t.Fatalf("expected 2 items, got %d", res.Store.TotalItems())
		}
		if res.RelIndex == nil {
			t.Fatal("expected relation index for 2+ items")
		}
		if len(res.Chains) == 0 {
			t.Fatal("expected assembled chains")
		}
	})

	t.Run("SingleItemNoRelations", func(t *testing.T) {
		dir := t.TempDir()
		caKey := mustGenECKey(t)
		caCert := mustMakeCA(t, caKey)
		caPath := writePEMFile(t, dir, "ca.crt", []certlib.CertItem{
			{Type: certlib.ContentCertificate, Certificate: caCert},
		})

		res := Scan(ScanOptions{Paths: []string{caPath}, AssembleChains: true})
		if res.RelIndex != nil {
			t.Error("expected nil relation index for single item")
		}
		if res.Chains != nil {
			t.Error("expected nil chains for single item")
		}
	})

	t.Run("Check", func(t *testing.T) {
		dir := t.TempDir()
		caKey := mustGenECKey(t)
		caCert := mustMakeCA(t, caKey)
		leafKey := mustGenECKey(t)
		leafCert := mustMakeLeaf(t, leafKey, caCert, caKey)
		caPath := writePEMFile(t, dir, "ca.crt", []certlib.CertItem{
			{Type: certlib.ContentCertificate, Certificate: caCert},
		})
		leafPath := writePEMFile(t, dir, "leaf.crt", []certlib.CertItem{
			{Type: certlib.ContentCertificate, Certificate: leafCert},
		})

		res := Scan(ScanOptions{
			Paths: []string{caPath, leafPath},
			Check: true,
		})
		if res.CheckResult == nil {
			t.Fatal("expected check result when Check=true")
		}
	})

	t.Run("CheckOptionsCarryRevocation", func(t *testing.T) {
		// Regression for --strict dropping revocation issues: the effective
		// CheckOptions RunChecks used must be exposed so a re-run sees the same
		// revocation wiring instead of the CLI-built options that lack it.
		dir := t.TempDir()
		caKey := mustGenECKey(t)
		caCert := mustMakeCA(t, caKey)
		leafKey := mustGenECKey(t)
		leafCert := mustMakeLeaf(t, leafKey, caCert, caKey)
		caPath := writePEMFile(t, dir, "ca.crt", []certlib.CertItem{
			{Type: certlib.ContentCertificate, Certificate: caCert},
		})
		leafPath := writePEMFile(t, dir, "leaf.crt", []certlib.CertItem{
			{Type: certlib.ContentCertificate, Certificate: leafCert},
		})

		res := Scan(ScanOptions{
			Paths:      []string{caPath, leafPath},
			Check:      true,
			Revocation: RevocationConfig{Enabled: true, Require: true, Method: certlib.RevocationMethodCRL},
		})
		if !res.CheckOptions.RevocationEnabled {
			t.Error("CheckOptions.RevocationEnabled not exposed; --strict re-run would drop revocation issues")
		}
		if !res.CheckOptions.RevocationRequire {
			t.Error("CheckOptions.RevocationRequire not exposed")
		}
	})

	t.Run("PathError", func(t *testing.T) {
		res := Scan(ScanOptions{Paths: []string{filepath.Join(t.TempDir(), "nonexistent.crt")}})
		if len(res.PathErrors) != 1 {
			t.Fatalf("expected 1 path error, got %v", res.PathErrors)
		}
		if res.Store.TotalItems() != 0 {
			t.Errorf("expected empty store, got %d items", res.Store.TotalItems())
		}
	})
}
