package tui

import (
	"crypto/x509"
	"path/filepath"
	"testing"
)

func TestSessionCertSave_WriteFailureReportsError(t *testing.T) {
	cert := testSelfSignedCert(t, testGenRSAKey(t))

	// A directory is not writable as a file, so writeCertsPEM must fail. This
	// is the same failure the save picker callback can hit.
	badPath := t.TempDir()
	werr := writeCertsPEM(badPath, []*x509.Certificate{cert})
	if werr == nil {
		t.Fatalf("expected writeCertsPEM to fail writing to a directory path")
	}

	m := RootModel{}
	m2, _ := m.Update(pcapCertSavedMsg{path: badPath, err: werr})
	rm := m2.(RootModel)
	if rm.popup.kind != popupError {
		t.Fatalf("expected error popup, got kind=%v message=%q status=%q", rm.popup.kind, rm.popup.message, rm.statusMessage)
	}
	if rm.statusMessage != "" {
		t.Fatalf("did not expect a status message on failure, got %q", rm.statusMessage)
	}
}

func TestSessionCertSave_SuccessReportsSaved(t *testing.T) {
	cert := testSelfSignedCert(t, testGenRSAKey(t))
	path := filepath.Join(t.TempDir(), "cert.pem")
	if err := writeCertsPEM(path, []*x509.Certificate{cert}); err != nil {
		t.Fatalf("writeCertsPEM should succeed: %v", err)
	}

	m := RootModel{}
	m2, _ := m.Update(pcapCertSavedMsg{path: path})
	rm := m2.(RootModel)
	if rm.popup.kind == popupError {
		t.Fatalf("did not expect error popup on success: %q", rm.popup.message)
	}
	if rm.statusMessage == "" {
		t.Fatalf("expected a 'Saved to' status message on success")
	}
}
