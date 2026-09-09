package tui

import (
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
)

func TestRunRemoteChecks(t *testing.T) {
	initStyles()
	cert := makeTestCert(t, "test.example.com")

	m := RootModel{}
	m.width = 80
	m.height = 24
	m.remoteResult = &certops.FetchRemoteCertResult{
		TargetResults: []certops.TargetFetchResult{
			{
				Target: "test.example.com:443",
				Connection: &certops.RemoteConnectionInfo{
					TLSVersion: "TLS 1.3",
				},
				Certs: []certops.RemoteCertInfo{
					{
						Index: 0,
						Role:  "leaf",
						Cert: &certlib.CertItem{
							Type:        certlib.ContentCertificate,
							Certificate: cert,
							RawBytes:    cert.Raw,
						},
					},
				},
			},
		},
	}

	m.runRemoteChecks()

	if m.state != stateCheckView {
		t.Errorf("expected stateCheckView, got %d", m.state)
	}
	if m.checkView.filesScanned != 1 {
		t.Errorf("expected 1 file scanned, got %d", m.checkView.filesScanned)
	}
}

func TestRunRemoteChecks_NoResult(t *testing.T) {
	initStyles()
	m := RootModel{}
	m.remoteResult = nil

	m.runRemoteChecks()

	if m.state == stateCheckView {
		t.Error("with no result there is nothing to check")
	}
}

func TestRunRemoteChecks_Error(t *testing.T) {
	initStyles()
	m := RootModel{}
	m.remoteResult = &certops.FetchRemoteCertResult{
		TargetResults: []certops.TargetFetchResult{
			{
				Target: "bad.example.com",
				Error:  "connection refused",
			},
		},
	}

	m.runRemoteChecks()

	if m.state == stateCheckView {
		t.Error("a target that failed to connect has no certificates to check")
	}
}

func makeRemoteResultModel(t *testing.T) RootModel {
	t.Helper()
	initStyles()
	initFormStyles()

	cert1 := makeTestCert(t, "leaf.example.com")
	cert2 := makeTestCert(t, "intermediate.example.com")

	m := RootModel{}
	m.width = 100
	m.height = 40
	m.remoteResult = &certops.FetchRemoteCertResult{
		TargetResults: []certops.TargetFetchResult{
			{
				Target: "example.com:443",
				Connection: &certops.RemoteConnectionInfo{
					TLSVersion:  "TLS 1.3",
					CipherSuite: "TLS_AES_256_GCM_SHA384",
				},
				Certs: []certops.RemoteCertInfo{
					{
						Index: 0,
						Role:  "leaf",
						Cert: &certlib.CertItem{
							Type:        certlib.ContentCertificate,
							Certificate: cert1,
							RawBytes:    cert1.Raw,
						},
					},
					{
						Index: 1,
						Role:  "intermediate",
						Cert: &certlib.CertItem{
							Type:        certlib.ContentCertificate,
							Certificate: cert2,
							RawBytes:    cert2.Raw,
						},
					},
				},
			},
		},
	}
	m.remoteHasResult = true
	m.currentRoot = rootRemoteFetch
	m.rebuildRemoteTree()
	m.state = stateTree
	return m
}

// ---------------------------------------------------------------------------
// #1: Remote result key handlers
// ---------------------------------------------------------------------------

func TestRemoteResult_SReturnsSaveCmd(t *testing.T) {
	m := makeRemoteResultModel(t)

	_, result, cmd := m.remoteKey(keyMsg("s"), stateTree)
	rm := result.(RootModel)

	// State should remain on remote result (filepicker runs as tea.Exec)
	if rm.state != stateTree {
		t.Fatalf("expected stateTree, got %d", rm.state)
	}
	// Should return a non-nil command (tea.Exec for filepicker)
	if cmd == nil {
		t.Fatal("expected non-nil cmd from save (tea.Exec)")
	}
}

func TestRemoteResult_SNoResultReturnsNil(t *testing.T) {
	initStyles()
	m := RootModel{}
	m.width = 80
	m.height = 24
	m.remoteResult = nil

	cmd := m.openRemoteSaveForm()
	if cmd != nil {
		t.Fatal("expected nil cmd when no remote result")
	}
}

func TestRemoteResult_SErrorResultReturnsNil(t *testing.T) {
	initStyles()
	m := RootModel{}
	m.width = 80
	m.height = 24
	m.remoteResult = &certops.FetchRemoteCertResult{
		TargetResults: []certops.TargetFetchResult{
			{Target: "bad.example.com", Error: "connection refused"},
		},
	}

	cmd := m.openRemoteSaveForm()
	if cmd != nil {
		t.Fatal("expected nil cmd when result has error")
	}
}

func TestRemoteSavePicked_Success(t *testing.T) {
	m := makeRemoteResultModel(t)

	tmpDir := t.TempDir()
	path := tmpDir + "/chain.pem"

	result, _ := m.handleRemoteSavePicked(remoteSavePickedMsg{path: path})
	rm := result.(RootModel)

	if rm.statusMessage == "" {
		t.Fatal("expected status message after save")
	}
	if !strings.Contains(rm.statusMessage, "Saved chain") {
		t.Errorf("expected 'Saved chain' in status, got %q", rm.statusMessage)
	}
}

// ---------------------------------------------------------------------------
// #4: Remote view IP wrapping
// ---------------------------------------------------------------------------
