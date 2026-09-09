package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func checkEnterModel(t *testing.T, remote bool) RootModel {
	t.Helper()
	initStyles()
	item := makeCertItem(t, "local.example.com")
	container := &certlib.CertContainer{FilePath: "/tmp/local.pem", Items: []certlib.CertItem{*item}}

	m := RootModel{width: 100, height: 40}
	m.state = stateCheckView
	m.checkReturn = stateTree
	m.allNodes = []TreeNode{
		{
			ContainerIdx: 0,
			ItemIdx:      0,
			Ref:          certlib.ItemRef{ContainerIdx: 0, ItemIdx: 0, FilePath: "/tmp/local.pem"},
			Filename:     "local.pem",
			ContentType:  string(certlib.ContentCertificate),
			Item:         item,
			Container:    container,
		},
	}
	m.checkView = newCheckViewModel(&certlib.CheckResult{
		Issues: []certlib.CheckIssue{
			{
				Severity: certlib.SeverityWarning,
				Filename: "(remote)",
				Message:  "some remote issue",
				ItemRef:  certlib.ItemRef{ContainerIdx: 0, ItemIdx: 0, FilePath: "(remote)"},
			},
		},
	})
	m.checkView.remoteOrigin = remote
	m.checkView.width = m.width
	m.checkView.height = m.height
	return m
}

// TestCheckView_EnterRemoteNoNav verifies bug #22: pressing Enter on a
// remote-origin check issue must not navigate to an unrelated local node
// (the remote ItemRef indexes a temporary "(remote)" store, not the local tree).
func TestCheckView_EnterRemoteNoNav(t *testing.T) {
	m := checkEnterModel(t, true)

	mm, _ := m.handleCheckViewKey(tea.KeyMsg{Type: tea.KeyEnter})
	rm := mm.(RootModel)

	if rm.state != stateCheckView {
		t.Errorf("remote Enter navigated away: state = %d, want stateCheckView (%d)", rm.state, stateCheckView)
	}
	if rm.detail != nil {
		t.Error("remote Enter built a detail view for a bogus local node")
	}
	if rm.checkView.status != statusRemoteCheckNoNav {
		t.Errorf("remote Enter status = %q, want %q", rm.checkView.status, statusRemoteCheckNoNav)
	}
}

// TestCheckView_EnterLocalNavigates is the regression guard: a local-scan check
// view still navigates to the referenced node on Enter.
func TestCheckView_EnterLocalNavigates(t *testing.T) {
	m := checkEnterModel(t, false)

	mm, _ := m.handleCheckViewKey(tea.KeyMsg{Type: tea.KeyEnter})
	rm := mm.(RootModel)

	if rm.state != stateTree {
		t.Errorf("local Enter did not navigate: state = %d, want stateTree (%d)", rm.state, stateTree)
	}
	if rm.detail == nil {
		t.Error("local Enter did not build a detail view for the referenced node")
	}
}
