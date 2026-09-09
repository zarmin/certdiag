package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
)

func TestRemoteSaveAllConfirmPreservesState(t *testing.T) {
	initStyles()

	result := &certops.FetchRemoteCertResult{
		TargetResults: []certops.TargetFetchResult{
			{
				Target: "example.com:443",
				Certs: []certops.RemoteCertInfo{
					{Index: 0, Role: "leaf", Cert: makeCertItem(t, "example.com")},
					{Index: 1, Role: "intermediate", Cert: makeCertItem(t, "Intermediate CA")},
				},
			},
		},
	}

	m := RootModel{width: 80, height: 24, remoteResult: result}
	m.openRemoteSaveAll()

	if m.popup.kind != popupConfirm {
		t.Fatalf("expected popupConfirm, got %v", m.popup.kind)
	}
	if m.confirmAction == nil {
		t.Fatal("expected confirmAction to be set")
	}

	resized, _ := m.Update(tea.WindowSizeMsg{Width: 200, Height: 60})
	rm := resized.(RootModel)
	if rm.width != 200 || rm.height != 60 {
		t.Fatalf("resize not applied: width=%d height=%d", rm.width, rm.height)
	}

	confirmed, cmd := rm.Update(tea.KeyMsg{Type: tea.KeyEnter})
	fm := confirmed.(RootModel)

	if fm.width != 200 || fm.height != 60 {
		t.Fatalf("stale closure reverted state: width=%d height=%d (want 200x60)", fm.width, fm.height)
	}
	if cmd == nil {
		t.Fatal("expected a save command to be dispatched async, got nil")
	}

	t.Chdir(t.TempDir())
	msg := cmd()
	saved, ok := msg.(remoteSaveAllMsg)
	if !ok {
		t.Fatalf("expected remoteSaveAllMsg, got %T", msg)
	}
	if saved.err != nil {
		t.Fatalf("unexpected save error: %v", saved.err)
	}
	if saved.count != 2 {
		t.Fatalf("expected 2 saved files, got %d", saved.count)
	}
}
