package tui

import (
	"testing"

	"github.com/atotto/clipboard"
)

func TestCopyToClipboard_UnsupportedSurfacesError(t *testing.T) {
	prev := clipboard.Unsupported
	clipboard.Unsupported = true
	defer func() { clipboard.Unsupported = prev }()

	m := &RootModel{}
	m.copyToClipboard("some value")

	if m.popup.kind != popupError {
		t.Fatalf("unsupported clipboard: popup kind=%v, want popupError", m.popup.kind)
	}
	if m.statusMessage == "Copied to clipboard" {
		t.Fatalf("unsupported clipboard falsely reported success")
	}
}

func TestCopyToClipboard_SuccessReportsCopied(t *testing.T) {
	prev := clipboard.Unsupported
	clipboard.Unsupported = false
	defer func() { clipboard.Unsupported = prev }()

	if err := clipboard.WriteAll("probe"); err != nil {
		t.Skipf("clipboard not writable in this environment: %v", err)
	}

	m := &RootModel{}
	m.copyToClipboard("some value")

	if m.popup.kind == popupError {
		t.Fatalf("successful clipboard write surfaced an error popup")
	}
	if m.statusMessage != "Copied to clipboard" {
		t.Fatalf("successful clipboard write: statusMessage=%q, want %q", m.statusMessage, "Copied to clipboard")
	}
}
