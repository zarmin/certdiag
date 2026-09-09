package tui

import (
	"os"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
)

// ---------------------------------------------------------------------------
// NewRootModel
// ---------------------------------------------------------------------------

func TestNewRootModel_Basic(t *testing.T) {
	tmpDir := t.TempDir()

	// Ensure NO_COLOR is set so initStyles doesn't allocate terminal styles
	os.Setenv("NO_COLOR", "1")
	defer os.Unsetenv("NO_COLOR")
	noColor = true

	scanOpts := certlib.ScanOptions{}
	opts := output.OutputOptions{}
	tuiOpts := TUIOptions{}

	m := NewRootModel(tmpDir, scanOpts, false, opts, tuiOpts)

	if m.scanPath != tmpDir {
		t.Errorf("scanPath = %q, want %q", m.scanPath, tmpDir)
	}

	if m.state != stateLoading {
		t.Errorf("initial state = %d, want stateLoading (%d)", m.state, stateLoading)
	}

	if m.passwordCache == nil {
		t.Error("passwordCache should be non-nil")
	}

	if m.scanProgress == nil {
		t.Error("scanProgress should be non-nil")
	}
}

func TestNewRootModel_PathDisplay(t *testing.T) {
	tmpDir := t.TempDir()

	os.Setenv("NO_COLOR", "1")
	defer os.Unsetenv("NO_COLOR")
	noColor = true

	tests := []struct {
		name        string
		pathDisplay string
		want        string
	}{
		{"default_is_filename", "", "filename"},
		{"explicit_relative", "relative", "relative"},
		{"explicit_absolute", "absolute", "absolute"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewRootModel(tmpDir, certlib.ScanOptions{}, false, output.OutputOptions{}, TUIOptions{
				PathDisplay: tt.pathDisplay,
			})
			if m.pathDisplay != tt.want {
				t.Errorf("pathDisplay = %q, want %q", m.pathDisplay, tt.want)
			}
		})
	}
}

func TestNewRootModel_TUIOptions(t *testing.T) {
	tmpDir := t.TempDir()

	os.Setenv("NO_COLOR", "1")
	defer os.Unsetenv("NO_COLOR")
	noColor = true

	tuiOpts := TUIOptions{
		SubjectOrg:     "TestOrg",
		SubjectCountry: "DE",
		StatusMessage:  "test status",
		DefaultDays:    730,
		DefaultCADays:  7300,
		DisabledChecks: []string{"check1", "check2"},
	}

	m := NewRootModel(tmpDir, certlib.ScanOptions{}, false, output.OutputOptions{}, tuiOpts)

	if m.subjectOrg != "TestOrg" {
		t.Errorf("subjectOrg = %q, want %q", m.subjectOrg, "TestOrg")
	}
	if m.subjectCountry != "DE" {
		t.Errorf("subjectCountry = %q, want %q", m.subjectCountry, "DE")
	}
	if m.statusMessage != "test status" {
		t.Errorf("statusMessage = %q, want %q", m.statusMessage, "test status")
	}
	if m.defaultDays != 730 {
		t.Errorf("defaultDays = %d, want 730", m.defaultDays)
	}
	if m.defaultCADays != 7300 {
		t.Errorf("defaultCADays = %d, want 7300", m.defaultCADays)
	}
	if len(m.disabledChecks) != 2 {
		t.Errorf("disabledChecks length = %d, want 2", len(m.disabledChecks))
	}
}

func TestNewRootModel_Discover(t *testing.T) {
	tmpDir := t.TempDir()

	os.Setenv("NO_COLOR", "1")
	defer os.Unsetenv("NO_COLOR")
	noColor = true

	m := NewRootModel(tmpDir, certlib.ScanOptions{}, true, output.OutputOptions{}, TUIOptions{})

	if !m.discover {
		t.Error("discover should be true")
	}
}

func TestNewRootModel_ScanOptions(t *testing.T) {
	tmpDir := t.TempDir()

	os.Setenv("NO_COLOR", "1")
	defer os.Unsetenv("NO_COLOR")
	noColor = true

	scanOpts := certlib.ScanOptions{
		Recursive:        true,
		MaxDepth:         3,
		UseSignatureScan: true,
	}

	m := NewRootModel(tmpDir, scanOpts, false, output.OutputOptions{}, TUIOptions{})

	if !m.scanOpts.Recursive {
		t.Error("scanOpts.Recursive should be true")
	}
	if m.scanOpts.MaxDepth != 3 {
		t.Errorf("scanOpts.MaxDepth = %d, want 3", m.scanOpts.MaxDepth)
	}
	if !m.scanOpts.UseSignatureScan {
		t.Error("scanOpts.UseSignatureScan should be true")
	}
}

// ---------------------------------------------------------------------------
// applyOptionsSnapshot / currentScanSnapshot round-trip
// ---------------------------------------------------------------------------

func TestScanOptionSnapshotRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()

	os.Setenv("NO_COLOR", "1")
	defer os.Unsetenv("NO_COLOR")
	noColor = true

	m := NewRootModel(tmpDir, certlib.ScanOptions{
		Recursive:        true,
		MaxDepth:         5,
		UseSignatureScan: true,
	}, true, output.OutputOptions{}, TUIOptions{PathDisplay: "relative"})

	snap := m.currentScanSnapshot()

	if !snap.Recursive {
		t.Error("snapshot Recursive should be true")
	}
	if snap.MaxDepth != 5 {
		t.Errorf("snapshot MaxDepth = %d, want 5", snap.MaxDepth)
	}
	if !snap.FileSignatureScan {
		t.Error("snapshot FileSignatureScan should be true")
	}
	if !snap.AutoDiscover {
		t.Error("snapshot AutoDiscover should be true")
	}
	if snap.PathDisplay != "relative" {
		t.Errorf("snapshot PathDisplay = %q, want %q", snap.PathDisplay, "relative")
	}

	// Modify the model
	m.scanOpts.Recursive = false
	m.scanOpts.MaxDepth = 0
	m.discover = false
	m.pathDisplay = "filename"

	// Apply the old snapshot back
	m.applyOptionsSnapshot(snap)

	if !m.scanOpts.Recursive {
		t.Error("after apply, Recursive should be true")
	}
	if m.scanOpts.MaxDepth != 5 {
		t.Errorf("after apply, MaxDepth = %d, want 5", m.scanOpts.MaxDepth)
	}
	if !m.discover {
		t.Error("after apply, discover should be true")
	}
	if m.pathDisplay != "relative" {
		t.Errorf("after apply, pathDisplay = %q, want %q", m.pathDisplay, "relative")
	}
}
