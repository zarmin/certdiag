package tui

import (
	"strings"
	"testing"
)

func TestOptionsModel_NewFromSnapshot(t *testing.T) {
	snap := scanOptionSnapshot{
		Recursive:         true,
		MaxDepth:          4,
		FileSignatureScan: false,
		AutoDiscover:      true,
	}
	m := newOptionsModel(snap, nil)

	if !m.bools["recursive"] {
		t.Fatal("expected recursive=true")
	}
	if m.bools["signature_scan"] {
		t.Fatal("expected signature_scan=false")
	}
	if !m.bools["auto_discover"] {
		t.Fatal("expected auto_discover=true")
	}
	if m.ints["max_depth"] != 4 {
		t.Fatalf("expected max_depth=4, got %d", m.ints["max_depth"])
	}
	if m.changed {
		t.Fatal("expected changed=false on new model")
	}
	if m.cursor != 0 {
		t.Fatalf("expected cursor=0, got %d", m.cursor)
	}
}

func TestOptionsModel_ToggleBool(t *testing.T) {
	m := newOptionsModel(scanOptionSnapshot{}, nil)

	if m.bools["recursive"] {
		t.Fatal("expected recursive=false initially")
	}
	m.toggleBool("recursive")
	if !m.bools["recursive"] {
		t.Fatal("expected recursive=true after toggle")
	}
	if !m.changed {
		t.Fatal("expected changed=true after toggle")
	}

	m.toggleBool("recursive")
	if m.bools["recursive"] {
		t.Fatal("expected recursive=false after second toggle")
	}
}

func TestOptionsModel_ToggleBool_Locked(t *testing.T) {
	locked := map[string]bool{"recursive": true}
	m := newOptionsModel(scanOptionSnapshot{}, locked)

	m.toggleBool("recursive")
	if m.bools["recursive"] {
		t.Fatal("expected recursive unchanged when locked")
	}
	if m.changed {
		t.Fatal("expected changed=false when toggle on locked key")
	}
}

func TestOptionsModel_AdjustInt(t *testing.T) {
	m := newOptionsModel(scanOptionSnapshot{MaxDepth: 3}, nil)

	m.adjustInt("max_depth", 1)
	if m.ints["max_depth"] != 4 {
		t.Fatalf("expected max_depth=4, got %d", m.ints["max_depth"])
	}
	if !m.changed {
		t.Fatal("expected changed=true after adjustInt")
	}

	m.adjustInt("max_depth", -2)
	if m.ints["max_depth"] != 2 {
		t.Fatalf("expected max_depth=2, got %d", m.ints["max_depth"])
	}
}

func TestOptionsModel_AdjustInt_Clamp(t *testing.T) {
	m := newOptionsModel(scanOptionSnapshot{MaxDepth: 1}, nil)

	m.adjustInt("max_depth", -5)
	if m.ints["max_depth"] != 0 {
		t.Fatalf("expected max_depth clamped to 0, got %d", m.ints["max_depth"])
	}

	m.ints["max_depth"] = 9
	m.adjustInt("max_depth", 5)
	if m.ints["max_depth"] != 10 {
		t.Fatalf("expected max_depth clamped to 10, got %d", m.ints["max_depth"])
	}
}

func TestOptionsModel_AdjustInt_Locked(t *testing.T) {
	locked := map[string]bool{"max_depth": true}
	m := newOptionsModel(scanOptionSnapshot{MaxDepth: 3}, locked)

	m.adjustInt("max_depth", 1)
	if m.ints["max_depth"] != 3 {
		t.Fatalf("expected max_depth unchanged at 3, got %d", m.ints["max_depth"])
	}
	if m.changed {
		t.Fatal("expected changed=false when adjusting locked key")
	}
}

func TestOptionsModel_Snapshot(t *testing.T) {
	m := newOptionsModel(scanOptionSnapshot{}, nil)
	m.toggleBool("recursive")
	m.toggleBool("auto_discover")
	m.adjustInt("max_depth", 6)

	snap := m.snapshot()
	if !snap.Recursive {
		t.Fatal("snapshot: expected Recursive=true")
	}
	if !snap.AutoDiscover {
		t.Fatal("snapshot: expected AutoDiscover=true")
	}
	if snap.MaxDepth != 6 {
		t.Fatalf("snapshot: expected MaxDepth=6, got %d", snap.MaxDepth)
	}
	if snap.FileSignatureScan {
		t.Fatal("snapshot: expected FileSignatureScan=false")
	}
}

func TestOptionsModel_View_ShowsLockAnnotation(t *testing.T) {
	initStyles()
	locked := map[string]bool{"recursive": true}
	m := newOptionsModel(scanOptionSnapshot{}, locked)

	rendered := m.view(80)
	if !strings.Contains(rendered, "(--recursive)") {
		t.Fatal("expected lock annotation (--recursive) in view output")
	}
}

func TestOptionsModel_View_ShowsCheckboxes(t *testing.T) {
	initStyles()
	snap := scanOptionSnapshot{Recursive: true, FileSignatureScan: false}
	m := newOptionsModel(snap, nil)

	rendered := m.view(80)
	if !strings.Contains(rendered, "[x]") {
		t.Fatal("expected [x] for true bools in view output")
	}
	if !strings.Contains(rendered, "[ ]") {
		t.Fatal("expected [ ] for false bools in view output")
	}
}
