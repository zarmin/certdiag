package tableformat

import (
	"strings"
	"testing"
)

// TestColumnPriority_DropsLowestFirst: when the width cannot hold every
// column at its minimum, droppable columns disappear in priority order and
// the identity columns keep their minimum (M31 H6, decision D3).
func TestColumnPriority_DropsLowestFirst(t *testing.T) {
	build := func(width int) *Table {
		tb := New(WithWidth(width), WithCompact(true))
		tb.SetHeaders("NAME", "SUBJECT", "EXTRA", "NOTES")
		tb.AddColumn("NAME", ColMinWidth(12))
		tb.AddColumn("SUBJECT", ColMinWidth(16))
		tb.AddColumn("EXTRA", ColMinWidth(8), ColPriority(1))
		tb.AddColumn("NOTES", ColMinWidth(10), ColPriority(2))
		tb.AddRow("averyveryverylongname.pem", "CN=a-subject-that-goes-on-and-on.example.com", "extra extra extra", "notes notes notes notes")
		return tb
	}

	wide, err := build(120).String()
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"NAME", "SUBJECT", "EXTRA", "NOTES"} {
		if !strings.Contains(wide, h) {
			t.Errorf("at 120 cells every column is shown; missing %q:\n%s", h, wide)
		}
	}
	if strings.Contains(wide, "columns hidden") {
		t.Errorf("nothing hidden at 120 cells:\n%s", wide)
	}

	narrow, err := build(40).String()
	if err != nil {
		t.Fatal(err)
	}
	header := strings.SplitN(narrow, "\n", 3)[1] // the header row of the box
	if strings.Contains(header, "NOTES") {
		t.Errorf("NOTES (priority 2) must go first at 40 cells:\n%s", narrow)
	}
	if !strings.Contains(narrow, "columns hidden") || !strings.Contains(narrow, "NOTES") {
		t.Errorf("the footer must name what was hidden:\n%s", narrow)
	}
	if !strings.Contains(header, "NAME") || !strings.Contains(header, "SUBJECT") {
		t.Errorf("identity columns are never hidden:\n%s", narrow)
	}
	if !strings.Contains(narrow, "averyveryver") {
		t.Errorf("name column squeezed below its 12-cell minimum:\n%s", narrow)
	}
}

// TestDetectTerminalWidth_ColumnsEnv: without a terminal (as in go test), the
// COLUMNS variable decides, so piped output matches the shell width.
func TestDetectTerminalWidth_ColumnsEnv(t *testing.T) {
	t.Setenv("COLUMNS", "132")
	if got := detectTerminalWidth(); got != 132 {
		t.Errorf("detectTerminalWidth() = %d, want 132 from COLUMNS", got)
	}
	t.Setenv("COLUMNS", "")
	if got := detectTerminalWidth(); got != 80 {
		t.Errorf("detectTerminalWidth() = %d, want the 80 fallback", got)
	}
}
