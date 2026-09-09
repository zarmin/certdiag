package tableformat

import "testing"

func TestDetectTerminalWidth(t *testing.T) {
	w := detectTerminalWidth()
	if w != 80 {
		t.Logf("detectTerminalWidth() = %d (may be real terminal or fallback)", w)
	}
	if w <= 0 {
		t.Errorf("detectTerminalWidth() = %d, want > 0", w)
	}
}

func TestDetectTerminalWidth_ViaAutoDetect(t *testing.T) {
	tb := New(WithAutoDetect())
	tb.Options.FixWidth = 0
	tb.AddColumn("A")
	tb.AddRow("hello")
	s, err := tb.String()
	if err != nil {
		t.Fatalf("String() error: %v", err)
	}
	if s == "" {
		t.Error("String() returned empty")
	}
}
