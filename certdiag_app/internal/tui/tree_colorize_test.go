package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"
)

func colorizeTestNode() TreeNode {
	return TreeNode{
		Filename:    "cert.pem",
		ContentType: "CERTIFICATE",
		Subject:     "example.com",
		Expiry:      "2025-01-01",
		ExpiryTime:  time.Now().Add(365 * 24 * time.Hour),
	}
}

func assertExpiryAligned(t *testing.T, cols colWidths, node TreeNode) {
	t.Helper()

	prefix := buildNodePrefix(node, []TreeNode{node}, 0)
	plainRow := formatNodeLine(cols, node, prefix, 0, displayTruncate, 0, false)
	colored := colorizeExpiryInRow(plainRow, cols, node)

	wantStyled := expiryStyle(node.ExpiryTime).Render(node.Expiry)
	if !strings.Contains(wantStyled, "\x1b[") {
		t.Fatalf("color not forced: styled expiry has no escape: %q", wantStyled)
	}
	if !strings.Contains(colored, wantStyled) {
		t.Fatalf("colored region misaligned: %q does not wrap full expiry %q", colored, wantStyled)
	}

	if got := ansi.Strip(colored); got != plainRow {
		t.Fatalf("colorize changed visible text: got %q want %q", got, plainRow)
	}

	idx := strings.Index(plainRow, node.Expiry)
	if idx < 0 {
		t.Fatalf("expiry text not present in row: %q", plainRow)
	}
	if !strings.HasPrefix(colored, plainRow[:idx]+"\x1b") {
		t.Fatalf("color escape does not start at expiry text position %d in %q", idx, colored)
	}
}

func TestColorizeExpiryAlignsWithZeroWidthColumn(t *testing.T) {
	prevProfile := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.ANSI)
	defer lipgloss.SetColorProfile(prevProfile)
	prevNoColor := noColor
	noColor = false
	defer func() { noColor = prevNoColor }()

	cols := calcColWidths([]string{"subject", "expiry"}, 20)
	if cols.opt["subject"] != 0 {
		t.Fatalf("expected subject column to collapse to width 0, got %d", cols.opt["subject"])
	}
	assertExpiryAligned(t, cols, colorizeTestNode())
}

func TestColorizeExpiryWideTerminal(t *testing.T) {
	prevProfile := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.ANSI)
	defer lipgloss.SetColorProfile(prevProfile)
	prevNoColor := noColor
	noColor = false
	defer func() { noColor = prevNoColor }()

	cols := calcColWidths([]string{"subject", "expiry"}, 200)
	if cols.opt["subject"] == 0 {
		t.Fatalf("expected subject column to have positive width on wide terminal")
	}
	assertExpiryAligned(t, cols, colorizeTestNode())
}
