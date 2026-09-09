package tui

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

func forceColor(t *testing.T) {
	t.Helper()
	prevProfile := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.ANSI)
	prevNoColor := noColor
	noColor = false
	t.Cleanup(func() {
		lipgloss.SetColorProfile(prevProfile)
		noColor = prevNoColor
	})
}

// wellFormedEscape matches a complete SGR sequence. Anything matching
// danglingReset but not part of one of these means a sequence was sliced.
var (
	wellFormedEscape = regexp.MustCompile("\x1b\\[[0-9;]*m")
	danglingReset    = regexp.MustCompile(`\[0m`)
)

// assertNoRawEscapes is the regression guard for the bug that shipped in M28
// and only became visible in M29: colorizeColumnInRow locates a column by rune
// offset in the raw row, so styling columns left to right sliced the next one
// mid-escape and leaked a literal "[0m" into the terminal.
func assertNoRawEscapes(t *testing.T, styled, plain string) {
	t.Helper()

	// Every "[0m" in the output must be the tail of a real escape sequence.
	withoutEscapes := wellFormedEscape.ReplaceAllString(styled, "")
	if loc := danglingReset.FindStringIndex(withoutEscapes); loc != nil {
		t.Errorf("raw ANSI leaked into the row at %d: %q", loc[0], withoutEscapes)
	}

	// Stripping the styling must give back exactly the plain row: same text,
	// same width, same column alignment.
	if got := ansi.Strip(styled); got != plain {
		t.Errorf("styling changed the visible text:\n got  %q\n want %q", got, plain)
	}
	if ansi.StringWidth(styled) != ansi.StringWidth(plain) {
		t.Errorf("styling changed the row width: %d vs %d",
			ansi.StringWidth(styled), ansi.StringWidth(plain))
	}
}

func trustColorNode(trust string, stores []string, withExpiry bool) TreeNode {
	n := TreeNode{
		Filename:    "chain.pem",
		ContentType: "pem/cert",
		Subject:     "example.com",
		Issuer:      "Example Issuing CA",
		Algo:        "ECDSA-P-256",
		Expiry:      "2027-01-01",
		Trust:       trust,
		Stores:      stores,
	}
	if withExpiry {
		n.ExpiryTime = time.Now().Add(365 * 24 * time.Hour)
	}
	return n
}

// TestColorizeRowColumns_NoRawEscapes covers every subset of the three styled
// columns. The failure only appeared when two of them were populated at once,
// which is why a single-column test missed it for a whole milestone.
func TestColorizeRowColumns_NoRawEscapes(t *testing.T) {
	forceColor(t)

	activeCols := []string{"subject", "issuer", "expiry", "algo", colIDTrust, colIDStores}
	cols := calcColWidths(activeCols, 170)

	cases := []struct {
		name   string
		trust  string
		stores []string
		expiry bool
		inAll  bool
	}{
		{name: "nothing styled"},
		{name: "expiry only", expiry: true},
		{name: "trust only", trust: "TRUSTED"},
		{name: "stores only", stores: []string{"OS", "J21"}},
		{name: "trust and stores", trust: "ANCHOR", stores: []string{"OS", "J21", "MOZ"}},
		{name: "expiry and trust", trust: "UNTRUSTED", expiry: true},
		{name: "expiry and stores", stores: []string{"OS"}, expiry: true},
		{name: "all three", trust: "ANCHOR", stores: []string{"OS", "J21", "SSL", "MOZ", "CHR"}, expiry: true},
		{name: "all three, in every store", trust: "ANCHOR", stores: []string{"OS", "MOZ"}, expiry: true, inAll: true},
		{name: "denied", trust: "DENIED", stores: []string{"OS"}, expiry: true},
		{name: "expired verdict", trust: "EXPIRED", stores: []string{"OS"}, expiry: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			node := trustColorNode(tc.trust, tc.stores, tc.expiry)
			node.StoresInAll = tc.inAll

			prefix := buildNodePrefix(node, []TreeNode{node}, 0)
			plain := formatNodeLine(cols, node, prefix, 0, displayTruncate, 0, false)
			styled := colorizeRowColumns(plain, cols, node)

			assertNoRawEscapes(t, styled, plain)
		})
	}
}

// TestColorizeRowColumns_NarrowTerminal exercises the same paths where columns
// collapse to zero width, which is where offset arithmetic goes wrong.
func TestColorizeRowColumns_NarrowTerminal(t *testing.T) {
	forceColor(t)

	for _, width := range []int{20, 40, 60, 80, 100, 170} {
		t.Run("width"+itoaTest(width), func(t *testing.T) {
			cols := calcColWidths([]string{"subject", "issuer", "expiry", "algo", colIDTrust, colIDStores}, width)
			node := trustColorNode("ANCHOR", []string{"OS", "J21", "MOZ"}, true)

			prefix := buildNodePrefix(node, []TreeNode{node}, 0)
			plain := formatNodeLine(cols, node, prefix, 0, displayTruncate, 0, false)
			styled := colorizeRowColumns(plain, cols, node)

			assertNoRawEscapes(t, styled, plain)
		})
	}
}

// TestColorizeRowColumns_StylesTheRightText: each styled span must wrap the
// column's own value, not a neighbour's.
func TestColorizeRowColumns_StylesTheRightText(t *testing.T) {
	forceColor(t)

	cols := calcColWidths([]string{"subject", "expiry", colIDTrust, colIDStores}, 170)
	node := trustColorNode("ANCHOR", []string{"OS", "J21"}, true)

	prefix := buildNodePrefix(node, []TreeNode{node}, 0)
	plain := formatNodeLine(cols, node, prefix, 0, displayTruncate, 0, false)
	styled := colorizeRowColumns(plain, cols, node)

	if !strings.Contains(styled, trustColumnStyle("ANCHOR")) {
		t.Errorf("expected the verdict to be styled as a whole, got %q", styled)
	}
	wantStores := lipgloss.NewStyle().Foreground(colorAccent).Render("OS J21")
	if !strings.Contains(styled, wantStores) {
		t.Errorf("expected the store tags to be styled as a whole, got %q", styled)
	}
}

// TestColorizeRowColumns_RightToLeftOrder pins the fix itself. Styling a later
// column first leaves the offsets the earlier columns need untouched.
func TestColorizeRowColumns_RightToLeftOrder(t *testing.T) {
	forceColor(t)

	cols := calcColWidths([]string{"expiry", colIDTrust, colIDStores}, 170)
	node := trustColorNode("TRUSTED", []string{"OS"}, true)

	prefix := buildNodePrefix(node, []TreeNode{node}, 0)
	plain := formatNodeLine(cols, node, prefix, 0, displayTruncate, 0, false)

	// Applying the columns left to right is the old, broken order. It must
	// produce a different (and damaged) result from the shipped function, or
	// this test is not guarding anything.
	broken := plain
	broken = colorizeColumnInRow(broken, cols, "expiry", func(s string) string {
		return expiryStyle(node.ExpiryTime).Render(s)
	})
	broken = colorizeColumnInRow(broken, cols, colIDTrust, trustColumnStyle)
	broken = colorizeColumnInRow(broken, cols, colIDStores, func(s string) string {
		return lipgloss.NewStyle().Foreground(colorAccent).Render(s)
	})

	if ansi.Strip(broken) == plain {
		t.Skip("left-to-right happens to be safe at this width; nothing to compare")
	}

	fixed := colorizeRowColumns(plain, cols, node)
	assertNoRawEscapes(t, fixed, plain)
}

func TestTrustColumnStyle(t *testing.T) {
	forceColor(t)

	cases := map[string]lipgloss.Color{
		truststore.VerdictAnchor.Display():    colorGreen,
		truststore.VerdictTrusted.Display():   colorGreen,
		truststore.VerdictDenied.Display():    colorRed,
		truststore.VerdictUntrusted.Display(): colorYellow,
		truststore.VerdictExpired.Display():   colorYellow,
	}
	for display, want := range cases {
		got := trustColumnStyle(display)
		expected := lipgloss.NewStyle().Foreground(want).Render(display)
		if got != expected {
			t.Errorf("%s: expected the %v palette colour, got %q", display, want, got)
		}
	}

	// An unrecognised value must not be coloured as if it were a verdict.
	if got := trustColumnStyle("SOMETHING"); got == lipgloss.NewStyle().Foreground(colorGreen).Render("SOMETHING") {
		t.Error("an unknown verdict must not read as trusted")
	}
}

func TestColorizeRowColumns_NoColorIsPassThrough(t *testing.T) {
	prev := noColor
	noColor = true
	t.Cleanup(func() { noColor = prev })

	cols := calcColWidths([]string{"expiry", colIDTrust, colIDStores}, 170)
	node := trustColorNode("ANCHOR", []string{"OS"}, true)

	prefix := buildNodePrefix(node, []TreeNode{node}, 0)
	plain := formatNodeLine(cols, node, prefix, 0, displayTruncate, 0, false)

	if got := colorizeRowColumns(plain, cols, node); got != plain {
		t.Errorf("NO_COLOR must pass the row through unchanged:\n got  %q\n want %q", got, plain)
	}
}

func TestColorizeRowColumns_NothingToStyle(t *testing.T) {
	forceColor(t)

	cols := calcColWidths([]string{"subject", colIDTrust, colIDStores}, 170)
	node := TreeNode{Filename: "x.pem", ContentType: "pem/cert", Subject: "x"}

	prefix := buildNodePrefix(node, []TreeNode{node}, 0)
	plain := formatNodeLine(cols, node, prefix, 0, displayTruncate, 0, false)

	if got := colorizeRowColumns(plain, cols, node); got != plain {
		t.Error("a row with no trust or expiry data must be returned unchanged")
	}
}

func itoaTest(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
