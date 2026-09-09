package tui

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
)

func makeCertWithSANs(t *testing.T, sans []string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "san-test.example.com"},
		DNSNames:     sans,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func makeSANDetailNode(cert *x509.Certificate) TreeNode {
	return TreeNode{
		ItemIdx:     0,
		Filename:    "san.pem",
		ContentType: "pem/cert",
		Item:        &certlib.CertItem{Type: certlib.ContentCertificate, Certificate: cert},
		Container:   &certlib.CertContainer{FilePath: "/tmp/san.pem"},
	}
}

func manySANs() []string {
	var sans []string
	for i := 0; i < 14; i++ {
		sans = append(sans, fmt.Sprintf("hostnode-%02d.example.com", i))
	}
	return sans
}

func TestWrapDetailValue_CJKDisplayWidth(t *testing.T) {
	const n = 20
	value := strings.Repeat("中", n) // each CJK glyph is 2 display cells
	maxW := 10

	chunks := wrapDetailValue(value, maxW)

	// Layout uses display width: n glyphs occupy 2n cells, so the value must
	// wrap into ceil(2n/maxW) chunks, not the ceil(n/maxW) a rune count gives.
	wantChunks := (2*n + maxW - 1) / maxW
	if len(chunks) != wantChunks {
		t.Fatalf("wrapped into %d chunks, want %d (display-width wrapping)", len(chunks), wantChunks)
	}

	for _, chunk := range chunks {
		if w := lipgloss.Width(chunk); w > maxW {
			t.Fatalf("chunk display width %d exceeds maxW %d: %q", w, maxW, chunk)
		}
		if !utf8.ValidString(chunk) {
			t.Fatalf("chunk is not valid UTF-8 (rune cut mid-character): %q", chunk)
		}
	}

	if got := strings.Join(chunks, ""); got != value {
		t.Fatalf("wrapped content changed: got %q want %q", got, value)
	}
}

func TestWrapDetailValue_ASCIIRegression(t *testing.T) {
	value := strings.Repeat("a", 20)
	maxW := 10

	chunks := wrapDetailValue(value, maxW)

	// For pure ASCII display width equals rune count, so layout is unchanged.
	wantChunks := (len(value) + maxW - 1) / maxW
	if len(chunks) != wantChunks {
		t.Fatalf("ASCII wrapped into %d chunks, want %d", len(chunks), wantChunks)
	}
	for _, chunk := range chunks {
		if w := lipgloss.Width(chunk); w > maxW {
			t.Fatalf("ASCII chunk display width %d exceeds maxW %d: %q", w, maxW, chunk)
		}
	}
	if got := strings.Join(chunks, ""); got != value {
		t.Fatalf("ASCII wrapped content changed: got %q want %q", got, value)
	}
}

func TestDetail_NarrowFullscreenNoCharLoss(t *testing.T) {
	initStyles()
	prev := noColor
	noColor = true
	defer func() { noColor = prev }()

	sans := manySANs()
	node := makeSANDetailNode(makeCertWithSANs(t, sans))

	width, height := 74, 20 // fullscreen: height < splitScreenMinHeight
	innerW := detailInnerWidth(width, height)

	d := newDetailModel(node, nil, nil, output.OutputOptions{}, width, height)

	if d.width != innerW {
		t.Fatalf("detail wrap width = %d, want inner render width %d", d.width, innerW)
	}

	// Every wrapped line must fit the inner render width; otherwise the
	// render pass would truncate it a second time and drop characters.
	for _, line := range d.contentLines {
		if w := runeWidth(line.text); w > innerW {
			t.Fatalf("content line width %d exceeds inner width %d: %q", w, innerW, line.text)
		}
	}

	// All SANs survive the wrap intact (no double-truncation loss).
	var joined strings.Builder
	for _, l := range d.contentLines {
		joined.WriteString(l.text)
		joined.WriteString("\n")
	}
	all := joined.String()
	for _, s := range sans {
		if !strings.Contains(all, "DNS:"+s) {
			t.Fatalf("SAN %q lost after wrapping at inner width", s)
		}
	}

	// Scroll a wide SANs line into view and confirm the render does not
	// truncate it (pre-fix it was wrapped wider than innerW, then cut).
	sansIdx := -1
	for i, l := range d.contentLines {
		if strings.HasPrefix(l.text, "SANs") {
			sansIdx = i
			break
		}
	}
	if sansIdx < 0 {
		t.Fatal("SANs line not found in detail content")
	}
	d.cursorLine = sansIdx
	rendered := renderDetailFullscreen(d, width, height)
	if !strings.Contains(rendered, d.contentLines[sansIdx].text) {
		t.Fatalf("SANs line truncated in render: %q", d.contentLines[sansIdx].text)
	}
}

func TestDetail_ResizeRewrapsToNewInnerWidth(t *testing.T) {
	m := makeTestRootModel()

	sans := manySANs()
	node := makeSANDetailNode(makeCertWithSANs(t, sans))

	m.width, m.height = 74, 20
	m.detail = newDetailModel(node, nil, nil, output.OutputOptions{}, m.width, m.height)
	m.state = stateSplit
	m.focus = focusDetail

	narrowInner := m.detail.width
	if narrowInner != detailInnerWidth(74, 20) {
		t.Fatalf("initial wrap width = %d, want %d", narrowInner, detailInnerWidth(74, 20))
	}

	res, _ := m.Update(tea.WindowSizeMsg{Width: 200, Height: 40})
	rm := res.(RootModel)

	if rm.detail == nil {
		t.Fatal("detail dropped on resize")
	}
	wideInner := detailInnerWidth(200, 40)
	if rm.detail.width != wideInner {
		t.Fatalf("detail not re-wrapped after resize: width=%d, want %d", rm.detail.width, wideInner)
	}
	if rm.detail.width <= narrowInner {
		t.Fatalf("expected wider wrap width after resize: narrow=%d wide=%d", narrowInner, rm.detail.width)
	}

	var joined strings.Builder
	for _, l := range rm.detail.contentLines {
		joined.WriteString(l.text)
		joined.WriteString("\n")
	}
	all := joined.String()
	for _, s := range sans {
		if !strings.Contains(all, "DNS:"+s) {
			t.Fatalf("SAN %q lost after resize re-wrap", s)
		}
	}
}
