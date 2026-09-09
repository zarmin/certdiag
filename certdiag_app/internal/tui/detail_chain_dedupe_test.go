package tui

import (
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

// TestDetail_IdenticalChainsCollapse guards M14: the same chain through four
// copies of one certificate is one line with a count, not four lines.
func TestDetail_IdenticalChainsCollapse(t *testing.T) {
	root, rootKey := tuiChainCert(t, "Dup Root", true, nil, nil)
	inter, interKey := tuiChainCert(t, "Dup Intermediate", true, root, rootKey)
	leaf, _ := tuiChainCert(t, "dup.example", false, inter, interKey)

	store := storeOf(t, root, inter, leaf)
	for _, name := range []string{"/tmp/copy1.pem", "/tmp/copy2.pem", "/tmp/copy3.pem"} {
		store.AddContainer(certlib.CertContainer{
			FilePath: name, Format: certlib.FormatPEM, Source: certlib.SourceFile,
			Items: []certlib.CertItem{{Type: certlib.ContentCertificate, Certificate: leaf, RawBytes: leaf.Raw}},
		})
	}

	got := detailFor(t, store, "Dup Intermediate")
	if n := countChainLines(got); n != 1 {
		t.Errorf("four copies of one chain must collapse into one line, saw %d:\n%s", n, got)
	}
	if !strings.Contains(got, "(x4)") {
		t.Errorf("the collapsed line must carry the count:\n%s", got)
	}
}
