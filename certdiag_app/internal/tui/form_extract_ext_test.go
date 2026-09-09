package tui

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

// TestExtractSingleForm_FormatSwitchRewritesPresetExt reproduces bug #38: switching
// the output format must rewrite the preset output_file's extension so DER bytes are
// not written into a .pem file.
func TestExtractSingleForm_FormatSwitchRewritesPresetExt(t *testing.T) {
	cert := selfSigned(t, "leaf")
	item := certlib.CertItem{Type: certlib.ContentCertificate, Certificate: cert, RawBytes: cert.Raw}
	node := &TreeNode{
		Container: &certlib.CertContainer{FilePath: "/tmp/bundle.pem"},
		Item:      &item,
		IsChild:   true,
		ItemIdx:   0,
		Subject:   "CN=leaf",
	}

	f := buildExtractSingleForm(node)
	if f == nil {
		t.Fatal("buildExtractSingleForm returned nil")
	}

	preset := f.fieldValue("output_file")
	if !strings.HasSuffix(preset, "-cert.pem") {
		t.Fatalf("expected preset ending in -cert.pem, got %q", preset)
	}

	f.fieldByName("format").SetValue(labelDER)
	f.evaluateVisibility()
	if got := f.fieldValue("output_file"); !strings.HasSuffix(got, "-cert.der") {
		t.Errorf("after switch to DER, want -cert.der, got %q", got)
	}

	f.fieldByName("format").SetValue(labelPEM)
	f.evaluateVisibility()
	if got := f.fieldValue("output_file"); !strings.HasSuffix(got, "-cert.pem") {
		t.Errorf("after switch back to PEM, want -cert.pem, got %q", got)
	}
}

// TestRewriteOutputExt covers the shared rewrite helper across formats and the
// custom-extension preservation case.
func TestRewriteOutputExt(t *testing.T) {
	base := filepath.Join("/tmp", "bundle-1-cert.pem")

	cases := []struct {
		format string
		want   string
	}{
		{labelDER, ".der"},
		{labelPEM, ".pem"},
		{labelPKCS12, ".p12"},
		{labelJKS, ".jks"},
		{labelPKCS7, ".p7b"},
	}
	for _, c := range cases {
		got := rewriteOutputExt(base, c.format)
		if filepath.Ext(got) != c.want {
			t.Errorf("format %s: want ext %s, got %q", c.format, c.want, got)
		}
	}

	// A custom, non-format extension must be preserved untouched.
	custom := filepath.Join("/tmp", "myfile.dump")
	if got := rewriteOutputExt(custom, labelDER); got != custom {
		t.Errorf("custom extension should be preserved, got %q", got)
	}
}
