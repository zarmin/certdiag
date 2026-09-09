package certops

import (
	"path/filepath"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

// TestBundle_InputItemsOnlyBundlesSelected verifies the fix: with InputItems set,
// Bundle includes exactly those items (not whole files) and aliases align to the
// provided items.
func TestBundle_InputItemsOnlyBundlesSelected(t *testing.T) {
	dir := t.TempDir()
	caKey, caCert := jksTestCA(t)
	_, certY := jksTestLeaf(t, "certY-SELECTED", 2, caKey, caCert)

	out := filepath.Join(dir, "out.jks")
	// Only certY is selected; alias intended for it at index 0.
	res, err := Bundle(BundleOptions{
		InputItems:     []certlib.CertItem{{Type: certlib.ContentCertificate, Certificate: certY, RawBytes: certY.Raw}},
		OutputPath:     out,
		OutputFormat:   certlib.FormatJKS,
		OutputPassword: []byte("storepw"),
		Aliases:        map[int]string{0: "alias-for-certy"},
		AutoChain:      false,
		IncludeRoot:    true,
	})
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}
	if res.ItemCount != 1 {
		t.Errorf("expected exactly 1 bundled item (the selected cert), got %d", res.ItemCount)
	}

	c, err := certlib.ReadFile(out, []certlib.TaggedPassword{{Password: []byte("storepw")}})
	if err != nil {
		t.Fatal(err)
	}
	var cns, aliases []string
	for _, it := range c.Items {
		if it.Type == certlib.ContentCertificate && it.Certificate != nil {
			cns = append(cns, it.Certificate.Subject.CommonName)
			aliases = append(aliases, it.Alias)
		}
	}
	t.Logf("bundled certs=%v aliases=%v", cns, aliases)

	for _, cn := range cns {
		if cn == "certX-UNSELECTED" {
			t.Error("unselected cert X was bundled")
		}
	}
	if len(cns) != 1 || cns[0] != "certY-SELECTED" {
		t.Fatalf("expected only certY-SELECTED, got %v", cns)
	}
	if len(aliases) != 1 || aliases[0] != "alias-for-certy" {
		t.Errorf("alias did not land on the selected cert: %v", aliases)
	}
}
