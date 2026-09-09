package certops

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

// TestConvertJKS_RefusesWhenKeyEntryLocked verifies the fix: converting a JKS
// whose entries have per-entry passwords not all supplied must refuse (so the
// locked key is not silently dropped) and must not write the output file.
func TestConvertJKS_RefusesWhenKeyEntryLocked(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "store.jks")
	buildTwoPasswordJKS(t, src) // entry ka=storepw, kb=passB
	out := filepath.Join(dir, "out.jks")

	_, err := Convert(ConvertOptions{
		InputPath:      src,
		InputPasswords: []certlib.TaggedPassword{{Password: []byte("storepw")}}, // passB missing
		OutputPath:     out,
		OutputFormat:   certlib.FormatJKS,
		OutputPassword: []byte("newstore"),
	})
	if err == nil {
		t.Fatal("expected convert to refuse (locked key entry would be lost), got nil error")
	}
	t.Logf("convert correctly refused: %v", err)
	if _, statErr := os.Stat(out); statErr == nil {
		t.Error("output file was written despite the refusal")
	}
}

// TestConvertJKS_SucceedsWithAllPasswords is the regression guard: with every
// entry password supplied, convert proceeds and preserves both keys.
func TestConvertJKS_SucceedsWithAllPasswords(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "store.jks")
	buildTwoPasswordJKS(t, src)
	out := filepath.Join(dir, "out.jks")

	_, err := Convert(ConvertOptions{
		InputPath:      src,
		InputPasswords: []certlib.TaggedPassword{{Password: []byte("storepw")}, {Password: []byte("passB")}},
		OutputPath:     out,
		OutputFormat:   certlib.FormatJKS,
		OutputPassword: []byte("newstore"),
	})
	if err != nil {
		t.Fatalf("convert with all passwords should succeed, got: %v", err)
	}
	// Convert preserves each entry's own password (it is a format conversion, not
	// a password change): ka keeps storepw, kb keeps passB; only the store
	// password changes to newstore. Supply all three to read both keys back.
	c, err := certlib.ReadFile(out, []certlib.TaggedPassword{{Password: []byte("newstore")}, {Password: []byte("storepw")}, {Password: []byte("passB")}})
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	keys := 0
	for _, it := range c.Items {
		if it.Type == certlib.ContentPrivateKey && it.PrivateKey != nil {
			keys++
		}
	}
	if keys != 2 {
		t.Errorf("expected 2 keys preserved, got %d", keys)
	}
}

// TestConvertJKS_KeyDroppingFormatDoesNotRefuse verifies the guard only fires
// when the locked key would actually be encoded. Converting to PKCS#7 (which
// holds only certificates) drops the key in the conversion matrix before the
// guard runs, so a locked key entry must not block it.
func TestConvertJKS_KeyDroppingFormatDoesNotRefuse(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "store.jks")
	buildTwoPasswordJKS(t, src)
	out := filepath.Join(dir, "certs.p7b")

	_, err := Convert(ConvertOptions{
		InputPath:      src,
		InputPasswords: []certlib.TaggedPassword{{Password: []byte("storepw")}}, // passB missing
		OutputPath:     out,
		OutputFormat:   certlib.FormatPKCS7,
	})
	if err != nil {
		t.Fatalf("PKCS#7 convert (keys dropped by the matrix) should not refuse over a locked key, got: %v", err)
	}
	if _, statErr := os.Stat(out); statErr != nil {
		t.Errorf("PKCS#7 output not written: %v", statErr)
	}
}
