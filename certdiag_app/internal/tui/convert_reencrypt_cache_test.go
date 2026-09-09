package tui

import (
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func hasPassword(pws []certlib.TaggedPassword, want string) bool {
	for _, p := range pws {
		if string(p.Password) == want {
			return true
		}
	}
	return false
}

// TestConvertOptions_WiresPasswordCache verifies the fix: buildConvertOptions
// merges the session password cache into InputPasswords, so a multi-password
// JKS whose extra entry password is already known this session can be read.
func TestConvertOptions_WiresPasswordCache(t *testing.T) {
	cache := []certlib.TaggedPassword{{Password: []byte("entry-b-pass")}}
	node := &TreeNode{Container: &certlib.CertContainer{FilePath: "/tmp/store.jks"}, Subject: "CN=store"}
	f := buildConvertForm("/tmp", node)
	if f == nil {
		t.Fatal("buildConvertForm returned nil")
	}
	f.fieldByName("output").SetValue("/tmp/out.jks")
	f.evaluateVisibility()

	opts, err := buildConvertOptions(f, cache)
	if err != nil {
		t.Fatal(err)
	}
	if !hasPassword(opts.InputPasswords, "entry-b-pass") {
		t.Errorf("cached password not merged into InputPasswords: %v", opts.InputPasswords)
	}
}

// TestReencryptOptions_WiresPasswordCache verifies the same for reencrypt: the
// cache reaches OldPasswords so the locked-entry guard is not triggered for a
// password the user already supplied this session.
func TestReencryptOptions_WiresPasswordCache(t *testing.T) {
	cache := []certlib.TaggedPassword{{Password: []byte("entry-b-pass")}}
	node := &TreeNode{Container: &certlib.CertContainer{FilePath: "/tmp/store.jks"}, Subject: "CN=store"}
	f := buildReencryptForm("/tmp", node)
	if f == nil {
		t.Fatal("buildReencryptForm returned nil")
	}
	f.evaluateVisibility()

	opts, err := buildReencryptOptions(f, cache)
	if err != nil {
		t.Fatal(err)
	}
	if !hasPassword(opts.OldPasswords, "entry-b-pass") {
		t.Errorf("cached password not merged into OldPasswords: %v", opts.OldPasswords)
	}
}
