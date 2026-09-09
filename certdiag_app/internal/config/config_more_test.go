package config

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestMatchByFilename(t *testing.T) {
	var nilCfg *ConfigFile
	if nilCfg.MatchByFilename("/a.p12") != nil {
		t.Error("nil config matches nothing")
	}
	cfg := &ConfigFile{}
	cfg.Passwords.ByFilename = []FilenamePassword{
		{Filename: "*.p12", PlaintextPassword: "a"},
		{Filepath: "/exact/store.jks", PlaintextPassword: "b"},
	}
	if m := cfg.MatchByFilename("/dir/site.p12"); len(m) != 1 || m[0].PlaintextPassword != "a" {
		t.Errorf("glob: %+v", m)
	}
	if m := cfg.MatchByFilename("/exact/store.jks"); len(m) != 1 || m[0].PlaintextPassword != "b" {
		t.Errorf("filepath: %+v", m)
	}
	if m := cfg.MatchByFilename("/other/store.jks"); len(m) != 0 {
		t.Errorf("no match expected: %+v", m)
	}
}

func TestHasEncryptedPasswords(t *testing.T) {
	var nilCfg *ConfigFile
	if nilCfg.HasEncryptedPasswords() {
		t.Error("nil")
	}
	cfg := &ConfigFile{}
	if cfg.HasEncryptedPasswords() {
		t.Error("empty")
	}
	cfg.Passwords.ByFilename = []FilenamePassword{{Filename: "x", EncryptedPassword: "enc"}}
	if !cfg.HasEncryptedPasswords() {
		t.Error("by_filename encrypted")
	}
	cfg = &ConfigFile{}
	cfg.Passwords.CommonEncrypted = []string{"enc"}
	if !cfg.HasEncryptedPasswords() {
		t.Error("common_encrypted")
	}
}

func TestGenerationDefaults(t *testing.T) {
	var nilCfg *ConfigFile
	if k := nilCfg.GetKeyDefaults(); k.Algorithm != "ecdsa" || k.KeySize != 2048 || k.Curve != "p256" {
		t.Errorf("nil key defaults %+v", k)
	}
	if s := nilCfg.GetSubjectDefaults(); s.CommonName != "" || len(s.Organization) != 0 {
		t.Errorf("nil subject defaults %+v", s)
	}
	if c := nilCfg.GetCertDefaults(); c.Days != 365 || c.CADays != 3650 {
		t.Errorf("nil cert defaults %+v", c)
	}
	org := "Example Org"
	cfg := &ConfigFile{}
	cfg.Defaults.Key.Algorithm = "rsa"
	cfg.Defaults.Key.RSAKeySize = 4096
	cfg.Defaults.Subject.Organization = &org
	cfg.Defaults.Subject.Country = "HU"
	cfg.Defaults.Cert.Days = 90
	cfg.Defaults.Cert.KeyUsage = []string{"digitalSignature"}
	cfg.Defaults.Cert.ExtKeyUsage = []string{"clientAuth"}
	if k := cfg.GetKeyDefaults(); k.Algorithm != "rsa" || k.KeySize != 4096 {
		t.Errorf("key defaults %+v", k)
	}
	if s := cfg.GetSubjectDefaults(); len(s.Organization) != 1 || s.Organization[0] != org || len(s.Country) != 1 {
		t.Errorf("subject defaults %+v", s)
	}
	c := cfg.GetCertDefaults()
	if c.Days != 90 || c.KeyUsage != x509.KeyUsageDigitalSignature || len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("cert defaults %+v", c)
	}
}

func TestTUIDefaults(t *testing.T) {
	if cols := ActiveColumns(nil); len(cols) == 0 {
		t.Error("default columns")
	}
	if cols := ActiveStoreColumns(nil); len(cols) == 0 {
		t.Error("default store columns")
	}
	if g := StoreGrouping(nil); g != "instance" {
		t.Errorf("default grouping %q", g)
	}
	cfg := &ConfigFile{}
	cfg.Defaults.TUI.Columns = []string{"subject"}
	cfg.Defaults.TUI.TrustStoreColumns = []string{"trust"}
	cfg.Defaults.TUI.TrustStoreGrouping = "type"
	if cols := ActiveColumns(cfg); len(cols) != 1 || cols[0] != "subject" {
		t.Errorf("columns %v", cols)
	}
	if cols := ActiveStoreColumns(cfg); len(cols) != 1 || cols[0] != "trust" {
		t.Errorf("store columns %v", cols)
	}
	if g := StoreGrouping(cfg); g != "type" {
		t.Errorf("grouping %q", g)
	}
}

func TestAIACacheDir_UnderHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dir, err := AIACacheDir()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(dir, home) || filepath.Base(dir) != AIACacheDirName {
		t.Errorf("AIACacheDir = %q", dir)
	}
}

func TestRewriteTrustStoreOptions_RoundTrip(t *testing.T) {
	raw := []byte("# keep me\nkind: certdiag-config\nversion: \"1\"\ndefaults:\n  tui:\n    columns: [subject]\n")
	out, err := RewriteTrustStoreOptions(raw, []string{"trust", "stores"}, "type")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "# keep me") {
		t.Error("comments must survive the rewrite")
	}
	var cfg ConfigFile
	if err := yaml.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Defaults.TUI.TrustStoreColumns) != 2 || cfg.Defaults.TUI.TrustStoreGrouping != "type" {
		t.Errorf("rewritten: %+v", cfg.Defaults.TUI)
	}
	if len(cfg.Defaults.TUI.Columns) != 1 || cfg.Defaults.TUI.Columns[0] != "subject" {
		t.Errorf("the lister's own columns must be untouched: %v", cfg.Defaults.TUI.Columns)
	}
	if _, err := RewriteTrustStoreOptions([]byte("- not a mapping\n"), nil, ""); err == nil {
		t.Error("a non-mapping document must be refused")
	}
	_ = os.Stderr
}
