package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/cmdutil"
	"github.com/zarmin/certdiag/certdiag_app/internal/config"
)

// ---------------------------------------------------------------------------
// flagPassword (root.go)
// ---------------------------------------------------------------------------

func TestFlagPassword(t *testing.T) {
	t.Run("NotChanged", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.Flags().StringP("password", "p", "", "test")
		pw, ok := flagPassword(cmd, "password")
		if ok {
			t.Error("expected ok=false when flag not set")
		}
		if pw != nil {
			t.Errorf("expected nil, got %q", pw)
		}
	})

	t.Run("SetEmpty", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.Flags().StringP("password", "p", "", "test")
		_ = cmd.Flags().Set("password", "")
		pw, ok := flagPassword(cmd, "password")
		if !ok {
			t.Error("expected ok=true when flag explicitly set")
		}
		if string(pw) != "" {
			t.Errorf("expected empty, got %q", pw)
		}
	})

	t.Run("SetValue", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.Flags().StringP("password", "p", "", "test")
		_ = cmd.Flags().Set("password", "secret")
		pw, ok := flagPassword(cmd, "password")
		if !ok {
			t.Error("expected ok=true")
		}
		if string(pw) != "secret" {
			t.Errorf("expected secret, got %q", pw)
		}
	})
}

// ---------------------------------------------------------------------------
// resolveFormat (root.go)
// ---------------------------------------------------------------------------

func TestResolveFormat(t *testing.T) {
	tests := []struct {
		name      string
		format    string
		tableFlag bool
		want      string
		wantErr   bool
	}{
		{"default_is_list", "", false, "list", false},
		{"table_flag", "", true, "table", false},
		{"explicit_list", "list", false, "list", false},
		{"explicit_table", "table", false, "table", false},
		{"explicit_yaml", "yaml", false, "yaml", false},
		{"explicit_json", "json", false, "json", false},
		{"both_flags_error", "json", true, "", true},
		{"unknown_format", "xml", false, "", true},
		{"empty_string_format", "csv", false, "", true},
		{"jsonpath_expr", "jsonpath=$.files[0].filename", false, "jsonpath=$.files[0].filename", false},
		{"jsonpath_empty_suffix_passes_resolve", "jsonpath=", false, "jsonpath=", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveFormat(tt.format, tt.tableFlag)
			if (err != nil) != tt.wantErr {
				t.Errorf("resolveFormat(%q, %v) error = %v, wantErr %v", tt.format, tt.tableFlag, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("resolveFormat(%q, %v) = %q, want %q", tt.format, tt.tableFlag, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseDiffIndex (diff.go)
// ---------------------------------------------------------------------------

func TestParseDiffIndex(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantLeft  int
		wantRight int
		wantErr   bool
	}{
		{"valid_1_1", "1:1", 0, 0, false},
		{"valid_2_3", "2:3", 1, 2, false},
		{"valid_10_20", "10:20", 9, 19, false},
		{"missing_colon", "11", 0, 0, true},
		{"empty_string", "", 0, 0, true},
		{"zero_left", "0:1", 0, 0, true},
		{"zero_right", "1:0", 0, 0, true},
		{"negative_left", "-1:1", 0, 0, true},
		{"negative_right", "1:-1", 0, 0, true},
		{"non_numeric_left", "a:1", 0, 0, true},
		{"non_numeric_right", "1:b", 0, 0, true},
		{"float_left", "1.5:1", 0, 0, true},
		{"extra_colons", "1:2:3", 0, 0, true}, // SplitN(s, ":", 2) gives ["1", "2:3"] -> "2:3" is invalid int
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			left, right, err := parseDiffIndex(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDiffIndex(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if err == nil {
				if left != tt.wantLeft {
					t.Errorf("parseDiffIndex(%q) left = %d, want %d", tt.input, left, tt.wantLeft)
				}
				if right != tt.wantRight {
					t.Errorf("parseDiffIndex(%q) right = %d, want %d", tt.input, right, tt.wantRight)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// resolveCheckSeverity (check.go)
// ---------------------------------------------------------------------------

func TestResolveCheckSeverity(t *testing.T) {
	tests := []struct {
		name string
		sev  string
		want certlib.CheckSeverity
	}{
		{"warning", "warning", certlib.SeverityWarning},
		{"critical", "critical", certlib.SeverityCritical},
		{"info", "info", certlib.SeverityInfo},
		{"case_insensitive_WARNING", "WARNING", certlib.SeverityWarning},
		{"case_insensitive_Critical", "Critical", certlib.SeverityCritical},
		{"unknown_returns_empty", "fatal", ""},
		{"empty_returns_empty", "", ""},
		{"all_returns_empty", "all", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveCheckSeverity(tt.sev)
			if got != tt.want {
				t.Errorf("resolveCheckSeverity(%q) = %q, want %q", tt.sev, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// needsOutputPassword (convert.go)
// ---------------------------------------------------------------------------

func TestNeedsOutputPassword(t *testing.T) {
	tests := []struct {
		name   string
		format certlib.FileFormat
		want   bool
	}{
		{"pkcs12_needs_password", certlib.FormatPKCS12, true},
		{"jks_needs_password", certlib.FormatJKS, true},
		{"pem_no_password", certlib.FormatPEM, false},
		{"der_no_password", certlib.FormatDER, false},
		{"pkcs7_no_password", certlib.FormatPKCS7, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cmdutil.NeedsOutputPassword(tt.format)
			if got != tt.want {
				t.Errorf("cmdutil.NeedsOutputPassword(%q) = %v, want %v", tt.format, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseNotBefore (create_cert.go)
// ---------------------------------------------------------------------------

func TestParseNotBefore(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		check   func(t *testing.T, got time.Time)
	}{
		{
			"yyyy_mm_dd",
			"2025-06-15",
			false,
			func(t *testing.T, got time.Time) {
				if got.Year() != 2025 || got.Month() != 6 || got.Day() != 15 {
					t.Errorf("expected 2025-06-15, got %v", got)
				}
			},
		},
		{
			"rfc3339",
			"2025-06-15T10:30:00Z",
			false,
			func(t *testing.T, got time.Time) {
				if got.Year() != 2025 || got.Hour() != 10 || got.Minute() != 30 {
					t.Errorf("expected 2025-06-15T10:30:00Z, got %v", got)
				}
			},
		},
		{
			"rfc3339_with_offset",
			"2025-06-15T10:30:00+02:00",
			false,
			func(t *testing.T, got time.Time) {
				if got.Year() != 2025 {
					t.Errorf("expected year 2025, got %v", got)
				}
			},
		},
		{"invalid_format", "June 15, 2025", true, nil},
		{"empty_string", "", true, nil},
		{"partial_date", "2025-06", true, nil},
		{"date_with_slashes", "2025/06/15", true, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseNotBefore(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseNotBefore(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if err == nil && tt.check != nil {
				tt.check(t, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// redactPasswords (config_show.go)
// ---------------------------------------------------------------------------

func TestRedactPasswords(t *testing.T) {
	original := &config.ConfigFile{
		Passwords: config.PasswordsConfig{
			CommonPlaintext: []string{"secret1", "secret2"},
			CommonEncrypted: []string{"enc:abc", "enc:def"},
			ByFilename: []config.FilenamePassword{
				{
					Filename:          "server.p12",
					PlaintextPassword: "mypass",
				},
				{
					Filename:          "client.p12",
					EncryptedPassword: "enc:xyz",
				},
				{
					Filename:          "both.jks",
					PlaintextPassword: "plain",
					EncryptedPassword: "enc:both",
				},
				{
					Filename: "no-password.pem",
				},
			},
		},
	}

	redacted := redactPasswords(original)

	// Original should be unchanged
	if original.Passwords.CommonPlaintext[0] != "secret1" {
		t.Error("original CommonPlaintext was modified")
	}
	if original.Passwords.CommonEncrypted[0] != "enc:abc" {
		t.Error("original CommonEncrypted was modified")
	}

	// Redacted plaintext passwords
	for i, v := range redacted.Passwords.CommonPlaintext {
		if v != "[redacted]" {
			t.Errorf("CommonPlaintext[%d] = %q, want [redacted]", i, v)
		}
	}

	// Redacted encrypted passwords
	for i, v := range redacted.Passwords.CommonEncrypted {
		if v != "[encrypted]" {
			t.Errorf("CommonEncrypted[%d] = %q, want [encrypted]", i, v)
		}
	}

	// ByFilename entries
	if redacted.Passwords.ByFilename[0].PlaintextPassword != "[redacted]" {
		t.Errorf("ByFilename[0].PlaintextPassword = %q, want [redacted]", redacted.Passwords.ByFilename[0].PlaintextPassword)
	}
	if redacted.Passwords.ByFilename[1].EncryptedPassword != "[encrypted]" {
		t.Errorf("ByFilename[1].EncryptedPassword = %q, want [encrypted]", redacted.Passwords.ByFilename[1].EncryptedPassword)
	}
	if redacted.Passwords.ByFilename[2].PlaintextPassword != "[redacted]" {
		t.Errorf("ByFilename[2].PlaintextPassword = %q, want [redacted]", redacted.Passwords.ByFilename[2].PlaintextPassword)
	}
	if redacted.Passwords.ByFilename[2].EncryptedPassword != "[encrypted]" {
		t.Errorf("ByFilename[2].EncryptedPassword = %q, want [encrypted]", redacted.Passwords.ByFilename[2].EncryptedPassword)
	}

	// Entry without passwords should remain empty
	if redacted.Passwords.ByFilename[3].PlaintextPassword != "" {
		t.Errorf("ByFilename[3].PlaintextPassword = %q, want empty", redacted.Passwords.ByFilename[3].PlaintextPassword)
	}
	if redacted.Passwords.ByFilename[3].EncryptedPassword != "" {
		t.Errorf("ByFilename[3].EncryptedPassword = %q, want empty", redacted.Passwords.ByFilename[3].EncryptedPassword)
	}

	// Filenames should be preserved
	if redacted.Passwords.ByFilename[0].Filename != "server.p12" {
		t.Errorf("ByFilename[0].Filename = %q, want server.p12", redacted.Passwords.ByFilename[0].Filename)
	}

	// Lengths should match
	if len(redacted.Passwords.CommonPlaintext) != 2 {
		t.Errorf("CommonPlaintext length = %d, want 2", len(redacted.Passwords.CommonPlaintext))
	}
	if len(redacted.Passwords.ByFilename) != 4 {
		t.Errorf("ByFilename length = %d, want 4", len(redacted.Passwords.ByFilename))
	}
}

// ---------------------------------------------------------------------------
// checkExitCode (check.go)
// ---------------------------------------------------------------------------

func TestCheckExitCode(t *testing.T) {
	tests := []struct {
		name          string
		hasScanErrors bool
		summary       certlib.CheckSummary
		strict        bool
		strictSummary certlib.CheckSummary
		want          int
	}{
		{"no_errors_no_findings", false, certlib.CheckSummary{}, false, certlib.CheckSummary{}, 0},
		{"scan_errors_only", true, certlib.CheckSummary{}, false, certlib.CheckSummary{}, 2},
		{"warning_only", false, certlib.CheckSummary{Warning: 1}, false, certlib.CheckSummary{Warning: 1}, 1},
		{"critical_only", false, certlib.CheckSummary{Critical: 1}, false, certlib.CheckSummary{Critical: 1}, 2},
		{"warning_and_critical", false, certlib.CheckSummary{Warning: 2, Critical: 1}, false, certlib.CheckSummary{Warning: 2, Critical: 1}, 2},
		{"info_only", false, certlib.CheckSummary{Info: 5}, false, certlib.CheckSummary{Info: 5}, 0},
		{"scan_errors_plus_warning", true, certlib.CheckSummary{Warning: 1}, false, certlib.CheckSummary{Warning: 1}, 2},
		{"scan_errors_plus_critical", true, certlib.CheckSummary{Critical: 1}, false, certlib.CheckSummary{Critical: 1}, 2},
		{"strict_warning_escalates_to_2", false, certlib.CheckSummary{Warning: 1}, true, certlib.CheckSummary{Warning: 1}, 2},
		{"strict_critical", false, certlib.CheckSummary{Critical: 1}, true, certlib.CheckSummary{Critical: 1}, 2},
		{"strict_info_only", false, certlib.CheckSummary{Info: 1}, true, certlib.CheckSummary{Info: 1}, 0},
		{"scan_errors_override_warning_upward", true, certlib.CheckSummary{Warning: 1}, false, certlib.CheckSummary{Warning: 1}, 2},
		{"strict_severity_filters_warning_from_display", false, certlib.CheckSummary{}, true, certlib.CheckSummary{Warning: 1}, 2},
		{"nonstrict_severity_filters_warning_from_display", false, certlib.CheckSummary{}, false, certlib.CheckSummary{Warning: 1}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkExitCode(tt.hasScanErrors, tt.summary, tt.strict, tt.strictSummary)
			if got != tt.want {
				t.Errorf("checkExitCode(%v, %+v, %v, %+v) = %d, want %d",
					tt.hasScanErrors, tt.summary, tt.strict, tt.strictSummary, got, tt.want)
			}
		})
	}
}

func TestRedactPasswords_Empty(t *testing.T) {
	original := &config.ConfigFile{}

	redacted := redactPasswords(original)

	if len(redacted.Passwords.CommonPlaintext) != 0 {
		t.Errorf("expected empty CommonPlaintext, got %d", len(redacted.Passwords.CommonPlaintext))
	}
	if len(redacted.Passwords.CommonEncrypted) != 0 {
		t.Errorf("expected empty CommonEncrypted, got %d", len(redacted.Passwords.CommonEncrypted))
	}
	if len(redacted.Passwords.ByFilename) != 0 {
		t.Errorf("expected empty ByFilename, got %d", len(redacted.Passwords.ByFilename))
	}
}

// ---------------------------------------------------------------------------
// loadTemplateDefaults (templates.go)
// ---------------------------------------------------------------------------

func TestLoadTemplateDefaults_NoConfig(t *testing.T) {
	// No config anywhere: the loader finds nothing under a fresh HOME and
	// returns nil, so every value comes from the built-in defaults. (An
	// explicit -c path that does not exist is fatal since M31 WP1.)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CERTDIAG_CONFIG", "")
	orig := configFile
	configFile = ""
	defer func() { configFile = orig }()

	td := loadTemplateDefaults()

	if td.certAlgorithm != "ecdsa" {
		t.Errorf("certAlgorithm = %q, want ecdsa", td.certAlgorithm)
	}
	if td.certCurve != "p256" {
		t.Errorf("certCurve = %q, want p256", td.certCurve)
	}
	if td.certKeySize != 2048 {
		t.Errorf("certKeySize = %d, want 2048", td.certKeySize)
	}
	if td.certDays != 365 {
		t.Errorf("certDays = %d, want 365", td.certDays)
	}
	if td.caAlgorithm != "ecdsa" {
		t.Errorf("caAlgorithm = %q, want ecdsa", td.caAlgorithm)
	}
	if td.caCurve != "p384" {
		t.Errorf("caCurve = %q, want p384", td.caCurve)
	}
	if td.caKeySize != 4096 {
		t.Errorf("caKeySize = %d, want 4096", td.caKeySize)
	}
	if td.caDays != 3650 {
		t.Errorf("caDays = %d, want 3650", td.caDays)
	}
	if td.country == "" {
		t.Error("country should be non-empty from OS detection")
	}
}

func TestLoadTemplateDefaults_WithConfig(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	cfgContent := `kind: certdiag-config
version: "1"
defaults:
  subject:
    organization: "TestOrg"
    organizational_unit: "TestOU"
    country: "DE"
    state: "Bavaria"
    locality: "Munich"
  key:
    algorithm: "rsa"
    rsa_key_size: 4096
    ecdsa_curve: "p521"
  cert:
    days: 730
    ca_days: 7300
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0644); err != nil {
		t.Fatal(err)
	}

	orig := configFile
	configFile = cfgPath
	defer func() { configFile = orig }()

	td := loadTemplateDefaults()

	if td.organization != "TestOrg" {
		t.Errorf("organization = %q, want TestOrg", td.organization)
	}
	if td.organizationalUnit != "TestOU" {
		t.Errorf("organizationalUnit = %q, want TestOU", td.organizationalUnit)
	}
	if td.country != "DE" {
		t.Errorf("country = %q, want DE", td.country)
	}
	if td.state != "Bavaria" {
		t.Errorf("state = %q, want Bavaria", td.state)
	}
	if td.locality != "Munich" {
		t.Errorf("locality = %q, want Munich", td.locality)
	}
	if td.certAlgorithm != "rsa" {
		t.Errorf("certAlgorithm = %q, want rsa", td.certAlgorithm)
	}
	if td.certKeySize != 4096 {
		t.Errorf("certKeySize = %d, want 4096", td.certKeySize)
	}
	if td.certCurve != "p521" {
		t.Errorf("certCurve = %q, want p521", td.certCurve)
	}
	if td.certDays != 730 {
		t.Errorf("certDays = %d, want 730", td.certDays)
	}
	if td.caDays != 7300 {
		t.Errorf("caDays = %d, want 7300", td.caDays)
	}
}

func TestLoadTemplateDefaults_ConfigCountryOverridesOS(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	cfgContent := `kind: certdiag-config
version: "1"
defaults:
  subject:
    country: "XX"
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0644); err != nil {
		t.Fatal(err)
	}

	orig := configFile
	configFile = cfgPath
	defer func() { configFile = orig }()

	td := loadTemplateDefaults()

	if td.country != "XX" {
		t.Errorf("country = %q, want XX (config should override OS)", td.country)
	}
}

func TestCertProfileTemplate_Formatting(t *testing.T) {
	out := fmt.Sprintf(certProfileTemplate,
		"AcmeCorp", "Engineering", "DE", "Bavaria", "Munich",
		"rsa", 4096, "p384", 730)

	checks := []struct {
		substr string
		label  string
	}{
		{`organization: "AcmeCorp"`, "organization"},
		{`organizational_unit: "Engineering"`, "organizational_unit"},
		{`country: "DE"`, "country"},
		{`state: "Bavaria"`, "state"},
		{`locality: "Munich"`, "locality"},
		{`algorithm: "rsa"`, "algorithm"},
		{`# key_size: 4096`, "key_size"},
		{`curve: "p384"`, "curve"},
		{`days: 730`, "days"},
	}
	for _, c := range checks {
		if !strings.Contains(out, c.substr) {
			t.Errorf("cert template missing %s: want %q in output", c.label, c.substr)
		}
	}
}

func TestCaProfileTemplate_Formatting(t *testing.T) {
	out := fmt.Sprintf(caProfileTemplate,
		"RootOrg", "Security", "US", "California", "SF",
		"ecdsa", 3072, "p521", 7300)

	checks := []struct {
		substr string
		label  string
	}{
		{`organization: "RootOrg"`, "organization"},
		{`organizational_unit: "Security"`, "organizational_unit"},
		{`country: "US"`, "country"},
		{`state: "California"`, "state"},
		{`locality: "SF"`, "locality"},
		{`algorithm: "ecdsa"`, "algorithm"},
		{`# key_size: 3072`, "key_size"},
		{`curve: "p521"`, "curve"},
		{`days: 7300`, "days"},
		{`ca: true`, "ca flag"},
	}
	for _, c := range checks {
		if !strings.Contains(out, c.substr) {
			t.Errorf("CA template missing %s: want %q in output", c.label, c.substr)
		}
	}
}

func writeRemoteTimeoutConfig(t *testing.T, timeout string) string {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	cfgContent := "kind: certdiag-config\nversion: \"1\"\ndefaults:\n  remote:\n    timeout: \"" + timeout + "\"\n"
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0644); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

func TestLoadRemoteSettings_TimeoutResolution(t *testing.T) {
	origTimeout := remoteTimeout
	origProxy := remoteProxy
	origParallel := remoteParallel
	origConfig := configFile
	defer func() {
		remoteTimeout = origTimeout
		remoteProxy = origProxy
		remoteParallel = origParallel
		configFile = origConfig
	}()
	remoteProxy = ""
	remoteParallel = 0

	t.Run("flag_unchanged_uses_config", func(t *testing.T) {
		remoteTimeout = ""
		configFile = writeRemoteTimeoutConfig(t, "1ms")
		settings, err := loadRemoteSettings()
		if err != nil {
			t.Fatalf("loadRemoteSettings error: %v", err)
		}
		if settings.timeout != time.Millisecond {
			t.Errorf("timeout = %v, want 1ms (config value)", settings.timeout)
		}
	})

	t.Run("flag_changed_wins_over_config", func(t *testing.T) {
		remoteTimeout = "5s"
		configFile = writeRemoteTimeoutConfig(t, "1ms")
		settings, err := loadRemoteSettings()
		if err != nil {
			t.Fatalf("loadRemoteSettings error: %v", err)
		}
		if settings.timeout != 5*time.Second {
			t.Errorf("timeout = %v, want 5s (flag value)", settings.timeout)
		}
	})

	t.Run("neither_uses_builtin_default", func(t *testing.T) {
		remoteTimeout = ""
		cfgPath := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(cfgPath, []byte("kind: certdiag-config\nversion: \"1\"\n"), 0644); err != nil {
			t.Fatal(err)
		}
		configFile = cfgPath
		settings, err := loadRemoteSettings()
		if err != nil {
			t.Fatalf("loadRemoteSettings error: %v", err)
		}
		if settings.timeout != 10*time.Second {
			t.Errorf("timeout = %v, want 10s (built-in default)", settings.timeout)
		}
	})
}
