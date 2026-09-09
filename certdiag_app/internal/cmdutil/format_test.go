package cmdutil

import (
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func TestParseFormat(t *testing.T) {
	tests := []struct {
		input   string
		want    certlib.FileFormat
		wantErr bool
	}{
		{"pem", certlib.FormatPEM, false},
		{"PEM", certlib.FormatPEM, false},
		{"der", certlib.FormatDER, false},
		{"pkcs12", certlib.FormatPKCS12, false},
		{"p12", certlib.FormatPKCS12, false},
		{"p7b", certlib.FormatPKCS7, false},
		{"pkcs7", certlib.FormatPKCS7, false},
		{"jks", certlib.FormatJKS, false},
		{"JKS", certlib.FormatJKS, false},
		{"xml", "", true},
		{"", "", true},
	}

	for _, tc := range tests {
		got, err := parseFormat(tc.input)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseFormat(%q): expected error, got %q", tc.input, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseFormat(%q): unexpected error: %v", tc.input, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseFormat(%q): got %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestResolveOutputFormat(t *testing.T) {
	tests := []struct {
		name          string
		explicit      string
		configDefault string
		outputPath    string
		want          certlib.FileFormat
		wantErr       bool
	}{
		{"all_empty_defaults_PEM", "", "", "", certlib.FormatPEM, false},
		{"explicit_wins", "der", "", "", certlib.FormatDER, false},
		{"config_default", "", "jks", "", certlib.FormatJKS, false},
		{"extension_from_path", "", "", "out.p12", certlib.FormatPKCS12, false},
		{"explicit_beats_all", "pem", "der", "out.p12", certlib.FormatPEM, false},
		{"extension_beats_config", "", "der", "out.p12", certlib.FormatPKCS12, false},
		{"unknown_ext_falls_to_PEM", "", "", "out.unknown", certlib.FormatPEM, false},
		{"jks_extension", "", "", "out.jks", certlib.FormatJKS, false},
		{"invalid_explicit", "bogus", "", "", "", true},
		{"invalid_config", "", "bogus", "", "", true},
		{"pfx_maps_to_PKCS12", "", "", "out.pfx", certlib.FormatPKCS12, false},
		{"path_with_dirs", "", "", "/path/to/cert.pem", certlib.FormatPEM, false},
		{"case_insensitive_ext", "", "", "out.PEM", certlib.FormatPEM, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveOutputFormat(tc.explicit, tc.configDefault, tc.outputPath)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
