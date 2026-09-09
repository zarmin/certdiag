package truststore

import (
	"testing"
)

func TestParseOpenSSLDir(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "OpenSSL 3.x Homebrew",
			input: `OPENSSLDIR: "/opt/homebrew/etc/openssl@3"`,
			want:  "/opt/homebrew/etc/openssl@3",
		},
		{
			name:  "OpenSSL 1.1 Ubuntu",
			input: `OPENSSLDIR: "/usr/lib/ssl"`,
			want:  "/usr/lib/ssl",
		},
		{
			name:  "OpenSSL 1.0 RHEL",
			input: `OPENSSLDIR: "/etc/pki/tls"`,
			want:  "/etc/pki/tls",
		},
		{
			name:  "LibreSSL macOS",
			input: `OPENSSLDIR: "/private/etc/ssl"`,
			want:  "/private/etc/ssl",
		},
		{
			name:  "with trailing newline",
			input: "OPENSSLDIR: \"/etc/ssl\"\n",
			want:  "/etc/ssl",
		},
		{
			name:    "garbage input",
			input:   "something unexpected",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "OPENSSLDIR with empty path",
			input:   `OPENSSLDIR: ""`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseOpenSSLDir(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseOpenSSLDir(%q) expected error, got %q", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseOpenSSLDir(%q) unexpected error: %v", tt.input, err)
				return
			}
			if got != tt.want {
				t.Errorf("ParseOpenSSLDir(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
