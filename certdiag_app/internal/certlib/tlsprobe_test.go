package certlib

import (
	"strings"
	"testing"
)

func TestClassifyCipher(t *testing.T) {
	tests := []struct {
		name string
		want CipherClassification
	}{
		{"TLS_AES_256_GCM_SHA384", CipherRecommended},
		{"TLS_AES_128_GCM_SHA256", CipherRecommended},
		{"TLS_CHACHA20_POLY1305_SHA256", CipherRecommended},
		{"TLS_AES_128_CCM_SHA256", CipherRecommended},
		{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", CipherRecommended},
		{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", CipherRecommended},
		{"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", CipherAcceptable},
		{"TLS_RSA_WITH_AES_128_CBC_SHA256", CipherWeak},
		{"TLS_RSA_WITH_AES_128_GCM_SHA256", CipherAcceptable},
		{"TLS_RSA_WITH_AES_256_GCM_SHA384", CipherAcceptable},
		{"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", CipherRecommended},
		{"TLS_DH_ANON_WITH_AES_128_CBC_SHA", CipherInsecure},
		{"TLS_RSA_WITH_AES_128_CBC_SHA", CipherWeak},
		{"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", CipherWeak},
		{"TLS_RSA_WITH_RC4_128_SHA", CipherInsecure},
		{"TLS_RSA_WITH_3DES_EDE_CBC_SHA", CipherInsecure},
		{"TLS_RSA_WITH_NULL_SHA", CipherInsecure},
		{"TLS_RSA_EXPORT_WITH_RC4_40_MD5", CipherInsecure},
		{"TLS_RSA_WITH_RC4_128_MD5", CipherInsecure},
		{"TLS_RSA_WITH_DES_CBC_SHA", CipherInsecure},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyCipher(tt.name)
			if got != tt.want {
				t.Errorf("ClassifyCipher(%s) = %s, want %s", tt.name, got, tt.want)
			}
		})
	}
}

func TestSslv3CipherName(t *testing.T) {
	tests := []struct {
		id   uint16
		want string
	}{
		{0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA"},
		{0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"},
		{0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
		{0x0005, "TLS_RSA_WITH_RC4_128_SHA"},
		{0x0004, "TLS_RSA_WITH_RC4_128_MD5"},
		{0xFFFF, "0xFFFF"},
	}

	for _, tt := range tests {
		got := sslv3CipherName(tt.id)
		if got != tt.want {
			t.Errorf("sslv3CipherName(0x%04X) = %s, want %s", tt.id, got, tt.want)
		}
	}
}

func TestCipherClassificationValues(t *testing.T) {
	// Verify enum values are correct strings
	if CipherRecommended != "recommended" {
		t.Error("CipherRecommended should be 'recommended'")
	}
	if CipherAcceptable != "acceptable" {
		t.Error("CipherAcceptable should be 'acceptable'")
	}
	if CipherWeak != "weak" {
		t.Error("CipherWeak should be 'weak'")
	}
	if CipherInsecure != "insecure" {
		t.Error("CipherInsecure should be 'insecure'")
	}
}

func TestDiagnoseProbeFailure(t *testing.T) {
	tests := []struct {
		name     string
		versions []ProbeVersionResult
		wantErr  string
	}{
		{
			name: "one version supported returns nil",
			versions: []ProbeVersionResult{
				{VersionName: "TLS 1.2", Supported: false, Error: "connection refused"},
				{VersionName: "TLS 1.3", Supported: true},
			},
			wantErr: "",
		},
		{
			name: "all supported returns nil",
			versions: []ProbeVersionResult{
				{VersionName: "TLS 1.2", Supported: true},
				{VersionName: "TLS 1.3", Supported: true},
			},
			wantErr: "",
		},
		{
			name: "plaintext port detected",
			versions: []ProbeVersionResult{
				{VersionName: "SSLv3", Supported: false, Error: "i/o timeout"},
				{VersionName: "TLS 1.0", Supported: false, Error: "tls: first record does not look like a TLS handshake"},
				{VersionName: "TLS 1.2", Supported: false, Error: "tls: first record does not look like a TLS handshake"},
				{VersionName: "TLS 1.3", Supported: false, Error: "tls: first record does not look like a TLS handshake"},
			},
			wantErr: "not a TLS port",
		},
		{
			name: "connection refused",
			versions: []ProbeVersionResult{
				{VersionName: "SSLv3", Supported: false, Error: "dial tcp 127.0.0.1:9999: connection refused"},
				{VersionName: "TLS 1.0", Supported: false, Error: "dial tcp 127.0.0.1:9999: connection refused"},
				{VersionName: "TLS 1.2", Supported: false, Error: "dial tcp 127.0.0.1:9999: connection refused"},
				{VersionName: "TLS 1.3", Supported: false, Error: "dial tcp 127.0.0.1:9999: connection refused"},
			},
			wantErr: "connection refused",
		},
		{
			name: "host unreachable",
			versions: []ProbeVersionResult{
				{VersionName: "TLS 1.2", Supported: false, Error: "dial tcp: no route to host"},
				{VersionName: "TLS 1.3", Supported: false, Error: "dial tcp: no route to host"},
			},
			wantErr: "host unreachable",
		},
		{
			name: "network unreachable",
			versions: []ProbeVersionResult{
				{VersionName: "TLS 1.2", Supported: false, Error: "dial tcp: network is unreachable"},
			},
			wantErr: "host unreachable",
		},
		{
			name: "timeout",
			versions: []ProbeVersionResult{
				{VersionName: "TLS 1.2", Supported: false, Error: "dial tcp: i/o timeout"},
				{VersionName: "TLS 1.3", Supported: false, Error: "context deadline exceeded"},
			},
			wantErr: "connection timed out",
		},
		{
			name: "not-TLS takes priority over timeout",
			versions: []ProbeVersionResult{
				{VersionName: "SSLv3", Supported: false, Error: "i/o timeout"},
				{VersionName: "TLS 1.2", Supported: false, Error: "tls: first record does not look like a TLS handshake"},
			},
			wantErr: "not a TLS port",
		},
		{
			name: "refused takes priority over timeout",
			versions: []ProbeVersionResult{
				{VersionName: "TLS 1.2", Supported: false, Error: "dial tcp: connection refused"},
				{VersionName: "TLS 1.3", Supported: false, Error: "i/o timeout"},
			},
			wantErr: "connection refused",
		},
		{
			name: "all failed with unknown errors returns nil",
			versions: []ProbeVersionResult{
				{VersionName: "TLS 1.2", Supported: false, Error: "protocol version not supported"},
				{VersionName: "TLS 1.3", Supported: false, Error: "handshake failure"},
			},
			wantErr: "",
		},
		{
			name:     "empty versions returns nil",
			versions: []ProbeVersionResult{},
			wantErr:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := diagnoseProbeFailure(tt.versions)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("expected nil error, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}
