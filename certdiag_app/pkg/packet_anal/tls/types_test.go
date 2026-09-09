package tls

import (
	"fmt"
	"testing"
)

func TestContentTypeString(t *testing.T) {
	tests := []struct {
		ct   ContentType
		want string
	}{
		{ContentChangeCipherSpec, "ChangeCipherSpec"},
		{ContentAlert, "Alert"},
		{ContentHandshake, "Handshake"},
		{ContentApplicationData, "ApplicationData"},
		{ContentType(99), "Unknown(99)"},
		{ContentType(0), "Unknown(0)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.ct.String(); got != tt.want {
				t.Errorf("ContentType(%d).String() = %q, want %q", tt.ct, got, tt.want)
			}
		})
	}
}

func TestHandshakeTypeString(t *testing.T) {
	tests := []struct {
		ht   HandshakeType
		want string
	}{
		{HandshakeClientHello, "ClientHello"},
		{HandshakeServerHello, "ServerHello"},
		{HandshakeCertificate, "Certificate"},
		{HandshakeServerKeyExchange, "ServerKeyExchange"},
		{HandshakeCertificateRequest, "CertificateRequest"},
		{HandshakeServerHelloDone, "ServerHelloDone"},
		{HandshakeClientKeyExchange, "ClientKeyExchange"},
		{HandshakeFinished, "Finished"},
		{HandshakeType(255), "Unknown(255)"},
		{HandshakeType(0), "Unknown(0)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.ht.String(); got != tt.want {
				t.Errorf("HandshakeType(%d).String() = %q, want %q", tt.ht, got, tt.want)
			}
		})
	}
}

func TestVersionString(t *testing.T) {
	tests := []struct {
		v    Version
		want string
	}{
		{VersionSSL30, "SSLv3"},
		{VersionTLS10, "TLS 1.0"},
		{VersionTLS11, "TLS 1.1"},
		{VersionTLS12, "TLS 1.2"},
		{VersionTLS13, "TLS 1.3"},
		{Version{4, 0}, "Unknown(4.0)"},
		{Version{0, 0}, "Unknown(0.0)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.v.String(); got != tt.want {
				t.Errorf("Version{%d,%d}.String() = %q, want %q", tt.v.Major, tt.v.Minor, got, tt.want)
			}
		})
	}
}

func TestVersionCode(t *testing.T) {
	tests := []struct {
		v    Version
		want uint16
	}{
		{VersionSSL30, 0x0300},
		{VersionTLS10, 0x0301},
		{VersionTLS11, 0x0302},
		{VersionTLS12, 0x0303},
		{VersionTLS13, 0x0304},
	}
	for _, tt := range tests {
		t.Run(tt.v.String(), func(t *testing.T) {
			if got := tt.v.Code(); got != tt.want {
				t.Errorf("Version{%d,%d}.Code() = 0x%04x, want 0x%04x", tt.v.Major, tt.v.Minor, got, tt.want)
			}
		})
	}
}

func TestVersionFromCode(t *testing.T) {
	tests := []struct {
		code uint16
		want Version
	}{
		{0x0300, VersionSSL30},
		{0x0301, VersionTLS10},
		{0x0302, VersionTLS11},
		{0x0303, VersionTLS12},
		{0x0304, VersionTLS13},
		{0x0201, Version{2, 1}},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("0x%04x", tt.code), func(t *testing.T) {
			got := VersionFromCode(tt.code)
			if got != tt.want {
				t.Errorf("VersionFromCode(0x%04x) = %+v, want %+v", tt.code, got, tt.want)
			}
		})
	}
}

func TestVersionCodeRoundtrip(t *testing.T) {
	versions := []Version{VersionSSL30, VersionTLS10, VersionTLS11, VersionTLS12, VersionTLS13}
	for _, v := range versions {
		t.Run(v.String(), func(t *testing.T) {
			code := v.Code()
			got := VersionFromCode(code)
			if got != v {
				t.Errorf("roundtrip failed: Version%+v -> 0x%04x -> %+v", v, code, got)
			}
		})
	}
}
