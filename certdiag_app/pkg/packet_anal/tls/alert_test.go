package tls

import (
	"errors"
	"fmt"
	"testing"
)

func TestParseAlert_Valid(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		wantLevel AlertLevel
		wantDesc  AlertDescription
	}{
		{
			name:      "fatal handshake_failure",
			data:      []byte{byte(AlertLevelFatal), byte(AlertHandshakeFailure)},
			wantLevel: AlertLevelFatal,
			wantDesc:  AlertHandshakeFailure,
		},
		{
			name:      "warning close_notify",
			data:      []byte{byte(AlertLevelWarning), byte(AlertCloseNotify)},
			wantLevel: AlertLevelWarning,
			wantDesc:  AlertCloseNotify,
		},
		{
			name:      "fatal certificate_expired",
			data:      []byte{byte(AlertLevelFatal), byte(AlertCertificateExpired)},
			wantLevel: AlertLevelFatal,
			wantDesc:  AlertCertificateExpired,
		},
		{
			name:      "extra bytes are ignored",
			data:      []byte{byte(AlertLevelFatal), byte(AlertInternalError), 0xFF, 0xFE},
			wantLevel: AlertLevelFatal,
			wantDesc:  AlertInternalError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alert, err := ParseAlert(tt.data)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if alert.Level != tt.wantLevel {
				t.Errorf("Level = %v, want %v", alert.Level, tt.wantLevel)
			}
			if alert.Description != tt.wantDesc {
				t.Errorf("Description = %v, want %v", alert.Description, tt.wantDesc)
			}
		})
	}
}

func TestParseAlert_TooShort(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"one byte", []byte{0x02}},
		{"zero length", []byte{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseAlert(tt.data)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, ErrTruncated) {
				t.Errorf("expected ErrTruncated, got %v", err)
			}
		})
	}
}

func TestAlertLevelString(t *testing.T) {
	tests := []struct {
		level AlertLevel
		want  string
	}{
		{AlertLevelWarning, "warning"},
		{AlertLevelFatal, "fatal"},
		{AlertLevel(0), "unknown(0)"},
		{AlertLevel(3), "unknown(3)"},
		{AlertLevel(255), "unknown(255)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.level.String(); got != tt.want {
				t.Errorf("AlertLevel(%d).String() = %q, want %q", tt.level, got, tt.want)
			}
		})
	}
}

func TestAlertDescriptionString(t *testing.T) {
	tests := []struct {
		desc AlertDescription
		want string
	}{
		{AlertCloseNotify, "close_notify"},
		{AlertUnexpectedMessage, "unexpected_message"},
		{AlertBadRecordMAC, "bad_record_mac"},
		{AlertHandshakeFailure, "handshake_failure"},
		{AlertBadCertificate, "bad_certificate"},
		{AlertUnsupportedCertificate, "unsupported_certificate"},
		{AlertCertificateRevoked, "certificate_revoked"},
		{AlertCertificateExpired, "certificate_expired"},
		{AlertCertificateUnknown, "certificate_unknown"},
		{AlertIllegalParameter, "illegal_parameter"},
		{AlertUnknownCA, "unknown_ca"},
		{AlertAccessDenied, "access_denied"},
		{AlertDecodeError, "decode_error"},
		{AlertProtocolVersion, "protocol_version"},
		{AlertInsufficientSecurity, "insufficient_security"},
		{AlertInternalError, "internal_error"},
		{AlertInappropriateFallback, "inappropriate_fallback"},
		{AlertUserCanceled, "user_canceled"},
		{AlertMissingExtension, "missing_extension"},
		{AlertUnrecognizedName, "unrecognized_name"},
		{AlertCertificateRequired, "certificate_required"},
		{AlertDescription(200), fmt.Sprintf("unknown(%d)", 200)},
		{AlertDescription(255), fmt.Sprintf("unknown(%d)", 255)},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.desc.String(); got != tt.want {
				t.Errorf("AlertDescription(%d).String() = %q, want %q", tt.desc, got, tt.want)
			}
		})
	}
}
