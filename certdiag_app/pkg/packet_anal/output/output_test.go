package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/session"
	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/tls"
)

// ---------------------------------------------------------------------------
// PrintDetail()
// ---------------------------------------------------------------------------

func TestPrintDetail_Populated(t *testing.T) {
	v := tls.VersionTLS12
	s := &session.Session{
		ClientAddr:        "192.168.1.10:54321",
		ServerAddr:        "10.0.0.1:443",
		Status:            session.StatusOK,
		NegotiatedVersion: &v,
		ClientHello: &tls.ClientHelloMsg{
			SNI:          "api.example.com",
			Version:      tls.VersionTLS12,
			CipherSuites: []uint16{0xc02f},
		},
		ServerHello: &tls.ServerHelloMsg{
			CipherSuite: 0xc02f,
			Version:     tls.VersionTLS12,
		},
		RecordVersion: tls.VersionTLS12,
	}

	var buf bytes.Buffer
	PrintDetail(&buf, s, 1)
	out := buf.String()

	checks := []struct {
		substr string
		label  string
	}{
		{"api.example.com", "SNI"},
		{"TLS 1.2", "version string"},
		{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "cipher name"},
		{"192.168.1.10:54321", "client addr"},
		{"10.0.0.1:443", "server addr"},
		{"OK", "status"},
		{"Session #1", "session index"},
	}
	for _, c := range checks {
		if !strings.Contains(out, c.substr) {
			t.Errorf("output missing %s: want %q in output:\n%s", c.label, c.substr, out)
		}
	}
}

func TestPrintDetail_Minimal(t *testing.T) {
	s := &session.Session{}

	var buf bytes.Buffer
	PrintDetail(&buf, s, 0)
	out := buf.String()

	if out == "" {
		t.Error("expected some output for minimal session, got empty")
	}

	if !strings.Contains(out, "Session #0") {
		t.Errorf("expected 'Session #0' in output, got:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// PrintSummaryTable()
// ---------------------------------------------------------------------------

func TestPrintSummaryTable_Empty(t *testing.T) {
	var buf bytes.Buffer
	PrintSummaryTable(&buf, nil)
	out := buf.String()

	if !strings.Contains(out, "No TLS sessions found") {
		t.Errorf("expected 'No TLS sessions found' message, got:\n%s", out)
	}
}

func TestPrintSummaryTable_OneSession(t *testing.T) {
	v := tls.VersionTLS12
	s := &session.Session{
		ClientAddr:        "10.0.0.1:12345",
		ServerAddr:        "10.0.0.2:443",
		Status:            session.StatusOK,
		NegotiatedVersion: &v,
		ClientHello:       &tls.ClientHelloMsg{SNI: "example.com"},
		ServerHello:       &tls.ServerHelloMsg{CipherSuite: 0xc02f},
	}

	var buf bytes.Buffer
	PrintSummaryTable(&buf, []*session.Session{s})
	out := buf.String()

	checks := []struct {
		substr string
		label  string
	}{
		{"#", "header column"},
		{"Source", "header column"},
		{"Dest", "header column"},
		{"example.com", "SNI"},
		{"TLS 1.2", "version"},
		{"10.0.0.1:12345", "client addr"},
		{"10.0.0.2:443", "server addr"},
		{"Total: 1 TLS sessions", "total count"},
	}
	for _, c := range checks {
		if !strings.Contains(out, c.substr) {
			t.Errorf("output missing %s: want %q in output:\n%s", c.label, c.substr, out)
		}
	}
}

func TestPrintSummaryTable_FailedSession(t *testing.T) {
	s := &session.Session{
		ClientAddr: "10.0.0.1:12345",
		ServerAddr: "10.0.0.2:443",
		Status:     session.StatusFailed,
		Diagnostic: "Alert(handshake_failure) from server after ClientHello",
	}

	var buf bytes.Buffer
	PrintSummaryTable(&buf, []*session.Session{s})
	out := buf.String()

	if !strings.Contains(out, "FAILED") {
		t.Errorf("expected FAILED in output, got:\n%s", out)
	}
	if !strings.Contains(out, "Failed: 1") {
		t.Errorf("expected 'Failed: 1' in stats, got:\n%s", out)
	}
}
