package session

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/tcp"
	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/tls"
)

// ---------------------------------------------------------------------------
// State.String()
// ---------------------------------------------------------------------------

func TestStateString(t *testing.T) {
	tests := []struct {
		state State
		want  string
	}{
		{StateInit, "INIT"},
		{StateClientHello, "ClientHello"},
		{StateServerHello, "ServerHello"},
		{StateCertificate, "Certificate"},
		{StateServerDone, "ServerHelloDone"},
		{StateClientKX, "ClientKeyExchange"},
		{StateClientCCS, "ClientCCS"},
		{StateServerCCS, "ServerCCS"},
		{StateEstablished, "Established"},
		{StateFailed, "Failed"},
		{StateAborted, "Aborted"},
		{State(99), "Unknown(99)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.state.String()
			if got != tt.want {
				t.Errorf("State(%d).String() = %q, want %q", tt.state, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Status.String()
// ---------------------------------------------------------------------------

func TestStatusString(t *testing.T) {
	tests := []struct {
		status Status
		want   string
	}{
		{StatusOK, "OK"},
		{StatusFailed, "FAILED"},
		{StatusAborted, "ABORTED"},
		{StatusIncomplete, "INCOMPLETE"},
		{Status(99), "Unknown(99)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.status.String()
			if got != tt.want {
				t.Errorf("Status(%d).String() = %q, want %q", tt.status, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Session.SNI()
// ---------------------------------------------------------------------------

func TestSessionSNI(t *testing.T) {
	t.Run("with_client_hello", func(t *testing.T) {
		s := &Session{
			ClientHello: &tls.ClientHelloMsg{SNI: "example.com"},
		}
		if got := s.SNI(); got != "example.com" {
			t.Errorf("SNI() = %q, want %q", got, "example.com")
		}
	})

	t.Run("no_client_hello", func(t *testing.T) {
		s := &Session{}
		if got := s.SNI(); got != "" {
			t.Errorf("SNI() = %q, want empty", got)
		}
	})
}

// ---------------------------------------------------------------------------
// Session.CipherSuite()
// ---------------------------------------------------------------------------

func TestSessionCipherSuite(t *testing.T) {
	t.Run("with_server_hello", func(t *testing.T) {
		s := &Session{
			ServerHello: &tls.ServerHelloMsg{CipherSuite: 0xc02f},
		}
		got := s.CipherSuite()
		want := tls.CipherSuiteName(0xc02f)
		if got != want {
			t.Errorf("CipherSuite() = %q, want %q", got, want)
		}
	})

	t.Run("no_server_hello", func(t *testing.T) {
		s := &Session{}
		if got := s.CipherSuite(); got != "--" {
			t.Errorf("CipherSuite() = %q, want %q", got, "--")
		}
	})
}

// ---------------------------------------------------------------------------
// Session.VersionString()
// ---------------------------------------------------------------------------

func TestSessionVersionString(t *testing.T) {
	t.Run("version_set", func(t *testing.T) {
		v := tls.VersionTLS12
		s := &Session{NegotiatedVersion: &v}
		if got := s.VersionString(); got != "TLS 1.2" {
			t.Errorf("VersionString() = %q, want %q", got, "TLS 1.2")
		}
	})

	t.Run("version_nil", func(t *testing.T) {
		s := &Session{}
		if got := s.VersionString(); got != "--" {
			t.Errorf("VersionString() = %q, want %q", got, "--")
		}
	})
}

// ---------------------------------------------------------------------------
// Session.MatchesSearch()
// ---------------------------------------------------------------------------

func TestSessionMatchesSearch(t *testing.T) {
	v := tls.VersionTLS12
	s := &Session{
		ClientAddr:        "10.0.0.1:54321",
		ServerAddr:        "10.0.0.2:443",
		NegotiatedVersion: &v,
		Status:            StatusOK,
		ClientHello:       &tls.ClientHelloMsg{SNI: "api.example.com"},
		ServerHello:       &tls.ServerHelloMsg{CipherSuite: 0xc02f},
	}

	tests := []struct {
		name  string
		query string
		want  bool
	}{
		{"empty_query_matches_all", "", true},
		{"match_sni", "example.com", true},
		{"match_sni_case_insensitive", "API.EXAMPLE.COM", true},
		{"match_client_addr", "10.0.0.1", true},
		{"match_server_addr", "443", true},
		{"match_cipher_name", "ECDHE_RSA", true},
		{"match_version", "TLS 1.2", true},
		{"match_status", "ok", true},
		{"no_match", "nonexistent_query_xyz", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.MatchesSearch(tt.query)
			if got != tt.want {
				t.Errorf("MatchesSearch(%q) = %v, want %v", tt.query, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Tracker.ProcessConnections()
// ---------------------------------------------------------------------------

func TestTrackerProcessConnections_Empty(t *testing.T) {
	tracker := &Tracker{}
	sessions := tracker.ProcessConnections(nil)
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions for nil connections, got %d", len(sessions))
	}

	sessions = tracker.ProcessConnections([]*tcp.Connection{})
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions for empty connections, got %d", len(sessions))
	}
}

func TestTrackerProcessConnections_EmptyData(t *testing.T) {
	tracker := &Tracker{}
	conn := &tcp.Connection{
		ClientAddr: "1.2.3.4:1234",
		ServerAddr: "5.6.7.8:443",
		ClientData: nil,
		ServerData: nil,
	}
	sessions := tracker.ProcessConnections([]*tcp.Connection{conn})
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions for connection with no TLS data, got %d", len(sessions))
	}
}

func TestTrackerProcessConnections_NonTLSData(t *testing.T) {
	tracker := &Tracker{}
	conn := &tcp.Connection{
		ClientAddr: "1.2.3.4:1234",
		ServerAddr: "5.6.7.8:443",
		ClientData: []byte("GET / HTTP/1.1\r\n\r\n"),
		ServerData: []byte("HTTP/1.1 200 OK\r\n\r\n"),
	}
	sessions := tracker.ProcessConnections([]*tcp.Connection{conn})
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions for non-TLS data, got %d", len(sessions))
	}
}

// ---------------------------------------------------------------------------
// TLS record/handshake construction helpers (duplicated from tls package tests
// since they are unexported)
// ---------------------------------------------------------------------------

func buildRecord(ct tls.ContentType, major, minor uint8, payload []byte) []byte {
	rec := make([]byte, 5+len(payload))
	rec[0] = byte(ct)
	rec[1] = major
	rec[2] = minor
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(payload)))
	copy(rec[5:], payload)
	return rec
}

func buildHandshakeMessage(hsType tls.HandshakeType, payload []byte) []byte {
	buf := make([]byte, 4+len(payload))
	buf[0] = byte(hsType)
	buf[1] = byte(len(payload) >> 16)
	buf[2] = byte(len(payload) >> 8)
	buf[3] = byte(len(payload))
	copy(buf[4:], payload)
	return buf
}

func buildExtensionBlock(extensions []tls.Extension) []byte {
	var extBytes []byte
	for _, ext := range extensions {
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint16(hdr[:2], ext.Type)
		binary.BigEndian.PutUint16(hdr[2:4], uint16(len(ext.Data)))
		extBytes = append(extBytes, hdr...)
		extBytes = append(extBytes, ext.Data...)
	}
	buf := make([]byte, 2+len(extBytes))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(extBytes)))
	copy(buf[2:], extBytes)
	return buf
}

func buildSNIExtension(host string) []byte {
	nameEntry := make([]byte, 3+len(host))
	nameEntry[0] = 0 // host_name
	binary.BigEndian.PutUint16(nameEntry[1:3], uint16(len(host)))
	copy(nameEntry[3:], host)

	snList := make([]byte, 2+len(nameEntry))
	binary.BigEndian.PutUint16(snList[:2], uint16(len(nameEntry)))
	copy(snList[2:], nameEntry)
	return snList
}

func buildClientHelloPayload(version tls.Version, cipherSuites []uint16, extensions []tls.Extension) []byte {
	var buf []byte
	buf = append(buf, version.Major, version.Minor)
	buf = append(buf, make([]byte, 32)...) // random
	buf = append(buf, 0)                   // session ID length = 0
	csLen := make([]byte, 2)
	binary.BigEndian.PutUint16(csLen, uint16(len(cipherSuites)*2))
	buf = append(buf, csLen...)
	for _, cs := range cipherSuites {
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, cs)
		buf = append(buf, b...)
	}
	buf = append(buf, 1, 0) // compression methods: length=1, null
	if len(extensions) > 0 {
		buf = append(buf, buildExtensionBlock(extensions)...)
	}
	return buf
}

func buildServerHelloPayload(version tls.Version, cipherSuite uint16, extensions []tls.Extension) []byte {
	var buf []byte
	buf = append(buf, version.Major, version.Minor)
	buf = append(buf, make([]byte, 32)...) // random
	buf = append(buf, 0)                   // session ID length = 0
	cs := make([]byte, 2)
	binary.BigEndian.PutUint16(cs, cipherSuite)
	buf = append(buf, cs...)
	buf = append(buf, 0) // compression method: null
	if len(extensions) > 0 {
		buf = append(buf, buildExtensionBlock(extensions)...)
	}
	return buf
}

func buildCertificatePayload(certs [][]byte) []byte {
	var certEntries []byte
	for _, cert := range certs {
		entry := make([]byte, 3+len(cert))
		entry[0] = byte(len(cert) >> 16)
		entry[1] = byte(len(cert) >> 8)
		entry[2] = byte(len(cert))
		copy(entry[3:], cert)
		certEntries = append(certEntries, entry...)
	}
	buf := make([]byte, 3+len(certEntries))
	buf[0] = byte(len(certEntries) >> 16)
	buf[1] = byte(len(certEntries) >> 8)
	buf[2] = byte(len(certEntries))
	copy(buf[3:], certEntries)
	return buf
}

func generateSelfSignedCertDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"test.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return der
}

// ---------------------------------------------------------------------------
// Full handshake test
// ---------------------------------------------------------------------------

func TestTrackerProcessConnections_FullHandshake(t *testing.T) {
	sni := "myserver.example.com"
	cipherSuite := uint16(0xc02f) // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

	// Build client data: a ClientHello record with SNI extension
	chPayload := buildClientHelloPayload(
		tls.VersionTLS12,
		[]uint16{cipherSuite, 0xc030},
		[]tls.Extension{
			{Type: tls.ExtServerName, Data: buildSNIExtension(sni)},
		},
	)
	chHandshake := buildHandshakeMessage(tls.HandshakeClientHello, chPayload)
	clientData := buildRecord(tls.ContentHandshake, 3, 1, chHandshake)

	// Build server data: ServerHello + Certificate records
	shPayload := buildServerHelloPayload(tls.VersionTLS12, cipherSuite, nil)
	shHandshake := buildHandshakeMessage(tls.HandshakeServerHello, shPayload)

	certDER := generateSelfSignedCertDER(t)
	certPayload := buildCertificatePayload([][]byte{certDER})
	certHandshake := buildHandshakeMessage(tls.HandshakeCertificate, certPayload)

	// Combine server handshake messages into one record
	serverHandshakeData := append(shHandshake, certHandshake...)
	serverData := buildRecord(tls.ContentHandshake, 3, 3, serverHandshakeData)

	conn := &tcp.Connection{
		ClientAddr: "192.168.1.10:54321",
		ServerAddr: "10.0.0.1:443",
		ClientData: clientData,
		ServerData: serverData,
		StartTime:  time.Now().Add(-time.Second),
		EndTime:    time.Now(),
	}

	tracker := &Tracker{}
	sessions := tracker.ProcessConnections([]*tcp.Connection{conn})

	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}

	s := sessions[0]

	if got := s.SNI(); got != sni {
		t.Errorf("SNI() = %q, want %q", got, sni)
	}

	wantCipher := tls.CipherSuiteName(cipherSuite)
	if got := s.CipherSuite(); got != wantCipher {
		t.Errorf("CipherSuite() = %q, want %q", got, wantCipher)
	}

	if got := s.VersionString(); got != "TLS 1.2" {
		t.Errorf("VersionString() = %q, want %q", got, "TLS 1.2")
	}

	if s.State < StateCertificate {
		t.Errorf("State = %v, expected at least Certificate", s.State)
	}

	if s.Certificates == nil {
		t.Fatal("expected Certificates to be non-nil")
	}

	if len(s.Certificates.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(s.Certificates.Certificates))
	}

	if s.ClientAddr != "192.168.1.10:54321" {
		t.Errorf("ClientAddr = %q, want %q", s.ClientAddr, "192.168.1.10:54321")
	}

	if s.ServerAddr != "10.0.0.1:443" {
		t.Errorf("ServerAddr = %q, want %q", s.ServerAddr, "10.0.0.1:443")
	}
}
