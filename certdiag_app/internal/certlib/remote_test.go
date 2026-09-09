package certlib

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"
)

// --- ParseTarget tests ---

func TestParseTarget(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantHost string
		wantPort int
		wantSNI  string
		wantIsIP bool
		wantIsV6 bool
		wantPath string
		wantErr  bool
	}{
		{
			name:     "simple hostname",
			input:    "example.com",
			wantHost: "example.com",
			wantPort: 443,
			wantSNI:  "example.com",
		},
		{
			name:     "hostname with port",
			input:    "example.com:8443",
			wantHost: "example.com",
			wantPort: 8443,
			wantSNI:  "example.com",
		},
		{
			name:     "IPv4",
			input:    "192.168.1.1",
			wantHost: "192.168.1.1",
			wantPort: 443,
			wantIsIP: true,
		},
		{
			name:     "IPv4 with port",
			input:    "10.0.0.1:8443",
			wantHost: "10.0.0.1",
			wantPort: 8443,
			wantIsIP: true,
		},
		{
			name:     "IPv6 bracketed",
			input:    "[::1]",
			wantHost: "::1",
			wantPort: 443,
			wantIsIP: true,
			wantIsV6: true,
		},
		{
			name:     "IPv6 bracketed with port",
			input:    "[::1]:8443",
			wantHost: "::1",
			wantPort: 8443,
			wantIsIP: true,
			wantIsV6: true,
		},
		{
			name:     "IPv6 full address bracketed",
			input:    "[2001:db8::1]:443",
			wantHost: "2001:db8::1",
			wantPort: 443,
			wantIsIP: true,
			wantIsV6: true,
		},
		{
			name:     "https URL",
			input:    "https://example.com",
			wantHost: "example.com",
			wantPort: 443,
			wantSNI:  "example.com",
			wantPath: "/",
		},
		{
			name:     "https URL with port",
			input:    "https://example.com:8443",
			wantHost: "example.com",
			wantPort: 8443,
			wantSNI:  "example.com",
			wantPath: "/",
		},
		{
			name:     "https URL with path",
			input:    "https://example.com/some/path",
			wantHost: "example.com",
			wantPort: 443,
			wantSNI:  "example.com",
			wantPath: "/some/path",
		},
		{
			name:     "tls URL",
			input:    "tls://mail.example.com:993",
			wantHost: "mail.example.com",
			wantPort: 993,
			wantSNI:  "mail.example.com",
			wantPath: "/",
		},
		{
			name:     "whitespace trimmed",
			input:    "  example.com  ",
			wantHost: "example.com",
			wantPort: 443,
			wantSNI:  "example.com",
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
		},
		{
			name:    "whitespace only",
			input:   "   ",
			wantErr: true,
		},
		{
			name:    "invalid port",
			input:   "example.com:abc",
			wantErr: true,
		},
		{
			name:    "port out of range high",
			input:   "example.com:70000",
			wantErr: true,
		},
		{
			name:    "port out of range zero",
			input:   "example.com:0",
			wantErr: true,
		},
		{
			name:    "IPv6 missing closing bracket",
			input:   "[::1",
			wantErr: true,
		},
		{
			name:    "unsupported scheme",
			input:   "ftp://example.com",
			wantErr: true,
		},
		{
			name:    "URL with userinfo",
			input:   "https://user:pass@example.com",
			wantErr: true,
		},
		{
			name:    "URL with empty host",
			input:   "https://",
			wantErr: true,
		},
		// malformed scheme (missing colon)
		{
			name:    "https missing colon",
			input:   "https//example.com",
			wantErr: true,
		},
		{
			name:    "http missing colon",
			input:   "http//example.com",
			wantErr: true,
		},
		{
			name:    "tls missing colon with port",
			input:   "tls//example.com:993",
			wantErr: true,
		},
		// invalid hostname characters
		{
			name:    "hostname with slash",
			input:   "example.com/path",
			wantErr: true,
		},
		{
			name:    "hostname with space",
			input:   "host name.com",
			wantErr: true,
		},
		{
			name:    "hostname with at sign",
			input:   "host@name.com",
			wantErr: true,
		},
		{
			name:    "hostname with hash",
			input:   "example.com#fragment",
			wantErr: true,
		},
		// valid hostnames that must still work
		{
			name:     "subdomain",
			input:    "sub.example.com",
			wantHost: "sub.example.com",
			wantPort: 443,
			wantSNI:  "sub.example.com",
		},
		{
			name:     "hyphenated hostname",
			input:    "my-host.example.com",
			wantHost: "my-host.example.com",
			wantPort: 443,
			wantSNI:  "my-host.example.com",
		},
		{
			name:     "underscore SRV hostname",
			input:    "_srv.example.com",
			wantHost: "_srv.example.com",
			wantPort: 443,
			wantSNI:  "_srv.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTarget(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseTarget(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTarget(%q) unexpected error: %v", tt.input, err)
			}
			if got.Host != tt.wantHost {
				t.Errorf("Host = %q, want %q", got.Host, tt.wantHost)
			}
			if got.Port != tt.wantPort {
				t.Errorf("Port = %d, want %d", got.Port, tt.wantPort)
			}
			if got.SNI != tt.wantSNI {
				t.Errorf("SNI = %q, want %q", got.SNI, tt.wantSNI)
			}
			if got.IsIP != tt.wantIsIP {
				t.Errorf("IsIP = %v, want %v", got.IsIP, tt.wantIsIP)
			}
			if got.IsIPv6 != tt.wantIsV6 {
				t.Errorf("IsIPv6 = %v, want %v", got.IsIPv6, tt.wantIsV6)
			}
			if tt.wantPath != "" && got.URLPath != tt.wantPath {
				t.Errorf("URLPath = %q, want %q", got.URLPath, tt.wantPath)
			}
		})
	}
}

func TestRemoteTargetAddress(t *testing.T) {
	tests := []struct {
		name   string
		target RemoteTarget
		want   string
	}{
		{
			name:   "IPv4",
			target: RemoteTarget{Host: "10.0.0.1", Port: 443},
			want:   "10.0.0.1:443",
		},
		{
			name:   "hostname",
			target: RemoteTarget{Host: "example.com", Port: 8443},
			want:   "example.com:8443",
		},
		{
			name:   "IPv6",
			target: RemoteTarget{Host: "::1", Port: 443, IsIPv6: true},
			want:   "[::1]:443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.target.Address()
			if got != tt.want {
				t.Errorf("Address() = %q, want %q", got, tt.want)
			}
		})
	}
}

// --- TLSVersionName / TLSVersionFromString tests ---

func TestTLSVersionName(t *testing.T) {
	tests := []struct {
		version uint16
		want    string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
		{0x0200, "unknown (0x0200)"},
	}

	for _, tt := range tests {
		got := TLSVersionName(tt.version)
		if got != tt.want {
			t.Errorf("TLSVersionName(0x%04x) = %q, want %q", tt.version, got, tt.want)
		}
	}
}

func TestTLSVersionFromString(t *testing.T) {
	tests := []struct {
		input   string
		want    uint16
		wantErr bool
	}{
		{"", 0, false},
		{"auto", 0, false},
		{"tls1.0", tls.VersionTLS10, false},
		{"tls10", tls.VersionTLS10, false},
		{"tls1.1", tls.VersionTLS11, false},
		{"tls1.2", tls.VersionTLS12, false},
		{"tls1.3", tls.VersionTLS13, false},
		{"TLS1.3", tls.VersionTLS13, false},
		{"ssl3", 0, true},
		{"invalid", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := TLSVersionFromString(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("got 0x%04x, want 0x%04x", got, tt.want)
			}
		})
	}
}

// --- StarttlsProtocol tests ---

func TestParseStarttlsProtocol(t *testing.T) {
	tests := []struct {
		input   string
		want    StarttlsProtocol
		wantErr bool
	}{
		{"", StarttlsNone, false},
		{"none", StarttlsNone, false},
		{"smtp", StarttlsSMTP, false},
		{"imap", StarttlsIMAP, false},
		{"pop3", StarttlsPOP3, false},
		{"ftp", StarttlsFTP, false},
		{"ldap", StarttlsLDAP, false},
		{"mysql", StarttlsMySQL, false},
		{"postgres", StarttlsPostgres, false},
		{"unknown", StarttlsNone, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseStarttlsProtocol(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDefaultStarttlsPort(t *testing.T) {
	tests := []struct {
		proto StarttlsProtocol
		want  int
	}{
		{StarttlsSMTP, 587},
		{StarttlsIMAP, 143},
		{StarttlsPOP3, 110},
		{StarttlsFTP, 21},
		{StarttlsLDAP, 389},
		{StarttlsMySQL, 3306},
		{StarttlsPostgres, 5432},
		{StarttlsNone, 443},
	}

	for _, tt := range tests {
		got := DefaultStarttlsPort(tt.proto)
		if got != tt.want {
			t.Errorf("DefaultStarttlsPort(%q) = %d, want %d", tt.proto, got, tt.want)
		}
	}
}

// --- buildTLSConfig tests ---

func TestBuildTLSConfig(t *testing.T) {
	t.Run("default SNI from target", func(t *testing.T) {
		target := RemoteTarget{Host: "example.com", SNI: "example.com"}
		config := buildTLSConfig(target, TLSDialOptions{})
		if config.ServerName != "example.com" {
			t.Errorf("ServerName = %q, want %q", config.ServerName, "example.com")
		}
		if !config.InsecureSkipVerify {
			t.Error("InsecureSkipVerify should be true")
		}
	})

	t.Run("custom SNI override", func(t *testing.T) {
		target := RemoteTarget{Host: "10.0.0.1", IsIP: true}
		config := buildTLSConfig(target, TLSDialOptions{ServerName: "custom.example.com"})
		if config.ServerName != "custom.example.com" {
			t.Errorf("ServerName = %q, want %q", config.ServerName, "custom.example.com")
		}
	})

	t.Run("disable SNI", func(t *testing.T) {
		target := RemoteTarget{Host: "example.com", SNI: "example.com"}
		config := buildTLSConfig(target, TLSDialOptions{DisableSNI: true})
		if config.ServerName != "" {
			t.Errorf("ServerName should be empty, got %q", config.ServerName)
		}
	})

	t.Run("forced version", func(t *testing.T) {
		target := RemoteTarget{Host: "example.com", SNI: "example.com"}
		config := buildTLSConfig(target, TLSDialOptions{ForcedVersion: tls.VersionTLS12})
		if config.MinVersion != tls.VersionTLS12 {
			t.Errorf("MinVersion = 0x%04x, want 0x%04x", config.MinVersion, tls.VersionTLS12)
		}
		if config.MaxVersion != tls.VersionTLS12 {
			t.Errorf("MaxVersion = 0x%04x, want 0x%04x", config.MaxVersion, tls.VersionTLS12)
		}
	})

	t.Run("min/max version", func(t *testing.T) {
		target := RemoteTarget{Host: "example.com", SNI: "example.com"}
		config := buildTLSConfig(target, TLSDialOptions{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
		})
		if config.MinVersion != tls.VersionTLS12 {
			t.Errorf("MinVersion = 0x%04x, want 0x%04x", config.MinVersion, tls.VersionTLS12)
		}
		if config.MaxVersion != tls.VersionTLS13 {
			t.Errorf("MaxVersion = 0x%04x, want 0x%04x", config.MaxVersion, tls.VersionTLS13)
		}
	})

	t.Run("IP target has no SNI", func(t *testing.T) {
		target := RemoteTarget{Host: "10.0.0.1", IsIP: true, SNI: ""}
		config := buildTLSConfig(target, TLSDialOptions{})
		if config.ServerName != "" {
			t.Errorf("ServerName should be empty for IP target, got %q", config.ServerName)
		}
	})
}

// --- In-process TLS server tests ---

func startTestTLSServer(t *testing.T) (net.Listener, *x509.Certificate, int) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test-server.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"test-server.local", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Must complete the TLS handshake before closing
			tlsConn, ok := conn.(*tls.Conn)
			if ok {
				tlsConn.Handshake()
			}
			conn.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return listener, cert, port
}

func TestDialTLS(t *testing.T) {
	listener, serverCert, port := startTestTLSServer(t)
	defer listener.Close()

	target := RemoteTarget{
		Host: "127.0.0.1",
		Port: port,
		IsIP: true,
	}

	result, err := DialTLS(target, TLSDialOptions{
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("DialTLS error: %v", err)
	}
	if result.Error != nil {
		t.Fatalf("FetchResult.Error: %v", result.Error)
	}

	if len(result.Certificates) == 0 {
		t.Fatal("no certificates returned")
	}
	if !result.Certificates[0].Equal(serverCert) {
		t.Error("returned certificate doesn't match server certificate")
	}

	if result.TLSInfo.VersionName == "" {
		t.Error("TLS version name should not be empty")
	}
	if result.TLSInfo.CipherSuiteName == "" {
		t.Error("cipher suite name should not be empty")
	}
	if !result.TLSInfo.HandshakeComplete {
		t.Error("handshake should be complete")
	}
	if result.TLSInfo.RemoteAddr == "" {
		t.Error("remote address should not be empty")
	}
	if len(result.ChainPEM) == 0 {
		t.Error("ChainPEM should not be empty")
	}
}

func TestDialTLSTiming(t *testing.T) {
	listener, _, port := startTestTLSServer(t)
	defer listener.Close()

	target := RemoteTarget{
		Host: "127.0.0.1",
		Port: port,
		IsIP: true,
	}

	result, err := DialTLS(target, TLSDialOptions{
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("DialTLS error: %v", err)
	}
	if result.Error != nil {
		t.Fatalf("FetchResult.Error: %v", result.Error)
	}

	timing := result.TLSInfo.Timing

	// For IP targets, DNS should be skipped
	if !timing.DNSStart.IsZero() {
		t.Error("DNS start should be zero for IP targets")
	}

	if timing.TCPStart.IsZero() {
		t.Error("TCP start should not be zero")
	}
	if timing.TCPDone.IsZero() {
		t.Error("TCP done should not be zero")
	}
	if timing.TCPDuration < 0 {
		t.Error("TCP duration should not be negative")
	}

	if timing.TLSStart.IsZero() {
		t.Error("TLS start should not be zero")
	}
	if timing.TLSDone.IsZero() {
		t.Error("TLS done should not be zero")
	}
	if timing.TLSDuration < 0 {
		t.Error("TLS duration should not be negative")
	}

	if timing.TotalDuration < 0 {
		t.Error("total duration should not be negative")
	}

	// TCP should happen before TLS
	if timing.TCPStart.After(timing.TLSStart) {
		t.Error("TCP start should be before TLS start")
	}
}

func TestDialTLSConnectionError(t *testing.T) {
	// Connect to a port that's not listening
	target := RemoteTarget{
		Host: "127.0.0.1",
		Port: 1, // unlikely to be open
		IsIP: true,
	}

	result, err := DialTLS(target, TLSDialOptions{
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("DialTLS should return result with Error, not an error: %v", err)
	}
	if result.Error == nil {
		t.Fatal("expected an error in FetchResult for connection to closed port")
	}
}

func TestDialTLSForcedVersion(t *testing.T) {
	listener, _, port := startTestTLSServer(t)
	defer listener.Close()

	target := RemoteTarget{
		Host: "127.0.0.1",
		Port: port,
		IsIP: true,
	}

	result, err := DialTLS(target, TLSDialOptions{
		Timeout:       5 * time.Second,
		ForcedVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("DialTLS error: %v", err)
	}
	if result.Error != nil {
		t.Fatalf("FetchResult.Error: %v", result.Error)
	}

	if result.TLSInfo.Version != tls.VersionTLS12 {
		t.Errorf("expected TLS 1.2, got %s", result.TLSInfo.VersionName)
	}
}

// --- PipeConnection tests ---

func TestPipeConnection(t *testing.T) {
	listener, serverCert, port := startTestTLSServer(t)
	defer listener.Close()

	target := RemoteTarget{
		Host: "127.0.0.1",
		Port: port,
		IsIP: true,
	}

	conn, info, err := PipeConnection(target, TLSDialOptions{
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("PipeConnection error: %v", err)
	}
	defer conn.Close()

	if info == nil {
		t.Fatal("TLSConnectionInfo should not be nil")
	}
	if !info.HandshakeComplete {
		t.Error("handshake should be complete")
	}
	if len(info.PeerCertificates) == 0 {
		t.Fatal("no peer certificates")
	}
	if !info.PeerCertificates[0].Equal(serverCert) {
		t.Error("peer certificate doesn't match server certificate")
	}
}

// --- FetchResultToStore tests ---

func TestFetchResultToStore(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	t.Run("single result", func(t *testing.T) {
		results := []FetchResult{
			{
				Target:       RemoteTarget{Host: "example.com", Port: 443},
				Certificates: []*x509.Certificate{cert},
			},
		}

		store := FetchResultToStore(results)
		if len(store.Containers) != 1 {
			t.Fatalf("expected 1 container, got %d", len(store.Containers))
		}
		if store.Containers[0].Source != SourceRemote {
			t.Errorf("source = %q, want %q", store.Containers[0].Source, SourceRemote)
		}
		if len(store.Containers[0].Items) != 1 {
			t.Errorf("expected 1 item, got %d", len(store.Containers[0].Items))
		}
		if store.Containers[0].Items[0].Type != ContentCertificate {
			t.Errorf("item type = %q, want %q", store.Containers[0].Items[0].Type, ContentCertificate)
		}
	})

	t.Run("error result skipped", func(t *testing.T) {
		results := []FetchResult{
			{
				Target: RemoteTarget{Host: "bad.example.com", Port: 443},
				Error:  net.ErrClosed,
			},
			{
				Target:       RemoteTarget{Host: "good.example.com", Port: 443},
				Certificates: []*x509.Certificate{cert},
			},
		}

		store := FetchResultToStore(results)
		if len(store.Containers) != 1 {
			t.Fatalf("expected 1 container (error result skipped), got %d", len(store.Containers))
		}
	})

	t.Run("empty certs skipped", func(t *testing.T) {
		results := []FetchResult{
			{
				Target:       RemoteTarget{Host: "empty.example.com", Port: 443},
				Certificates: nil,
			},
		}

		store := FetchResultToStore(results)
		if len(store.Containers) != 0 {
			t.Fatalf("expected 0 containers, got %d", len(store.Containers))
		}
	})

	t.Run("with AIA certs", func(t *testing.T) {
		serial2, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		template2 := &x509.Certificate{
			SerialNumber: serial2,
			Subject:      pkix.Name{CommonName: "aia-issuer"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Hour),
		}
		aiaDER, _ := x509.CreateCertificate(rand.Reader, template2, template2, &key.PublicKey, key)
		aiaCert, _ := x509.ParseCertificate(aiaDER)

		results := []FetchResult{
			{
				Target:       RemoteTarget{Host: "example.com", Port: 443},
				Certificates: []*x509.Certificate{cert},
				AIACerts:     []*x509.Certificate{aiaCert},
			},
		}

		store := FetchResultToStore(results)
		if len(store.Containers) != 1 {
			t.Fatalf("expected 1 container, got %d", len(store.Containers))
		}
		if len(store.Containers[0].Items) != 2 {
			t.Errorf("expected 2 items (cert + AIA), got %d", len(store.Containers[0].Items))
		}
	})
}

// --- Chain comparison tests ---

func TestCompareChains(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	makeCert := func(cn string) *x509.Certificate {
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		template := &x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Hour),
		}
		der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		cert, _ := x509.ParseCertificate(der)
		return cert
	}

	certA := makeCert("A")
	certB := makeCert("B")

	t.Run("identical chains", func(t *testing.T) {
		results := []FetchResult{
			{Certificates: []*x509.Certificate{certA}},
			{Certificates: []*x509.Certificate{certA}},
		}
		if !compareChains(results) {
			t.Error("identical chains should return true")
		}
	})

	t.Run("different chains", func(t *testing.T) {
		results := []FetchResult{
			{Certificates: []*x509.Certificate{certA}},
			{Certificates: []*x509.Certificate{certB}},
		}
		if compareChains(results) {
			t.Error("different chains should return false")
		}
	})

	t.Run("different lengths", func(t *testing.T) {
		results := []FetchResult{
			{Certificates: []*x509.Certificate{certA}},
			{Certificates: []*x509.Certificate{certA, certB}},
		}
		if compareChains(results) {
			t.Error("chains of different length should return false")
		}
	})

	t.Run("error results ignored", func(t *testing.T) {
		results := []FetchResult{
			{Certificates: []*x509.Certificate{certA}},
			{Error: net.ErrClosed},
			{Certificates: []*x509.Certificate{certA}},
		}
		if !compareChains(results) {
			t.Error("error results should be ignored, identical chains should return true")
		}
	})

	t.Run("single result is not identical", func(t *testing.T) {
		results := []FetchResult{
			{Certificates: []*x509.Certificate{certA}},
		}
		if compareChains(results) {
			t.Error("single result should return false (nothing to compare)")
		}
	})

	t.Run("all errors is not identical", func(t *testing.T) {
		results := []FetchResult{
			{Error: net.ErrClosed},
		}
		if compareChains(results) {
			t.Error("all-error results should return false (nothing to compare)")
		}
	})

	t.Run("no results is not identical", func(t *testing.T) {
		if compareChains(nil) {
			t.Error("empty results should return false (nothing to compare)")
		}
	})

	t.Run("one success among errors is not identical", func(t *testing.T) {
		results := []FetchResult{
			{Error: net.ErrClosed},
			{Certificates: []*x509.Certificate{certA}},
			{Error: net.ErrClosed},
		}
		if compareChains(results) {
			t.Error("a single successful result should return false (nothing to compare)")
		}
	})
}

// --- Proxy URL parsing tests ---

func TestDialWithProxyInvalidURL(t *testing.T) {
	ctx := context.Background()
	_, err := dialWithProxy(ctx, "://invalid", "host:443", time.Second)
	if err == nil {
		t.Error("expected error for invalid proxy URL")
	}
}

func TestDialWithProxyUnsupportedScheme(t *testing.T) {
	ctx := context.Background()
	_, err := dialWithProxy(ctx, "ftp://proxy:1080", "host:443", time.Second)
	if err == nil {
		t.Error("expected error for unsupported proxy scheme")
	}
}
