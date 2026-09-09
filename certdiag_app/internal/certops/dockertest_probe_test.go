//go:build dockertest

package certops

import (
	"strings"
	"testing"
)

func TestDockerProbe_ModernServer(t *testing.T) {
	requireDockerAvailable(t)

	result, err := ProbeRemoteTLS(ProbeRemoteOptions{
		Target:  dockerTarget(portModernTLS),
		Timeout: dockerTestTimeout,
	})
	if err != nil {
		t.Fatalf("ProbeRemoteTLS error: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("probe error: %s", result.Error)
	}
	if result.Probe == nil {
		t.Fatal("probe result is nil")
	}

	// Modern server should support TLS 1.2 and 1.3
	var tls12, tls13 bool
	for _, v := range result.Probe.Versions {
		switch {
		case strings.Contains(v.VersionName, "1.2") && v.Supported:
			tls12 = true
		case strings.Contains(v.VersionName, "1.3") && v.Supported:
			tls13 = true
		case strings.Contains(v.VersionName, "1.0") && v.Supported:
			t.Error("modern server should not support TLS 1.0")
		case strings.Contains(v.VersionName, "1.1") && v.Supported:
			t.Error("modern server should not support TLS 1.1")
		}
	}
	if !tls12 {
		t.Error("modern server should support TLS 1.2")
	}
	if !tls13 {
		t.Error("modern server should support TLS 1.3")
	}

	// Check that all ciphers are AEAD (no CBC)
	for _, cs := range result.Probe.CipherSuites {
		if cs.Supported {
			name := strings.ToUpper(cs.CipherSuiteName)
			if strings.Contains(name, "CBC") {
				t.Errorf("modern server has non-AEAD cipher: %s", cs.CipherSuiteName)
			}
			if strings.Contains(name, "RC4") || strings.Contains(name, "3DES") || strings.Contains(name, "NULL") {
				t.Errorf("modern server has weak cipher: %s", cs.CipherSuiteName)
			}
		}
	}
}

func TestDockerProbe_LegacyServer(t *testing.T) {
	requireDockerAvailable(t)
	requireServiceAvailable(t, portLegacyTLS)

	result, err := ProbeRemoteTLS(ProbeRemoteOptions{
		Target:  dockerTarget(portLegacyTLS),
		Timeout: dockerTestTimeout,
	})
	if err != nil {
		t.Fatalf("ProbeRemoteTLS error: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("probe error: %s", result.Error)
	}
	if result.Probe == nil {
		t.Fatal("probe result is nil")
	}

	var tls10, tls11, tls12 bool
	for _, v := range result.Probe.Versions {
		switch {
		case strings.Contains(v.VersionName, "1.0") && v.Supported:
			tls10 = true
		case strings.Contains(v.VersionName, "1.1") && v.Supported:
			tls11 = true
		case strings.Contains(v.VersionName, "1.2") && v.Supported:
			tls12 = true
		}
	}
	if !tls10 {
		t.Error("legacy server should support TLS 1.0")
	}
	if !tls11 {
		t.Error("legacy server should support TLS 1.1")
	}
	if !tls12 {
		t.Error("legacy server should support TLS 1.2")
	}

	// Legacy server should have CBC ciphers
	hasCBC := false
	for _, cs := range result.Probe.CipherSuites {
		if cs.Supported && strings.Contains(strings.ToUpper(cs.CipherSuiteName), "CBC") {
			hasCBC = true
			break
		}
	}
	if !hasCBC {
		t.Error("legacy server should have at least one CBC cipher")
	}
}

func TestDockerProbe_SSLv3Server(t *testing.T) {
	requireDockerAvailable(t)
	requireServiceAvailable(t, portSSLv3)

	result, err := ProbeRemoteTLS(ProbeRemoteOptions{
		Target:  dockerTarget(portSSLv3),
		Timeout: dockerTestTimeout,
	})
	if err != nil {
		t.Fatalf("ProbeRemoteTLS error: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("probe error: %s", result.Error)
	}
	if result.Probe == nil {
		t.Fatal("probe result is nil")
	}

	sslv3Supported := false
	for _, v := range result.Probe.Versions {
		if strings.Contains(strings.ToLower(v.VersionName), "ssl") && v.Supported {
			sslv3Supported = true
			break
		}
		// Also check by version number (0x0300)
		if v.Version == 0x0300 && v.Supported {
			sslv3Supported = true
			break
		}
	}
	if !sslv3Supported {
		t.Error("SSLv3 server should support SSLv3 (key Docker-only test)")
	}
}
