//go:build fulltest

package certlib

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testCertsDir = filepath.Join("..", "..", "..", "tools", "testing", "certs")

// passwordFor returns a TaggedPassword slice for a specific fixture password.
func passwordFor(pw string) []TaggedPassword {
	return []TaggedPassword{{Password: []byte(pw), Source: PasswordSourceCLI}}
}

func wrongPasswords() []TaggedPassword {
	return []TaggedPassword{{Password: []byte("wrongpassword"), Source: PasswordSourceCLI}}
}

func noPasswords() []TaggedPassword {
	return nil
}

// --- PEM paths ---

func TestPEM_SingleCert(t *testing.T) {
	c, err := ReadFile(filepath.Join(testCertsDir, "self-signed-rsa.crt"), noPasswords())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Format != FormatPEM {
		t.Errorf("expected format PEM, got %s", c.Format)
	}
	if len(c.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(c.Items))
	}
	if c.Items[0].Type != ContentCertificate {
		t.Errorf("expected certificate, got %s", c.Items[0].Type)
	}
	if c.Items[0].Certificate == nil {
		t.Error("certificate is nil")
	}
}

func TestPEM_ChainFile(t *testing.T) {
	c, err := ReadFile(filepath.Join(testCertsDir, "ca-chain.pem"), noPasswords())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Format != FormatPEM {
		t.Errorf("expected format PEM, got %s", c.Format)
	}
	if len(c.Items) < 2 {
		t.Fatalf("expected at least 2 items in chain, got %d", len(c.Items))
	}
	for i, item := range c.Items {
		if item.Type != ContentCertificate {
			t.Errorf("item %d: expected certificate, got %s", i, item.Type)
		}
	}
}

func TestPEM_CombinedBundle(t *testing.T) {
	c, err := ReadFile(filepath.Join(testCertsDir, "combined-bundle.pem"), noPasswords())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	hasCert := false
	hasKey := false
	for _, item := range c.Items {
		if item.Type == ContentCertificate {
			hasCert = true
		}
		if item.Type == ContentPrivateKey {
			hasKey = true
		}
	}
	if !hasCert {
		t.Error("expected at least one certificate in combined bundle")
	}
	if !hasKey {
		t.Error("expected at least one private key in combined bundle")
	}
}

func TestPEM_CSR(t *testing.T) {
	c, err := ReadFile(filepath.Join(testCertsDir, "csr-request.csr"), noPasswords())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(c.Items) < 1 {
		t.Fatal("expected at least 1 item")
	}
	found := false
	for _, item := range c.Items {
		if item.Type == ContentCSR && item.CSR != nil {
			found = true
		}
	}
	if !found {
		t.Error("expected a CSR item with non-nil CSR")
	}
}

func TestPEM_EncryptedKey_PKCS8(t *testing.T) {
	c, err := ReadFile(filepath.Join(testCertsDir, "encrypted-key.key"), passwordFor("keypass123"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, item := range c.Items {
		if item.Type == ContentPrivateKey {
			found = true
			if !item.Encrypted {
				t.Error("expected Encrypted=true for PKCS#8 encrypted key")
			}
			if item.PrivateKey == nil {
				t.Error("expected PrivateKey to be decrypted (non-nil)")
			}
		}
	}
	if !found {
		t.Error("expected a private key item")
	}
	if len(c.ParseErrors) > 0 {
		t.Errorf("expected no parse errors, got: %v", c.ParseErrors)
	}
}

func TestPEM_EncryptedKey_WrongPassword(t *testing.T) {
	c, err := ReadFile(filepath.Join(testCertsDir, "encrypted-key.key"), wrongPasswords())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, item := range c.Items {
		if item.Type == ContentPrivateKey && item.Encrypted {
			found = true
		}
	}
	if !found {
		t.Error("expected an encrypted (undecrypted) private key item")
	}
	if len(c.ParseErrors) == 0 {
		t.Error("expected parse errors for failed decryption")
	}
}

func TestPEM_MixedValidInvalidBlocks(t *testing.T) {
	// Build a PEM file with: valid cert + garbage block + valid cert
	certPath := filepath.Join(testCertsDir, "self-signed-rsa.crt")
	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("failed to read cert fixture: %v", err)
	}

	garbageBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("this is not a valid certificate"),
	})

	combined := append(certData, garbageBlock...)
	combined = append(combined, certData...)

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "mixed.pem")
	if err := os.WriteFile(tmpFile, combined, 0644); err != nil {
		t.Fatal(err)
	}

	c, err := ReadFile(tmpFile, noPasswords())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	certCount := 0
	for _, item := range c.Items {
		if item.Type == ContentCertificate {
			certCount++
		}
	}
	if certCount != 2 {
		t.Errorf("expected 2 valid certificates, got %d", certCount)
	}
	if len(c.ParseErrors) == 0 {
		t.Error("expected parse errors for the garbage block")
	}
}

func TestPEM_OnlyInvalidBlocks(t *testing.T) {
	garbageBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("not a valid cert at all"),
	})

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "garbage.pem")
	if err := os.WriteFile(tmpFile, garbageBlock, 0644); err != nil {
		t.Fatal(err)
	}

	// readPEM returns ErrUnknownFormat when Items==0 and ParseErrors has entries
	// Actually it returns the container with ParseErrors. Let's check both cases.
	c, err := ReadFile(tmpFile, noPasswords())
	// With no valid items but parse errors present, readPEM returns the container (not ErrUnknownFormat)
	// because the condition is: len(Items)==0 && len(ParseErrors)==0 -> ErrUnknownFormat
	// Here ParseErrors won't be empty, so we get a container back.
	if err != nil {
		// It's also acceptable if it returns ErrUnknownFormat
		if !errors.Is(err, ErrUnknownFormat) {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	if c != nil && len(c.ParseErrors) == 0 {
		t.Error("expected parse errors when all blocks are invalid")
	}
}

func TestPEM_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "empty.pem")
	if err := os.WriteFile(tmpFile, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	_, err := ReadFile(tmpFile, noPasswords())
	if !errors.Is(err, ErrUnknownFormat) {
		t.Errorf("expected ErrUnknownFormat, got %v", err)
	}
}

func TestPEM_TrailingGarbage(t *testing.T) {
	certPath := filepath.Join(testCertsDir, "self-signed-rsa.crt")
	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}

	withGarbage := append(certData, []byte("\n\nsome trailing garbage text\n")...)

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "trailing.pem")
	if err := os.WriteFile(tmpFile, withGarbage, 0644); err != nil {
		t.Fatal(err)
	}

	c, err := ReadFile(tmpFile, noPasswords())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(c.Items) != 1 {
		t.Errorf("expected 1 item, got %d", len(c.Items))
	}
	if c.Items[0].Type != ContentCertificate {
		t.Errorf("expected certificate, got %s", c.Items[0].Type)
	}
}

// --- DER paths ---

func TestDER_Table(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		wantType ContentType
	}{
		{"RSA cert", "rsa-cert.der", ContentCertificate},
		{"ECDSA cert", "ecdsa-cert.der", ContentCertificate},
		{"RSA key", "rsa-key.der", ContentPrivateKey},
		{"CSR", "request.csr.der", ContentCSR},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := ReadFile(filepath.Join(testCertsDir, tt.file), noPasswords())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.Format != FormatDER {
				t.Errorf("expected format DER, got %s", c.Format)
			}
			if len(c.Items) != 1 {
				t.Fatalf("expected 1 item, got %d", len(c.Items))
			}
			if c.Items[0].Type != tt.wantType {
				t.Errorf("expected type %s, got %s", tt.wantType, c.Items[0].Type)
			}
		})
	}
}

func TestDER_Truncated(t *testing.T) {
	certPath := filepath.Join(testCertsDir, "rsa-cert.der")
	data, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}

	truncated := data[:len(data)/2]
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "truncated.der")
	if err := os.WriteFile(tmpFile, truncated, 0644); err != nil {
		t.Fatal(err)
	}

	_, err = ReadFile(tmpFile, noPasswords())
	if !errors.Is(err, ErrUnknownFormat) {
		t.Errorf("expected ErrUnknownFormat for truncated DER, got %v", err)
	}
}

func TestDER_ZeroByte(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "empty.der")
	if err := os.WriteFile(tmpFile, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	_, err := ReadFile(tmpFile, noPasswords())
	if !errors.Is(err, ErrUnknownFormat) {
		t.Errorf("expected ErrUnknownFormat for zero-byte DER, got %v", err)
	}
}

// --- PKCS#12 paths ---

func TestPKCS12_Table(t *testing.T) {
	tests := []struct {
		name          string
		file          string
		passwords     []TaggedPassword
		wantCerts     bool
		wantKey       bool
		wantMinItems  int
		wantErrSubstr string
	}{
		{
			name:         "standard with correct password",
			file:         "standard.p12",
			passwords:    passwordFor("p12pass"),
			wantCerts:    true,
			wantKey:      true,
			wantMinItems: 2,
		},
		{
			name:         "empty password",
			file:         "empty-password.p12",
			passwords:    noPasswords(),
			wantCerts:    true,
			wantMinItems: 1,
		},
		{
			name:          "wrong password",
			file:          "wrong-password.p12",
			passwords:     wrongPasswords(),
			wantErrSubstr: "password required",
		},
		{
			name:         "with chain",
			file:         "with-chain.p12",
			passwords:    passwordFor("chainpass"),
			wantCerts:    true,
			wantMinItems: 2,
		},
		{
			name:         "ECDSA",
			file:         "ecdsa.pfx",
			passwords:    passwordFor("ecdsapfx"),
			wantCerts:    true,
			wantKey:      true,
			wantMinItems: 2,
		},
		{
			name:         "legacy DES3",
			file:         "legacy-des3.p12",
			passwords:    passwordFor("legacydes"),
			wantCerts:    true,
			wantMinItems: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := ReadFile(filepath.Join(testCertsDir, tt.file), tt.passwords)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.Format != FormatPKCS12 {
				t.Errorf("expected format PKCS12, got %s", c.Format)
			}

			if tt.wantErrSubstr != "" {
				if len(c.ParseErrors) == 0 {
					t.Error("expected parse errors")
				}
				return
			}

			if len(c.Items) < tt.wantMinItems {
				t.Errorf("expected at least %d items, got %d", tt.wantMinItems, len(c.Items))
			}

			if tt.wantCerts {
				found := false
				for _, item := range c.Items {
					if item.Type == ContentCertificate && item.Certificate != nil {
						found = true
						break
					}
				}
				if !found {
					t.Error("expected at least one certificate")
				}
			}

			if tt.wantKey {
				found := false
				for _, item := range c.Items {
					if item.Type == ContentPrivateKey && item.PrivateKey != nil {
						found = true
						break
					}
				}
				if !found {
					t.Error("expected at least one private key")
				}
			}
		})
	}
}

// --- JKS paths ---

func TestJKS_Table(t *testing.T) {
	tests := []struct {
		name          string
		file          string
		passwords     []TaggedPassword
		wantMinItems  int
		wantErrSubstr string
	}{
		{
			name:         "keystore with entries",
			file:         "keystore.jks",
			passwords:    passwordFor("changeit"),
			wantMinItems: 1,
		},
		{
			name:          "wrong password",
			file:          "wrong-password.jks",
			passwords:     wrongPasswords(),
			wantErrSubstr: "password required",
		},
		{
			name:         "multi entries",
			file:         "multi.jks",
			passwords:    passwordFor("multientry"),
			wantMinItems: 2,
		},
		{
			name:         "trust store",
			file:         "truststore.jks",
			passwords:    passwordFor("trustme"),
			wantMinItems: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := ReadFile(filepath.Join(testCertsDir, tt.file), tt.passwords)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.Format != FormatJKS {
				t.Errorf("expected format JKS, got %s", c.Format)
			}

			if tt.wantErrSubstr != "" {
				if len(c.ParseErrors) == 0 {
					t.Error("expected parse errors")
				}
				return
			}

			if len(c.Items) < tt.wantMinItems {
				t.Errorf("expected at least %d items, got %d", tt.wantMinItems, len(c.Items))
			}
		})
	}
}

// --- PKCS#7 paths ---

func TestPKCS7_Table(t *testing.T) {
	tests := []struct {
		name         string
		file         string
		wantMinCerts int
	}{
		{"chain p7b", "chain.p7b", 2},
		{"single p7b", "single.p7b", 1},
		{"PEM-encoded p7b", "pem-encoded.p7b", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := ReadFile(filepath.Join(testCertsDir, tt.file), noPasswords())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.Format != FormatPKCS7 {
				t.Errorf("expected format PKCS7, got %s", c.Format)
			}
			certCount := 0
			for _, item := range c.Items {
				if item.Type == ContentCertificate {
					certCount++
				}
			}
			if certCount < tt.wantMinCerts {
				t.Errorf("expected at least %d certs, got %d", tt.wantMinCerts, certCount)
			}
		})
	}
}

// --- Edge cases ---

func TestEdge_ZeroByteWithCrtExtension(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "empty.crt")
	if err := os.WriteFile(tmpFile, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	_, err := ReadFile(tmpFile, noPasswords())
	if !errors.Is(err, ErrUnknownFormat) {
		t.Errorf("expected ErrUnknownFormat for zero-byte .crt, got %v", err)
	}
}

func TestEdge_BinaryGarbageWithCrtExtension(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "garbage.crt")
	garbage := []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56}
	if err := os.WriteFile(tmpFile, garbage, 0644); err != nil {
		t.Fatal(err)
	}

	_, err := ReadFile(tmpFile, noPasswords())
	if !errors.Is(err, ErrUnknownFormat) {
		t.Errorf("expected ErrUnknownFormat for binary garbage .crt, got %v", err)
	}
}

func TestEdge_EmptyPEMMarkers(t *testing.T) {
	content := []byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "empty-markers.pem")
	if err := os.WriteFile(tmpFile, content, 0644); err != nil {
		t.Fatal(err)
	}

	c, err := ReadFile(tmpFile, noPasswords())
	// Empty PEM block decodes to zero bytes; x509.ParseCertificate will fail.
	// readPEM should either return a container with parse errors or ErrUnknownFormat.
	if err != nil {
		if !errors.Is(err, ErrUnknownFormat) {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	if len(c.ParseErrors) == 0 && len(c.Items) == 0 {
		t.Error("expected either parse errors or items for empty PEM markers")
	}
}

// --- passwordsWithEmpty tests ---

func TestPasswordsWithEmpty_AlreadyContainsEmpty(t *testing.T) {
	input := [][]byte{[]byte("changeit"), []byte("")}
	result := passwordsWithEmpty(input)
	if len(result) != 2 {
		t.Errorf("expected 2 passwords (no duplicate), got %d", len(result))
	}
}

func TestPasswordsWithEmpty_NoEmpty(t *testing.T) {
	input := [][]byte{[]byte("changeit"), []byte("secret")}
	result := passwordsWithEmpty(input)
	if len(result) != 3 {
		t.Errorf("expected 3 passwords (empty appended), got %d", len(result))
	}
	last := result[len(result)-1]
	if len(last) != 0 {
		t.Errorf("expected last password to be empty, got %q", last)
	}
}

func TestPasswordsWithEmpty_EmptyInput(t *testing.T) {
	var input [][]byte
	result := passwordsWithEmpty(input)
	if len(result) != 1 {
		t.Fatalf("expected 1 password, got %d", len(result))
	}
	if len(result[0]) != 0 {
		t.Errorf("expected empty password, got %q", result[0])
	}
}

// --- New edge case tests ---

func TestPEM_WithUTF8BOM(t *testing.T) {
	// Windows editors often prepend UTF-8 BOM before PEM data.
	// isPEM() uses pem.Decode which should handle this, but the BOM
	// bytes could interfere with prefix detection.
	certPath := filepath.Join(testCertsDir, "self-signed-rsa.crt")
	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}

	bom := []byte{0xEF, 0xBB, 0xBF}
	withBOM := append(bom, certData...)

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "bom.pem")
	if err := os.WriteFile(tmpFile, withBOM, 0644); err != nil {
		t.Fatal(err)
	}

	c, err := ReadFile(tmpFile, noPasswords())
	// Document actual behavior: BOM may prevent PEM detection.
	// If it fails, that's the current behavior (BOM not stripped).
	if err != nil {
		if !errors.Is(err, ErrUnknownFormat) {
			t.Fatalf("unexpected error type: %v", err)
		}
		// BOM causes PEM detection failure -- this documents the current behavior.
		// A future fix could strip BOM before parsing.
		t.Log("BOM prefix prevents PEM detection (known limitation)")
		return
	}
	if len(c.Items) != 1 {
		t.Errorf("expected 1 item, got %d", len(c.Items))
	}
}

func TestPEM_UnknownBlockTypeReported(t *testing.T) {
	// A file with only unrecognised PEM block types is reported with the
	// types it holds (M31 WP8), not as a bare "unknown format".
	unknownBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"),
	})

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "unknown.pem")
	if err := os.WriteFile(tmpFile, unknownBlock, 0644); err != nil {
		t.Fatal(err)
	}

	_, err := ReadFile(tmpFile, noPasswords())
	if err == nil || !strings.Contains(err.Error(), "OPENSSH PRIVATE KEY") {
		t.Fatalf("expected the block type in the error, got %v", err)
	}
}

func TestPEM_UnknownBlockMixedWithValid(t *testing.T) {
	// Unknown block type mixed with valid cert: cert should be parsed,
	// unknown block silently skipped (no parse error for it).
	certPath := filepath.Join(testCertsDir, "self-signed-rsa.crt")
	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}

	unknownBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: []byte("fake-openssh-key-data"),
	})

	combined := append(unknownBlock, certData...)

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "mixed-unknown.pem")
	if err := os.WriteFile(tmpFile, combined, 0644); err != nil {
		t.Fatal(err)
	}

	c, err := ReadFile(tmpFile, noPasswords())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(c.Items) != 1 {
		t.Errorf("expected 1 item (cert only), got %d", len(c.Items))
	}
	if c.Items[0].Type != ContentCertificate {
		t.Errorf("expected certificate, got %s", c.Items[0].Type)
	}
	// No parse error is recorded for the unknown block type --
	// it is silently dropped.
}

// Ensure DER items have proper x509 objects
func TestDER_CertHasSubject(t *testing.T) {
	c, err := ReadFile(filepath.Join(testCertsDir, "rsa-cert.der"), noPasswords())
	if err != nil {
		t.Fatal(err)
	}
	cert := c.Items[0].Certificate
	if cert == nil {
		t.Fatal("certificate is nil")
	}
	if cert.Subject.String() == "" {
		t.Error("certificate subject is empty")
	}
	if cert.PublicKeyAlgorithm != x509.RSA {
		t.Errorf("expected RSA public key algorithm, got %v", cert.PublicKeyAlgorithm)
	}
}

// ---------------------------------------------------------------------------
// Input-format edge cases (from input_formats.md)
// ---------------------------------------------------------------------------

// TestPEM_CertWith100SANs verifies that a certificate with 100+ SAN entries
// round-trips correctly through PEM write and read.
func TestPEM_CertWith100SANs(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	dnsNames := make([]string, 120)
	for i := range dnsNames {
		dnsNames[i] = fmt.Sprintf("host%d.example.com", i)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "many-sans"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		DNSNames:              dnsNames,
		IPAddresses:           []net.IP{net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2)},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	tmpDir := t.TempDir()
	tmpFile := mustWriteTempFile(t, tmpDir, "many-sans.pem", pemData)
	c, err := ReadFile(tmpFile, noPasswords())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(c.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(c.Items))
	}
	cert := c.Items[0].Certificate
	if cert == nil {
		t.Fatal("certificate is nil")
	}
	if len(cert.DNSNames) != 120 {
		t.Errorf("expected 120 DNS SANs, got %d", len(cert.DNSNames))
	}
	if len(cert.IPAddresses) != 2 {
		t.Errorf("expected 2 IP SANs, got %d", len(cert.IPAddresses))
	}
}

// TestPEM_MinimalSelfSignedRoundTrip creates a self-signed certificate with
// minimal fields (no SAN, no KeyUsage, no BasicConstraints beyond what Go adds),
// writes it as PEM, reads it back, and verifies the result is parseable.
// Note: Go's x509.CreateCertificate always adds AuthorityKeyIdentifier for
// self-signed certs, which forces v3. This test documents that behavior.
func TestPEM_MinimalSelfSignedRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "minimal-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	tmpDir := t.TempDir()
	tmpFile := mustWriteTempFile(t, tmpDir, "minimal-cert.pem", pemData)

	c, err := ReadFile(tmpFile, noPasswords())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(c.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(c.Items))
	}
	cert := c.Items[0].Certificate
	if cert == nil {
		t.Fatal("certificate is nil")
	}
	// Go always produces v3 for self-signed (adds AuthorityKeyIdentifier).
	if cert.Version != 3 {
		t.Errorf("expected X.509 version 3 (Go default for self-signed), got %d", cert.Version)
	}
	if cert.Subject.CommonName != "minimal-test" {
		t.Errorf("expected CN=minimal-test, got %q", cert.Subject.CommonName)
	}
	// No SAN requested
	if len(cert.DNSNames) != 0 {
		t.Errorf("expected 0 DNS SANs, got %d", len(cert.DNSNames))
	}
}

// TestPEM_NonStandardBase64LineLength writes a PEM block with 76-char base64
// lines (MIME standard) instead of the usual 64-char lines. Go's pem.Decode
// should handle this gracefully.
func TestPEM_NonStandardBase64LineLength(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "wide-base64"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}

	// Manually encode PEM with 76-char base64 lines
	b64 := base64.StdEncoding.EncodeToString(der)
	var lines []string
	lines = append(lines, "-----BEGIN CERTIFICATE-----")
	for len(b64) > 76 {
		lines = append(lines, b64[:76])
		b64 = b64[76:]
	}
	if len(b64) > 0 {
		lines = append(lines, b64)
	}
	lines = append(lines, "-----END CERTIFICATE-----")
	pemData := []byte(strings.Join(lines, "\n") + "\n")

	tmpDir := t.TempDir()
	tmpFile := mustWriteTempFile(t, tmpDir, "wide-base64.pem", pemData)
	c, err := ReadFile(tmpFile, noPasswords())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(c.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(c.Items))
	}
	if c.Items[0].Certificate == nil {
		t.Error("certificate is nil")
	}
}

// TestPEM_WildcardVariants tests reading certs with unusual wildcard SAN entries.
func TestPEM_WildcardVariants(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		dnsNames []string
	}{
		{"standard_wildcard", []string{"*.example.com"}},
		{"multi_level_wildcard", []string{"*.sub.example.com"}},
		{"mixed_wildcard_and_exact", []string{"*.example.com", "example.com", "www.example.com"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
			template := &x509.Certificate{
				SerialNumber:          serial,
				Subject:               pkix.Name{CommonName: tt.dnsNames[0]},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(365 * 24 * time.Hour),
				DNSNames:              tt.dnsNames,
				BasicConstraintsValid: true,
			}
			der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
			if err != nil {
				t.Fatal(err)
			}
			pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
			tmpDir := t.TempDir()
			tmpFile := mustWriteTempFile(t, tmpDir, "wildcard.pem", pemData)

			c, readErr := ReadFile(tmpFile, noPasswords())
			if readErr != nil {
				t.Fatalf("unexpected error: %v", readErr)
			}
			if len(c.Items) != 1 {
				t.Fatalf("expected 1 item, got %d", len(c.Items))
			}
			cert := c.Items[0].Certificate
			if cert == nil {
				t.Fatal("certificate is nil")
			}
			if len(cert.DNSNames) != len(tt.dnsNames) {
				t.Errorf("expected %d DNS SANs, got %d", len(tt.dnsNames), len(cert.DNSNames))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// cfssl-inspired edge cases
// ---------------------------------------------------------------------------

// TestDER_TrailingWhitespaceBytePreserved verifies that DER data whose final
// byte happens to be a whitespace character (0x0A = newline) is not corrupted
// by any trimming. cfssl#937 found that bytes.TrimSpace on DER corrupts certs.
func TestDER_TrailingWhitespaceBytePreserved(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "der-trim-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the raw DER can be parsed as-is (regardless of final byte value)
	tmpDir := t.TempDir()
	tmpFile := mustWriteTempFile(t, tmpDir, "cert.der", der)
	c, err := ReadFile(tmpFile, noPasswords())
	if err != nil {
		t.Fatalf("unexpected error reading DER: %v", err)
	}
	if len(c.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(c.Items))
	}
	// Verify raw bytes match exactly (no trimming)
	if !bytes.Equal(c.Items[0].RawBytes, der) {
		t.Error("DER raw bytes were modified (possible TrimSpace corruption)")
	}
}

// TestPEM_ECParametersBlockSkipped verifies that a PEM file containing an
// EC PARAMETERS block (from `openssl ecparam -genkey`) before the EC PRIVATE KEY
// block is handled gracefully -- the parameters block is silently skipped and
// the key is still extracted. cfssl#1074.
func TestPEM_ECParametersBlockSkipped(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Marshal the EC key as SEC1
	ecBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	// Construct PEM with EC PARAMETERS block first (like openssl ecparam output)
	// The EC PARAMETERS block contains the curve OID in ASN.1
	curveOID := asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7} // P-256
	paramBytes, err := asn1.Marshal(curveOID)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	pem.Encode(&buf, &pem.Block{Type: "EC PARAMETERS", Bytes: paramBytes})
	pem.Encode(&buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: ecBytes})

	tmpDir := t.TempDir()
	tmpFile := mustWriteTempFile(t, tmpDir, "ec-with-params.pem", buf.Bytes())

	c, err := ReadFile(tmpFile, noPasswords())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// EC PARAMETERS block is unknown -> silently skipped
	// EC PRIVATE KEY block -> parsed as key
	if len(c.Items) != 1 {
		t.Fatalf("expected 1 item (key only, EC PARAMETERS skipped), got %d", len(c.Items))
	}
	if c.Items[0].Type != ContentPrivateKey {
		t.Errorf("expected private key, got %s", c.Items[0].Type)
	}
	if c.Items[0].PrivateKey == nil {
		t.Error("private key is nil")
	}
}

// TestPKCS12_MalformedInputNoPanic verifies that feeding random/truncated bytes
// to the PKCS#12 reader produces graceful behavior (no panic, parse errors
// recorded, zero items extracted). cfssl#279.
func TestPKCS12_MalformedInputNoPanic(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"random_bytes", []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}},
		{"truncated_asn1_header", []byte{0x30, 0x82, 0x01}},
		{"null_bytes", make([]byte, 256)},
		{"single_byte", []byte{0x30}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			tmpFile := mustWriteTempFile(t, tmpDir, "bad.p12", tt.data)
			// Should not panic. May return error or container with parse errors.
			c, err := ReadFile(tmpFile, passwordFor("test"))
			if err != nil {
				return // error is fine
			}
			// If no error, container should have 0 items and parse errors
			if len(c.Items) > 0 {
				t.Errorf("expected 0 items from malformed P12, got %d", len(c.Items))
			}
			if len(c.ParseErrors) == 0 {
				t.Error("expected parse errors for malformed P12, got none")
			}
		})
	}
}

// TestPEM_GeneralizedTimeBeyond2049 creates a certificate with NotAfter in
// the year 2060. RFC 5280 requires GeneralizedTime encoding for dates >= 2050.
// Verifies that the certificate round-trips correctly. cfssl#1329.
func TestPEM_GeneralizedTimeBeyond2049(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "long-lived-root"},
		NotBefore:             time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2060, 12, 31, 23, 59, 59, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	tmpDir := t.TempDir()
	tmpFile := mustWriteTempFile(t, tmpDir, "long-lived.pem", pemData)

	c, err := ReadFile(tmpFile, noPasswords())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(c.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(c.Items))
	}
	cert := c.Items[0].Certificate
	if cert == nil {
		t.Fatal("certificate is nil")
	}
	if cert.NotAfter.Year() != 2060 {
		t.Errorf("expected NotAfter year 2060, got %d", cert.NotAfter.Year())
	}
}

// TestPEM_CACertWithDNSSANs verifies that a CA certificate with DNS SANs
// has those SANs correctly parsed and accessible. cfssl#1276 found that some
// tools strip SANs from CA certs.
func TestPEM_CACertWithDNSSANs(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "My CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		DNSNames:              []string{"ca.example.com", "ca.example.org"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	tmpDir := t.TempDir()
	tmpFile := mustWriteTempFile(t, tmpDir, "ca-with-sans.pem", pemData)

	c, err := ReadFile(tmpFile, noPasswords())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cert := c.Items[0].Certificate
	if len(cert.DNSNames) != 2 {
		t.Errorf("expected 2 DNS SANs on CA cert, got %d", len(cert.DNSNames))
	}
	if !cert.IsCA {
		t.Error("expected IsCA=true")
	}
}

// TestPEM_CertWithAllFourSANTypes verifies that a certificate with DNS, IP,
// email, and URI SANs has all four types correctly parsed. cfssl#1389 found
// that only DNS SANs were preserved in some code paths.
func TestPEM_CertWithAllFourSANTypes(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	uriVal, _ := parseURI("https://auth.example.com/oidc")

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "all-san-types"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		DNSNames:              []string{"example.com", "www.example.com"},
		IPAddresses:           []net.IP{net.IPv4(10, 0, 0, 1), net.ParseIP("::1")},
		EmailAddresses:        []string{"admin@example.com"},
		URIs:                  []*url.URL{uriVal},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	tmpDir := t.TempDir()
	tmpFile := mustWriteTempFile(t, tmpDir, "all-sans.pem", pemData)

	c, err := ReadFile(tmpFile, noPasswords())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cert := c.Items[0].Certificate
	if len(cert.DNSNames) != 2 {
		t.Errorf("expected 2 DNS SANs, got %d", len(cert.DNSNames))
	}
	if len(cert.IPAddresses) != 2 {
		t.Errorf("expected 2 IP SANs, got %d", len(cert.IPAddresses))
	}
	if len(cert.EmailAddresses) != 1 {
		t.Errorf("expected 1 email SAN, got %d", len(cert.EmailAddresses))
	}
	if len(cert.URIs) != 1 {
		t.Errorf("expected 1 URI SAN, got %d", len(cert.URIs))
	}
}

// parseURI is a small helper to parse a URI string for test use.
func parseURI(raw string) (*url.URL, error) {
	return url.Parse(raw)
}

// TestDER_CertFromSmoketestFixtures reads the pre-generated DER
// fixtures and verifies they parse correctly.
func TestDER_CertFromSmoketestFixtures(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		itemType ContentType
	}{
		{"ecdsa_der_cert", "ecdsa-cert.der", ContentCertificate},
		{"rsa_der_cert", "rsa-cert.der", ContentCertificate},
		{"rsa_der_key", "rsa-key.der", ContentPrivateKey},
		{"csr_der", "request.csr.der", ContentCSR},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := ReadFile(filepath.Join(testCertsDir, tt.file), noPasswords())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(c.Items) != 1 {
				t.Fatalf("expected 1 item, got %d", len(c.Items))
			}
			if c.Items[0].Type != tt.itemType {
				t.Errorf("expected %s, got %s", tt.itemType, c.Items[0].Type)
			}
		})
	}
}
