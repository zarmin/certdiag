package certlib

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// A file extension is a hint, not a guarantee. ".crt" and ".cer" are routinely
// used for DER as well as PEM (Microsec's e-Szigno roots ship that way), and
// certdiag used to trust the extension absolutely: a DER certificate named
// .crt was parsed as PEM, failed, and reported "unknown or unsupported file
// format" for a file it could read perfectly well.
//
// The fallback is gated on the extension being a known certificate extension,
// so it applies during directory scans too (the TUI included). Extensions
// outside that set stay strict: the recursive walk has no filter of its own and
// relies on this reader refusing unrelated files, which is what
// --file-signature-scan opts into. See TestReadFileCore_UnknownExtensionStrict.

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadFile_DERContentWithPEMExtension(t *testing.T) {
	cert, _ := generateTestCertAndKey(t)

	for _, name := range []string{"root.crt", "root.cer", "root.pem", "root.csr", "root"} {
		t.Run(name, func(t *testing.T) {
			path := writeTemp(t, name, cert.Raw)

			container, err := ReadFile(path, nil)
			if err != nil {
				t.Fatalf("DER content named %q must still be read: %v", name, err)
			}
			if container.Format != FormatDER {
				t.Errorf("expected the real format DER, got %q", container.Format)
			}
			if len(container.Items) != 1 {
				t.Fatalf("expected 1 item, got %d", len(container.Items))
			}
			if got := container.Items[0].Certificate; got == nil ||
				got.Subject.CommonName != cert.Subject.CommonName {
				t.Error("expected the certificate to round-trip")
			}
		})
	}
}

func TestReadFile_PEMContentWithDERExtension(t *testing.T) {
	cert, _ := generateTestCertAndKey(t)
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	path := writeTemp(t, "root.der", encoded)
	container, err := ReadFile(path, nil)
	if err != nil {
		t.Fatalf("PEM content named .der must still be read: %v", err)
	}
	if container.Format != FormatPEM {
		t.Errorf("expected the real format PEM, got %q", container.Format)
	}
}

func TestReadFile_CorrectExtensionStillWins(t *testing.T) {
	// The fallback must not change behaviour for correctly named files.
	cert, _ := generateTestCertAndKey(t)
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	pemPath := writeTemp(t, "root.pem", encoded)
	if c, err := ReadFile(pemPath, nil); err != nil || c.Format != FormatPEM {
		t.Errorf("expected PEM, got %q (%v)", c.Format, err)
	}

	derPath := writeTemp(t, "root.der", cert.Raw)
	if c, err := ReadFile(derPath, nil); err != nil || c.Format != FormatDER {
		t.Errorf("expected DER, got %q (%v)", c.Format, err)
	}
}

func TestReadFile_UnreadableContentStillErrors(t *testing.T) {
	// The fallback must not turn genuine garbage into a spurious success.
	for _, name := range []string{"junk.crt", "junk.pem", "junk.der", "junk"} {
		path := writeTemp(t, name, []byte("this is not a certificate in any encoding"))
		if _, err := ReadFile(path, nil); err == nil {
			t.Errorf("%s: expected an error for unreadable content", name)
		}
	}
}

func TestReadFile_EmptyFileStillErrors(t *testing.T) {
	path := writeTemp(t, "empty.crt", nil)
	if _, err := ReadFile(path, nil); err == nil {
		t.Error("expected an error for an empty file")
	}
}

func TestReadFileCore_UnknownExtensionStrict(t *testing.T) {
	// The directory walk has no extension filter of its own; it relies on this
	// reader rejecting unrelated files. Sniffing every extension would silently
	// make --file-signature-scan a no-op and parse every file in a scanned tree.
	cert, _ := generateTestCertAndKey(t)
	path := writeTemp(t, "mystery.dat", cert.Raw)

	if _, err := readFileCore(path, nil, nil); err == nil {
		t.Error("readFileCore must not sniff content for a non-certificate extension")
	}

	// The same bytes, named explicitly, are still read.
	if _, err := ReadFile(path, nil); err != nil {
		t.Errorf("an explicitly named file must still be read: %v", err)
	}
}

// TestReadFileCore_KnownExtensionFallsBack is the scan path: this is what makes
// `certdiag tui .` list a DER certificate that happens to be named .crt.
func TestReadFileCore_KnownExtensionFallsBack(t *testing.T) {
	cert, _ := generateTestCertAndKey(t)

	// ".csr" has no entry in FormatFromExtension at all, so it exercises the
	// other branch into the fallback.
	for _, name := range []string{"root.crt", "root.cer", "root.pem", "root.key", "root.csr"} {
		t.Run(name, func(t *testing.T) {
			path := writeTemp(t, name, cert.Raw)

			container, err := readFileCore(path, nil, nil)
			if err != nil {
				t.Fatalf("a certificate extension must fall back to content: %v", err)
			}
			if container.Format != FormatDER {
				t.Errorf("expected DER, got %q", container.Format)
			}
		})
	}
}

func TestScanPath_FindsDERWithCertExtension(t *testing.T) {
	// End to end through the scanner, which is what the TUI and a plain
	// `certdiag <dir>` both use.
	cert, _ := generateTestCertAndKey(t)
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "root.crt"), cert.Raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// A DER certificate under a non-certificate extension must stay invisible
	// without --file-signature-scan.
	if err := os.WriteFile(filepath.Join(dir, "mystery.dat"), cert.Raw, 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := ScanPathWithOptions(dir, ScanOptions{})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	var names []string
	for _, c := range store.Containers {
		names = append(names, filepath.Base(c.FilePath))
	}
	if len(names) != 1 || names[0] != "root.crt" {
		t.Fatalf("expected only root.crt, got %v", names)
	}
	if store.Containers[0].Format != FormatDER {
		t.Errorf("expected the real format DER, got %q", store.Containers[0].Format)
	}

	// With signature scanning both are found.
	store, err = ScanPathWithOptions(dir, ScanOptions{UseSignatureScan: true})
	if err != nil {
		t.Fatalf("signature scan failed: %v", err)
	}
	if len(store.Containers) != 2 {
		t.Errorf("expected both files with --file-signature-scan, got %d", len(store.Containers))
	}
}
