package cmdutil

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// KeyDestination decides where a generated private key goes (M31 decision D1).
//
//   - no key generated: keyOut unchanged
//   - --key-output given: that path
//   - certificate/CSR to stdout: "" (the caller prints both PEM blocks)
//   - otherwise: <certOut without extension>.key next to the certificate; an
//     existing file there is an error, never overwritten, because the user
//     did not name it.
func KeyDestination(certOut, keyOut string, withKey bool) (string, error) {
	if !withKey || keyOut != "" || certOut == "" {
		return keyOut, nil
	}
	ext := filepath.Ext(certOut)
	base := strings.TrimSuffix(certOut, ext)
	derived := base + ".key"
	if ext == ".key" {
		derived = certOut + ".key"
	}
	if _, err := os.Stat(derived); err == nil {
		return "", fmt.Errorf("key output %s already exists; pass --key-output to choose another path", derived)
	}
	return derived, nil
}
