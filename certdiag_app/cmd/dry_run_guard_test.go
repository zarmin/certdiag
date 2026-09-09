package cmd

import (
	"testing"

	"github.com/spf13/cobra"
)

// TestValidateOpenSSLFlags covers the M6 guard: --dry-run requires
// --show-openssl, and both are rejected on commands that do not implement them.
func TestValidateOpenSSLFlags(t *testing.T) {
	supported := &cobra.Command{Use: "convert"}
	markOpenSSLSupported(supported)
	unsupported := &cobra.Command{Use: "bundle"}

	t.Cleanup(func() { showOpenSSLFlag, dryRunFlag = false, false })

	cases := []struct {
		name     string
		cmd      *cobra.Command
		showOpen bool
		dryRun   bool
		wantErr  bool
	}{
		{"neither flag, supported", supported, false, false, false},
		{"neither flag, unsupported", unsupported, false, false, false},
		{"show-openssl on supported", supported, true, false, false},
		{"show-openssl + dry-run on supported", supported, true, true, false},
		{"dry-run alone requires show-openssl", supported, false, true, true},
		{"show-openssl on unsupported command", unsupported, true, false, true},
		{"dry-run on unsupported command", unsupported, false, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			showOpenSSLFlag, dryRunFlag = tc.showOpen, tc.dryRun
			err := validateOpenSSLFlags(tc.cmd)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateOpenSSLFlags() err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}
