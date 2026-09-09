package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
)

// buildRevocationConfig validates the revocation flags and produces the certops
// config. A local CRL file implies offline CRL checking.
func buildRevocationConfig(cmd *cobra.Command, enabled bool, method string, require bool, crlFile string) (certops.RevocationConfig, error) {
	// Validate the method even when revocation is off, so a typo is caught.
	m, err := parseRevocationMethod(method)
	if err != nil {
		return certops.RevocationConfig{}, err
	}
	if !enabled && crlFile == "" {
		if require {
			return certops.RevocationConfig{}, fmt.Errorf("--revocation-require has no effect without --revocation (or --crl-file)")
		}
		return certops.RevocationConfig{}, nil
	}
	methodChanged := cmd != nil && cmd.Flags().Changed("revocation-method")
	if crlFile != "" && methodChanged && m == certlib.RevocationMethodOCSP {
		// --crl-file supplies an offline CRL; OCSP-only would silently ignore it.
		return certops.RevocationConfig{}, fmt.Errorf("--crl-file cannot be combined with --revocation-method ocsp; use --revocation-method crl or auto")
	}
	if crlFile != "" && !methodChanged {
		m = certlib.RevocationMethodCRL
	}
	return certops.RevocationConfig{
		Enabled: true,
		Require: require,
		Method:  m,
		CRLFile: crlFile,
	}, nil
}

func parseRevocationMethod(method string) (certlib.RevocationMethod, error) {
	switch certlib.RevocationMethod(method) {
	case certlib.RevocationMethodAuto, certlib.RevocationMethodOCSP, certlib.RevocationMethodCRL:
		return certlib.RevocationMethod(method), nil
	default:
		return "", fmt.Errorf("invalid revocation method %q (valid: auto, ocsp, crl)", method)
	}
}
