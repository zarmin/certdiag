package cmdutil

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

const (
	OutputHuman = "human"
	OutputJSON  = "json"
	OutputYAML  = "yaml"
	OutputList  = "list"
	OutputTable = "table"
)

func ValidateDisplayFormat(format string, valid ...string) error {
	for _, v := range valid {
		if format == v {
			return nil
		}
	}
	return fmt.Errorf("invalid --output %q (valid: %s)", format, strings.Join(valid, ", "))
}

func ParseCheckSeverity(sev string) (certlib.CheckSeverity, error) {
	switch s := certlib.CheckSeverity(strings.ToLower(sev)); s {
	case certlib.SeverityInfo, certlib.SeverityWarning, certlib.SeverityCritical:
		return s, nil
	default:
		return "", fmt.Errorf("invalid --severity %q (valid: %s, %s, %s)", sev,
			certlib.SeverityInfo, certlib.SeverityWarning, certlib.SeverityCritical)
	}
}

func ValidateKeyParams(cmd *cobra.Command, algo string, keySize int, curve string) error {
	algo = strings.ToLower(algo)

	switch algo {
	case "rsa", "ecdsa", "ed25519":
	default:
		return fmt.Errorf("invalid algorithm %q (valid: rsa, ecdsa, ed25519)", algo)
	}

	if algo == "ed25519" {
		if cmd.Flags().Changed("key-size") {
			return fmt.Errorf("--key-size is not applicable to Ed25519")
		}
		if cmd.Flags().Changed("curve") {
			return fmt.Errorf("--curve is not applicable to Ed25519")
		}
		return nil
	}

	if algo == "rsa" {
		if cmd.Flags().Changed("curve") {
			return fmt.Errorf("--curve is only valid for ECDSA, not RSA")
		}
		switch keySize {
		case 2048, 3072, 4096:
		default:
			return fmt.Errorf("invalid RSA key size %d (valid: 2048, 3072, 4096)", keySize)
		}
		return nil
	}

	// ecdsa
	if cmd.Flags().Changed("key-size") {
		return fmt.Errorf("--key-size is only valid for RSA, not ECDSA")
	}
	switch strings.ToLower(curve) {
	case "p256", "p384", "p521":
	default:
		return fmt.Errorf("invalid ECDSA curve %q (valid: p256, p384, p521)", curve)
	}

	return nil
}

func ValidateExtractType(t string) error {
	switch t {
	case "all", "certs", "keys":
		return nil
	default:
		return fmt.Errorf("invalid --type %q (valid: all, certs, keys)", t)
	}
}
