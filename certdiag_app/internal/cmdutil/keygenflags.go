package cmdutil

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

// KeyGenFlags is the shared --algorithm/--key-size/--curve flag group used by
// every command that generates a key (create cert/key/csr, renew --new-key).
type KeyGenFlags struct {
	Algorithm string
	KeySize   int
	Curve     string
}

// Register binds the three key-generation flags on cmd. descSuffix is inserted
// before the colon in each usage string (e.g. " for --new-key"); pass "" for
// the plain wording.
func (f *KeyGenFlags) Register(cmd *cobra.Command, descSuffix string) {
	cmd.Flags().StringVarP(&f.Algorithm, "algorithm", "a", "", "Key algorithm"+descSuffix+": rsa, ecdsa, ed25519")
	cmd.Flags().IntVarP(&f.KeySize, "key-size", "s", 0, "RSA key size"+descSuffix+": 2048, 3072, 4096")
	cmd.Flags().StringVar(&f.Curve, "curve", "", "ECDSA curve"+descSuffix+": p256, p384, p521")
}

// ApplyChanged overrides dst with each flag the user explicitly set, matching
// the CLI-overrides-template-overrides-config precedence. Algorithm and curve
// are lowercased.
func (f *KeyGenFlags) ApplyChanged(cmd *cobra.Command, dst *certlib.KeyGenOptions) {
	if cmd.Flags().Changed("algorithm") {
		dst.Algorithm = strings.ToLower(f.Algorithm)
	}
	if cmd.Flags().Changed("key-size") {
		dst.KeySize = f.KeySize
	}
	if cmd.Flags().Changed("curve") {
		dst.Curve = strings.ToLower(f.Curve)
	}
}
