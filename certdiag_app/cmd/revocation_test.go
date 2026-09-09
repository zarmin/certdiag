package cmd

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

// newRevocationTestCmd builds a command with the revocation-method flag so the
// Changed() check in buildRevocationConfig can be exercised.
func newRevocationTestCmd(t *testing.T, method string, setMethod bool) *cobra.Command {
	t.Helper()
	c := &cobra.Command{Use: "x"}
	var m string
	c.Flags().StringVar(&m, "revocation-method", "auto", "")
	if setMethod {
		if err := c.Flags().Set("revocation-method", method); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

func TestBuildRevocationConfig(t *testing.T) {
	t.Run("crl-file defaults method to crl", func(t *testing.T) {
		c := newRevocationTestCmd(t, "auto", false)
		cfg, err := buildRevocationConfig(c, false, "auto", false, "my.crl")
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Method != certlib.RevocationMethodCRL {
			t.Errorf("method = %s, want crl", cfg.Method)
		}
		if !cfg.Enabled || cfg.CRLFile != "my.crl" {
			t.Errorf("expected enabled offline CRL, got %+v", cfg)
		}
	})

	t.Run("crl-file with explicit ocsp is rejected", func(t *testing.T) {
		c := newRevocationTestCmd(t, "ocsp", true)
		_, err := buildRevocationConfig(c, true, "ocsp", false, "my.crl")
		if err == nil {
			t.Fatal("expected an error combining --crl-file with --revocation-method ocsp")
		}
	})

	t.Run("crl-file with explicit crl is fine", func(t *testing.T) {
		c := newRevocationTestCmd(t, "crl", true)
		cfg, err := buildRevocationConfig(c, true, "crl", false, "my.crl")
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Method != certlib.RevocationMethodCRL {
			t.Errorf("method = %s, want crl", cfg.Method)
		}
	})

	t.Run("require without revocation is rejected", func(t *testing.T) {
		c := newRevocationTestCmd(t, "auto", false)
		if _, err := buildRevocationConfig(c, false, "auto", true, ""); err == nil {
			t.Fatal("expected an error for --revocation-require without --revocation")
		}
	})

	t.Run("require with revocation is fine", func(t *testing.T) {
		c := newRevocationTestCmd(t, "auto", false)
		cfg, err := buildRevocationConfig(c, true, "auto", true, "")
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.Require {
			t.Error("expected Require carried through")
		}
	})

	t.Run("invalid method rejected", func(t *testing.T) {
		c := newRevocationTestCmd(t, "auto", false)
		if _, err := buildRevocationConfig(c, true, "bogus", false, ""); err == nil {
			t.Fatal("expected an error for an invalid method")
		}
	})
}
