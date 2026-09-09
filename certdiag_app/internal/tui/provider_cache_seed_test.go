package tui

import (
	"bytes"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
)

type seedTestProvider []certlib.TaggedPassword

func (p seedTestProvider) PasswordsForFile(_ string) []certlib.TaggedPassword {
	return p
}

// TestNewRootModel_SeedsProviderPasswordsIntoCache verifies the fix: provider
// passwords (CLI/env/config) are seeded into the session password cache at model
// init, so form operations (which only see m.passwordCache.tagged()) can use them.
func TestNewRootModel_SeedsProviderPasswordsIntoCache(t *testing.T) {
	provider := seedTestProvider{
		{Password: []byte("cli-pw"), Source: certlib.PasswordSourceCLI},
		{Password: []byte("env-pw"), Source: certlib.PasswordSourceEnvVar},
	}
	scanOpts := certlib.ScanOptions{PasswordProvider: provider}

	m := NewRootModel("/tmp", scanOpts, false, output.OutputOptions{}, TUIOptions{})

	cached := m.passwordCache.tagged()
	for _, want := range []string{"cli-pw", "env-pw"} {
		found := false
		for _, c := range cached {
			if bytes.Equal(c.Password, []byte(want)) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("provider password %q not seeded into cache: %v", want, cached)
		}
	}
}
