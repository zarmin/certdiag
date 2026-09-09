package cmd

import "testing"

// TestVerifyStorePasswordFlagRegistered verifies the fix: verify and store now
// register -p/--password (previously they checked Changed("password") for a flag
// that did not exist, and passing -p errored with "unknown shorthand flag").
func TestVerifyStorePasswordFlagRegistered(t *testing.T) {
	if verifyCmd.Flags().Lookup("password") == nil {
		t.Error("verify: --password not registered")
	}
	if verifyCmd.Flags().ShorthandLookup("p") == nil {
		t.Error("verify: -p not registered")
	}
	if storeCmd.Flags().Lookup("password") == nil {
		t.Error("store: --password not registered")
	}
	if storeCmd.Flags().ShorthandLookup("p") == nil {
		t.Error("store: -p not registered")
	}
}
