//go:build darwin

package truststore

import "testing"

// TestParseTrustOutput_FlushesLastPolicy verifies the fix: a non-final cert with
// a single Deny policy is reported as TrustDenied (its policy is flushed when the
// next "Cert N:" line starts), not dropped to TrustUnset.
func TestParseTrustOutput_FlushesLastPolicy(t *testing.T) {
	output := `Cert 0: DeniedCA
   Number of trust settings : 1
   Trust Setting 0:
      Policy OID            : SSL
      Result Type           : kSecTrustSettingsResultDeny
Cert 1: TrustedCA
   Number of trust settings : 1
   Trust Setting 0:
      Policy OID            : SSL
      Result Type           : kSecTrustSettingsResultTrustRoot
`
	result := parseTrustOutput(output)

	if got := result["DeniedCA"].Overall; got != TrustDenied {
		t.Errorf("first cert: got %v, want TrustDenied (policy must be flushed on next Cert line)", got)
	}
	if got := result["TrustedCA"].Overall; got != TrustTrusted {
		t.Errorf("last cert: got %v, want TrustTrusted", got)
	}
}
