//go:build darwin

package truststore

import "testing"

func TestMapResultType(t *testing.T) {
	tests := []struct {
		result string
		want   TrustStatus
	}{
		{"kSecTrustSettingsResultTrustRoot", TrustTrusted},
		{"kSecTrustSettingsResultTrustAsRoot", TrustTrusted},
		{"kSecTrustSettingsResultDeny", TrustDenied},
		{"kSecTrustSettingsResultUnspecified", TrustUnset},
		{"", TrustUnset},
		{"something new from a future macOS", TrustUnset},
	}

	for _, tt := range tests {
		if got := mapResultType(tt.result); got != tt.want {
			t.Errorf("mapResultType(%q) = %q, want %q", tt.result, got, tt.want)
		}
	}
}

func TestBuildCertTrust_NoSettingsMeansTrusted(t *testing.T) {
	// A root with no explicit trust settings inherits the system default.
	got := buildCertTrust(nil, 0)
	if got.Overall != TrustTrusted {
		t.Errorf("expected Trusted with no settings, got %q", got.Overall)
	}
}

func TestBuildCertTrust_SettingsButNoPolicies(t *testing.T) {
	got := buildCertTrust(nil, 3)
	if got.Overall != TrustUnset {
		t.Errorf("expected Unset when settings exist but no policy parsed, got %q", got.Overall)
	}
}

func TestBuildCertTrust_DeniedOnly(t *testing.T) {
	// This is the case the TUI paints red: an explicitly distrusted root.
	policies := []TrustPolicy{{Purpose: "SSL", Status: TrustDenied}}
	got := buildCertTrust(policies, 1)

	if got.Overall != TrustDenied {
		t.Errorf("expected Denied, got %q", got.Overall)
	}
	if len(got.Policies) != 1 {
		t.Fatalf("expected the policy to be retained, got %d", len(got.Policies))
	}
}

func TestBuildCertTrust_TrustedOnly(t *testing.T) {
	policies := []TrustPolicy{{Purpose: "SSL", Status: TrustTrusted}}
	if got := buildCertTrust(policies, 1); got.Overall != TrustTrusted {
		t.Errorf("expected Trusted, got %q", got.Overall)
	}
}

func TestBuildCertTrust_MixedPrefersTrusted(t *testing.T) {
	// A root trusted for one purpose and denied for another is still usable,
	// so the overall status stays Trusted and the detail lives in Policies.
	policies := []TrustPolicy{
		{Purpose: "SSL", Status: TrustTrusted},
		{Purpose: "S/MIME", Status: TrustDenied},
	}
	got := buildCertTrust(policies, 2)

	if got.Overall != TrustTrusted {
		t.Errorf("expected Trusted for a mixed cert, got %q", got.Overall)
	}
	if len(got.Policies) != 2 {
		t.Errorf("expected both policies retained, got %d", len(got.Policies))
	}
}

func TestDeduplicatePolicies_DenyWins(t *testing.T) {
	policies := []TrustPolicy{
		{Purpose: "SSL", Status: TrustTrusted},
		{Purpose: "SSL", Status: TrustDenied},
	}
	got := deduplicatePolicies(policies)

	if len(got) != 1 {
		t.Fatalf("expected one SSL entry, got %d", len(got))
	}
	if got[0].Status != TrustDenied {
		t.Errorf("deny must win for the same purpose, got %q", got[0].Status)
	}
}

func TestDeduplicatePolicies_UnsetUpgradesToTrusted(t *testing.T) {
	policies := []TrustPolicy{
		{Purpose: "SSL", Status: TrustUnset},
		{Purpose: "SSL", Status: TrustTrusted},
	}
	got := deduplicatePolicies(policies)

	if len(got) != 1 || got[0].Status != TrustTrusted {
		t.Errorf("expected Unset to upgrade to Trusted, got %+v", got)
	}
}

func TestDeduplicatePolicies_PreservesOrder(t *testing.T) {
	policies := []TrustPolicy{
		{Purpose: "SSL", Status: TrustTrusted},
		{Purpose: "S/MIME", Status: TrustTrusted},
		{Purpose: "Code Signing", Status: TrustTrusted},
		{Purpose: "SSL", Status: TrustTrusted},
	}
	got := deduplicatePolicies(policies)

	want := []string{"SSL", "S/MIME", "Code Signing"}
	if len(got) != len(want) {
		t.Fatalf("expected %d policies, got %d", len(want), len(got))
	}
	for i := range want {
		if got[i].Purpose != want[i] {
			t.Errorf("position %d: expected %q, got %q", i, want[i], got[i].Purpose)
		}
	}
}

func TestNormalizePolicyName_PassesThroughKnownNames(t *testing.T) {
	if got := normalizePolicyName("SSL"); got != "SSL" {
		t.Errorf("expected a plain name to pass through, got %q", got)
	}
}

func TestNormalizePolicyName_UnknownOIDWithoutBraces(t *testing.T) {
	raw := "Unknown OID with no braces"
	if got := normalizePolicyName(raw); got != raw {
		t.Errorf("expected the raw string back, got %q", got)
	}
}
