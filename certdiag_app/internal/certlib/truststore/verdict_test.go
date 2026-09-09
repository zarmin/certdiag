package truststore

import "testing"

func TestTrustVerdict_Precedence(t *testing.T) {
	// The order that makes DENIED beat ANCHOR, which is the whole point of
	// macOS "Never Trust": a root in the store that is explicitly distrusted
	// must never read as trusted.
	order := []TrustVerdict{
		VerdictDenied, VerdictAnchor, VerdictTrusted, VerdictExpired, VerdictUntrusted, VerdictUnknown,
	}
	for i := 1; i < len(order); i++ {
		if order[i-1].Rank() >= order[i].Rank() {
			t.Errorf("%q must outrank %q", order[i-1], order[i])
		}
	}
}

func TestTrustVerdict_Stronger(t *testing.T) {
	cases := []struct {
		a, b, want TrustVerdict
	}{
		{VerdictAnchor, VerdictDenied, VerdictDenied},
		{VerdictDenied, VerdictAnchor, VerdictDenied},
		{VerdictTrusted, VerdictAnchor, VerdictAnchor},
		{VerdictUntrusted, VerdictExpired, VerdictExpired},
		{VerdictUnknown, VerdictUntrusted, VerdictUntrusted},
		{VerdictTrusted, VerdictTrusted, VerdictTrusted},
	}
	for _, tc := range cases {
		if got := tc.a.Stronger(tc.b); got != tc.want {
			t.Errorf("%q.Stronger(%q): expected %q, got %q", tc.a, tc.b, tc.want, got)
		}
		// Order must not matter.
		if got := tc.b.Stronger(tc.a); got != tc.want {
			t.Errorf("%q.Stronger(%q): expected %q, got %q", tc.b, tc.a, tc.want, got)
		}
	}
}

func TestTrustVerdict_DisplayRoundTrip(t *testing.T) {
	for _, v := range []TrustVerdict{
		VerdictDenied, VerdictAnchor, VerdictTrusted, VerdictExpired, VerdictUntrusted,
	} {
		display := v.Display()
		if display != upper(string(v)) {
			t.Errorf("%q: expected an upper-cased display form, got %q", v, display)
		}
		if got := ParseTrustVerdict(display); got != v {
			t.Errorf("%q: display round trip gave %q", v, got)
		}
		// The canonical form must also parse, since that is what JSON carries.
		if got := ParseTrustVerdict(string(v)); got != v {
			t.Errorf("%q: canonical round trip gave %q", v, got)
		}
	}

	if VerdictUnknown.Display() != "" {
		t.Error("an unevaluated verdict must render as empty, not as a word")
	}
	for _, junk := range []string{"", "  ", "yes", "TRUSTWORTHY", "unset"} {
		if got := ParseTrustVerdict(junk); got != VerdictUnknown {
			t.Errorf("ParseTrustVerdict(%q) = %q, expected unknown", junk, got)
		}
	}
}

func upper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 'a' - 'A'
		}
	}
	return string(b)
}

func TestTrustVerdict_IsTrusted(t *testing.T) {
	trusted := map[TrustVerdict]bool{
		VerdictAnchor:    true,
		VerdictTrusted:   true,
		VerdictExpired:   false,
		VerdictUntrusted: false,
		VerdictDenied:    false,
		VerdictUnknown:   false,
	}
	for v, want := range trusted {
		if got := v.IsTrusted(); got != want {
			t.Errorf("%q.IsTrusted() = %v, expected %v", v, got, want)
		}
	}
}

// TestVerdictFromTrustStatus: a certificate present in a store is an anchor
// unless the store explicitly distrusts it. An unset trust setting (Java, the
// Linux bundle, an NSS profile with no trust row) is still membership.
func TestVerdictFromTrustStatus(t *testing.T) {
	cases := map[TrustStatus]TrustVerdict{
		TrustDenied:                   VerdictDenied,
		TrustTrusted:                  VerdictAnchor,
		TrustUnset:                    VerdictAnchor,
		TrustStatus("something else"): VerdictAnchor,
	}
	for status, want := range cases {
		if got := VerdictFromTrustStatus(status); got != want {
			t.Errorf("status %q: expected %q, got %q", status, want, got)
		}
	}
}

func TestTrustIndex(t *testing.T) {
	ca := newTestCA(t, "Index Root")
	leaf := ca.issue(t, "leaf.test", false, []string{"leaf.test"})

	idx := NewTrustIndex()
	if idx.Len() != 0 {
		t.Errorf("expected an empty index, got %d", idx.Len())
	}
	if got := idx.Verdict(ca.cert); got != VerdictUnknown {
		t.Errorf("an unevaluated certificate must read unknown, got %q", got)
	}
	if idx.AnchorFor(ca.cert) != nil {
		t.Error("expected no anchor for an unevaluated certificate")
	}

	idx.Set(ca.cert, VerdictAnchor, ca.cert)
	idx.Set(leaf.cert, VerdictTrusted, ca.cert)

	if got := idx.Verdict(ca.cert); got != VerdictAnchor {
		t.Errorf("expected anchor, got %q", got)
	}
	if got := idx.AnchorFor(leaf.cert); got == nil || got.Subject.CommonName != "Index Root" {
		t.Errorf("expected the anchor to be reported for the leaf, got %v", got)
	}
	if idx.Len() != 2 {
		t.Errorf("expected 2 entries, got %d", idx.Len())
	}
}

// TestTrustIndex_SetKeepsStrongest: repeated evaluation must never downgrade a
// result, or a second pass over the same certificate could turn DENIED into
// something weaker.
func TestTrustIndex_SetKeepsStrongest(t *testing.T) {
	ca := newTestCA(t, "Downgrade Root")

	idx := NewTrustIndex()
	idx.Set(ca.cert, VerdictDenied, nil)
	idx.Set(ca.cert, VerdictTrusted, ca.cert)
	if got := idx.Verdict(ca.cert); got != VerdictDenied {
		t.Errorf("expected denied to survive, got %q", got)
	}

	idx2 := NewTrustIndex()
	idx2.Set(ca.cert, VerdictUntrusted, nil)
	idx2.Set(ca.cert, VerdictAnchor, ca.cert)
	if got := idx2.Verdict(ca.cert); got != VerdictAnchor {
		t.Errorf("expected the stronger verdict to win, got %q", got)
	}
}

func TestTrustIndex_NilSafe(t *testing.T) {
	ca := newTestCA(t, "Nil Root")

	var idx *TrustIndex
	idx.Set(ca.cert, VerdictAnchor, ca.cert) // must not panic
	if got := idx.Verdict(ca.cert); got != VerdictUnknown {
		t.Errorf("a nil index must read unknown, got %q", got)
	}
	if idx.AnchorFor(ca.cert) != nil {
		t.Error("a nil index must report no anchor")
	}
	if idx.Len() != 0 {
		t.Error("a nil index must have length 0")
	}

	real := NewTrustIndex()
	real.Set(nil, VerdictAnchor, nil) // must not panic
	if real.Len() != 0 {
		t.Error("a nil certificate must not be recorded")
	}
	if got := real.Verdict(nil); got != VerdictUnknown {
		t.Errorf("expected unknown for a nil certificate, got %q", got)
	}
}
