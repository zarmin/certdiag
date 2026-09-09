package truststore

import "strings"

// TrustVerdict is the single vocabulary for "does this machine trust this
// certificate", used by the TRUST column, the trust store view and structured
// output alike. Canonical values are lowercase; display upper-cases them.
type TrustVerdict string

const (
	VerdictUnknown   TrustVerdict = ""          // not evaluated
	VerdictDenied    TrustVerdict = "denied"    // explicitly distrusted
	VerdictAnchor    TrustVerdict = "anchor"    // this exact certificate is in the store
	VerdictTrusted   TrustVerdict = "trusted"   // chains to an anchor
	VerdictExpired   TrustVerdict = "expired"   // chains to an anchor, but expired
	VerdictUntrusted TrustVerdict = "untrusted" // no path to an anchor
)

// verdictRank orders verdicts by precedence: a lower rank wins when several
// apply. denied beats anchor so an explicitly distrusted root never reads as
// trusted.
var verdictRank = map[TrustVerdict]int{
	VerdictDenied:    0,
	VerdictAnchor:    1,
	VerdictTrusted:   2,
	VerdictExpired:   3,
	VerdictUntrusted: 4,
	VerdictUnknown:   5,
}

// Rank returns the precedence of a verdict; lower wins.
func (v TrustVerdict) Rank() int {
	if r, ok := verdictRank[v]; ok {
		return r
	}
	return verdictRank[VerdictUnknown]
}

// Stronger returns whichever of the two verdicts wins by precedence.
func (v TrustVerdict) Stronger(other TrustVerdict) TrustVerdict {
	if other.Rank() < v.Rank() {
		return other
	}
	return v
}

// Display returns the human form shown in columns and detail panes.
func (v TrustVerdict) Display() string {
	if v == VerdictUnknown {
		return ""
	}
	return strings.ToUpper(string(v))
}

// IsTrusted reports whether the verdict means the certificate would be
// accepted, which covers both being an anchor and chaining to one.
func (v TrustVerdict) IsTrusted() bool {
	return v == VerdictAnchor || v == VerdictTrusted
}

// ParseTrustVerdict accepts a canonical or display value.
func ParseTrustVerdict(s string) TrustVerdict {
	v := TrustVerdict(strings.ToLower(strings.TrimSpace(s)))
	if _, ok := verdictRank[v]; ok {
		return v
	}
	return VerdictUnknown
}

// VerdictFromTrustStatus maps a store's per-certificate trust setting onto the
// verdict vocabulary. A certificate present in a store is an anchor unless the
// store explicitly distrusts it.
func VerdictFromTrustStatus(s TrustStatus) TrustVerdict {
	switch s {
	case TrustDenied:
		return VerdictDenied
	case TrustTrusted, TrustUnset:
		return VerdictAnchor
	}
	return VerdictAnchor
}
