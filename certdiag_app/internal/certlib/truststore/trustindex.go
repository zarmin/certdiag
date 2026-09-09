package truststore

import "crypto/x509"

// TrustIndex holds the resolved trust verdict for every certificate that was
// evaluated, keyed by the SHA-256 fingerprint used everywhere else in certdiag.
//
// It lives here rather than in certops because certlib's check engine consumes
// it, and certlib must not import the operations layer.
type TrustIndex struct {
	verdicts map[string]TrustVerdict
	anchors  map[string]*x509.Certificate
	details  map[string]TrustDetail
}

func NewTrustIndex() *TrustIndex {
	return &TrustIndex{
		verdicts: make(map[string]TrustVerdict),
		anchors:  make(map[string]*x509.Certificate),
	}
}

// TrustDetail is everything known about one certificate's trust: the verdict,
// what terminated the chain, and - when the verdict is untrusted - what would
// have to be true for it not to be.
type TrustDetail struct {
	Verdict TrustVerdict
	Anchor  *x509.Certificate
	// ViaAIA is true when the path completed only through a certificate fetched
	// over AIA. That is exactly the trust a client which does not chase AIA
	// (Java, most command-line tools) does not have.
	ViaAIA bool
	// Hint explains an untrusted verdict when the explanation is actionable,
	// for instance that the missing issuer is published at a known URL.
	Hint string
}

// SetDetail records a verdict along with its explanation.
func (t *TrustIndex) SetDetail(cert *x509.Certificate, d TrustDetail) {
	if t == nil || cert == nil {
		return
	}
	t.Set(cert, d.Verdict, d.Anchor)
	if t.details == nil {
		t.details = make(map[string]TrustDetail)
	}
	fp := CertFingerprint(cert)
	d.Verdict = t.verdicts[fp]
	t.details[fp] = d
}

// Detail returns everything known about a certificate's trust.
func (t *TrustIndex) Detail(cert *x509.Certificate) TrustDetail {
	if t == nil || cert == nil {
		return TrustDetail{}
	}
	fp := CertFingerprint(cert)
	d, ok := t.details[fp]
	if !ok {
		return TrustDetail{Verdict: t.verdicts[fp], Anchor: t.anchors[fp]}
	}
	return d
}

// Set records a verdict. The strongest verdict wins if one is already present,
// so repeated evaluation cannot downgrade a result.
func (t *TrustIndex) Set(cert *x509.Certificate, verdict TrustVerdict, anchor *x509.Certificate) {
	if t == nil || cert == nil {
		return
	}
	fp := CertFingerprint(cert)
	if existing, ok := t.verdicts[fp]; ok {
		verdict = existing.Stronger(verdict)
	}
	t.verdicts[fp] = verdict
	if anchor != nil {
		t.anchors[fp] = anchor
	}
}

// Verdict returns the recorded verdict, or VerdictUnknown when the certificate
// was never evaluated.
func (t *TrustIndex) Verdict(cert *x509.Certificate) TrustVerdict {
	if t == nil || cert == nil {
		return VerdictUnknown
	}
	return t.verdicts[CertFingerprint(cert)]
}

// AnchorFor returns the trust anchor that terminated the chain, when one was
// found.
func (t *TrustIndex) AnchorFor(cert *x509.Certificate) *x509.Certificate {
	if t == nil || cert == nil {
		return nil
	}
	return t.anchors[CertFingerprint(cert)]
}

// Len reports how many certificates were evaluated.
func (t *TrustIndex) Len() int {
	if t == nil {
		return 0
	}
	return len(t.verdicts)
}
