package extensions

import "encoding/asn1"

// TLS Feature, RFC 7633. The one that matters in practice is status_request:
// a certificate that demands a stapled OCSP response and does not get one is
// meant to be rejected, which makes a missing staple critical rather than an
// observation.
const tlsFeatureStatusRequest = 5

func parseTLSFeature(der []byte) []int {
	var features []int
	if _, err := asn1.Unmarshal(der, &features); err != nil {
		return nil
	}
	return features
}

// TLSFeatureName names a feature number.
func TLSFeatureName(f int) string {
	switch f {
	case tlsFeatureStatusRequest:
		return "status_request (must-staple)"
	case 17:
		return "status_request_v2"
	default:
		return "feature " + itoa(f)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}
