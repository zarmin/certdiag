package extensions

import (
	"encoding/asn1"
	"encoding/hex"
	"time"
)

// Certificate Transparency, RFC 6962.
//
// The SCT list is not ASN.1 inside: the extension value is an OCTET STRING
// wrapping a TLS-encoded SignedCertificateTimestampList. Decoding it as ASN.1
// is the mistake to avoid.

// SCT is one Signed Certificate Timestamp.
type SCT struct {
	Version   int       `json:"version" yaml:"version"`
	LogID     string    `json:"log_id" yaml:"log_id"`
	LogName   string    `json:"log_name,omitempty" yaml:"log_name,omitempty"`
	Timestamp time.Time `json:"timestamp" yaml:"timestamp"`
}

// ctLogNames (ctlogs_gen.go) names the logs certdiag knows, from Google's
// log list. An unknown log is shown by its ID rather than hidden, since logs
// are added and retired constantly.

func parseSCTList(extValue []byte) []SCT {
	// The extension value is an OCTET STRING; its content is the TLS list.
	var payload []byte
	if _, err := asn1.Unmarshal(extValue, &payload); err != nil {
		payload = extValue
	}
	if len(payload) < 2 {
		return nil
	}

	listLen := int(payload[0])<<8 | int(payload[1])
	body := payload[2:]
	if listLen > len(body) {
		listLen = len(body)
	}
	body = body[:listLen]

	var out []SCT
	for len(body) >= 2 {
		itemLen := int(body[0])<<8 | int(body[1])
		body = body[2:]
		if itemLen > len(body) {
			return out
		}
		if sct, ok := parseSCT(body[:itemLen]); ok {
			out = append(out, sct)
		}
		body = body[itemLen:]
	}
	return out
}

// parseSCT decodes one SignedCertificateTimestamp: version(1), log id(32),
// timestamp(8), then extensions and signature which certdiag does not need.
func parseSCT(b []byte) (SCT, bool) {
	if len(b) < 1+32+8 {
		return SCT{}, false
	}
	logID := hex.EncodeToString(b[1 : 1+32])
	ms := uint64(0)
	for _, c := range b[33:41] {
		ms = ms<<8 | uint64(c)
	}
	return SCT{
		Version:   int(b[0]),
		LogID:     logID,
		LogName:   ctLogNames[logID],
		Timestamp: time.UnixMilli(int64(ms)).UTC(),
	}, true
}
