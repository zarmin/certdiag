package extensions

import "encoding/asn1"

// Qualified Certificate statements, RFC 3739 with the eIDAS statement OIDs
// from ETSI EN 319 412-5. These are what makes a certificate "qualified" in
// the EU legal sense, and they are invisible without a parser.

// QCStatement is one statement, named where certdiag knows it.
type QCStatement struct {
	OID  string `json:"oid" yaml:"oid"`
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
}

var qcStatementNames = map[string]string{
	"0.4.0.1862.1.1":     "QcCompliance (qualified under eIDAS)",
	"0.4.0.1862.1.2":     "QcLimitValue (transaction value limit)",
	"0.4.0.1862.1.3":     "QcRetentionPeriod",
	"0.4.0.1862.1.4":     "QcSSCD (key held in a qualified device)",
	"0.4.0.1862.1.5":     "QcPDS (PKI disclosure statements)",
	"0.4.0.1862.1.6":     "QcType",
	"0.4.0.1862.1.7":     "QcCClegislation",
	"0.4.0.19495.2":      "PSD2 QcStatement (payment services roles)",
	"1.3.6.1.5.5.7.11.2": "QcSemanticsId (legal person)",
	"0.4.0.194121.1.1":   "QcType: eSign",
	"0.4.0.194121.1.2":   "QcType: eSeal",
	"0.4.0.194121.1.3":   "QcType: web authentication",
}

func parseQCStatements(der []byte) []QCStatement {
	var raw []asn1.RawValue
	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		return nil
	}

	var out []QCStatement
	for _, item := range raw {
		var stmt struct {
			ID   asn1.ObjectIdentifier
			Info asn1.RawValue `asn1:"optional"`
		}
		if _, err := asn1.Unmarshal(item.FullBytes, &stmt); err != nil {
			continue
		}
		id := stmt.ID.String()
		out = append(out, QCStatement{OID: id, Name: qcStatementNames[id]})
	}
	return out
}

// QCStatementName names a statement OID, empty when unknown.
func QCStatementName(oid string) string { return qcStatementNames[oid] }
