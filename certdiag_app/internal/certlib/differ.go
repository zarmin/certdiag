package certlib

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

type DiffStatus string

const (
	DiffSame    DiffStatus = "same"
	DiffChanged DiffStatus = "changed"
	DiffAdded   DiffStatus = "added"
	DiffRemoved DiffStatus = "removed"
)

type DiffSource struct {
	FilePath  string
	ItemIndex int
	Alias     string
	Format    string
}

type DiffSummary struct {
	Same    int
	Changed int
	Added   int
	Removed int
}

type DiffField struct {
	Name     string      `json:"name"`
	Category string      `json:"category"`
	Left     string      `json:"left"`
	Right    string      `json:"right"`
	Status   DiffStatus  `json:"status"`
	Children []DiffField `json:"children,omitempty"`
}

type DiffResult struct {
	Left    DiffSource
	Right   DiffSource
	Fields  []DiffField
	Summary DiffSummary
}

func (r *DiffResult) Identical() bool {
	return r.Summary.Changed == 0 && r.Summary.Added == 0 && r.Summary.Removed == 0
}

func CompareCertificates(left, right *x509.Certificate, detailed bool) DiffResult {
	if left == nil || right == nil {
		return DiffResult{
			Fields:  []DiffField{{Name: "error", Category: "identity", Left: "nil", Right: "nil", Status: DiffChanged}},
			Summary: DiffSummary{Changed: 1},
		}
	}

	var fields []DiffField

	fields = append(fields, compareString("Subject", "identity",
		FormatDNName(left.Subject), FormatDNName(right.Subject)))

	fields = append(fields, compareString("Issuer", "identity",
		FormatDNName(left.Issuer), FormatDNName(right.Issuer)))

	fields = append(fields, compareBool("Self-signed", "identity",
		IsSelfSigned(left), IsSelfSigned(right)))

	fields = append(fields, compareBool("CA", "identity",
		left.IsCA, right.IsCA))

	fields = append(fields, compareTime("Not Before", "validity",
		left.NotBefore, right.NotBefore))

	fields = append(fields, compareTime("Not After", "validity",
		left.NotAfter, right.NotAfter))

	fields = append(fields, compareString("Serial", "identity",
		FormatSerial(left.SerialNumber), FormatSerial(right.SerialNumber)))

	fields = append(fields, compareString("Algorithm", "algorithm",
		formatPubKeyAlgo(left), formatPubKeyAlgo(right)))

	fields = append(fields, compareString("Signature Algorithm", "algorithm",
		left.SignatureAlgorithm.String(), right.SignatureAlgorithm.String()))

	fields = append(fields, compareStringSet("SANs", "extensions",
		FormatSANs(left), FormatSANs(right)))

	fields = append(fields, compareStringSet("Issuer Alt Names", "extensions",
		ParseIssuerAltNames(left), ParseIssuerAltNames(right)))

	fields = append(fields, compareStringSet("Key Usage", "extensions",
		FormatKeyUsage(left.KeyUsage), FormatKeyUsage(right.KeyUsage)))

	fields = append(fields, compareStringSet("Ext Key Usage", "extensions",
		FormatExtKeyUsage(left.ExtKeyUsage), FormatExtKeyUsage(right.ExtKeyUsage)))

	if detailed {
		fields = append(fields, compareString("Version", "identity",
			fmt.Sprintf("%d", left.Version), fmt.Sprintf("%d", right.Version)))

		fields = append(fields, compareString("Subject Key ID", "fingerprint",
			formatHexBytes(left.SubjectKeyId), formatHexBytes(right.SubjectKeyId)))

		fields = append(fields, compareString("Authority Key ID", "fingerprint",
			formatHexBytes(left.AuthorityKeyId), formatHexBytes(right.AuthorityKeyId)))

		// Canonical lowercase hex; diffview re-formats these rows for display.
		for _, algo := range FingerprintAlgos {
			fields = append(fields, compareString(algo.Label(), "fingerprint",
				CertFingerprint(left, algo, FingerprintHex),
				CertFingerprint(right, algo, FingerprintHex)))
		}

		fields = append(fields, compareString("Path Length", "extensions",
			formatPathLength(left), formatPathLength(right)))

		fields = append(fields, compareStringSet("CRL Distribution Points", "extensions",
			left.CRLDistributionPoints, right.CRLDistributionPoints))

		var leftAIA, rightAIA []string
		leftAIA = append(leftAIA, left.OCSPServer...)
		leftAIA = append(leftAIA, left.IssuingCertificateURL...)
		rightAIA = append(rightAIA, right.OCSPServer...)
		rightAIA = append(rightAIA, right.IssuingCertificateURL...)
		fields = append(fields, compareStringSet("Authority Info Access", "extensions",
			leftAIA, rightAIA))
	}

	var summary DiffSummary
	for _, f := range fields {
		switch f.Status {
		case DiffSame:
			summary.Same++
		case DiffChanged:
			summary.Changed++
		case DiffAdded:
			summary.Added++
		case DiffRemoved:
			summary.Removed++
		}
	}

	return DiffResult{
		Fields:  fields,
		Summary: summary,
	}
}

func compareString(name, category, left, right string) DiffField {
	status := DiffSame
	if left != right {
		status = DiffChanged
	}
	return DiffField{
		Name:     name,
		Category: category,
		Left:     left,
		Right:    right,
		Status:   status,
	}
}

func compareBool(name, category string, left, right bool) DiffField {
	return compareString(name, category, fmt.Sprintf("%v", left), fmt.Sprintf("%v", right))
}

func compareTime(name, category string, left, right time.Time) DiffField {
	const layout = "2006-01-02 15:04:05 UTC"
	return compareString(name, category, left.UTC().Format(layout), right.UTC().Format(layout))
}

func compareStringSet(name, category string, left, right []string) DiffField {
	leftSet := make(map[string]bool, len(left))
	for _, s := range left {
		leftSet[s] = true
	}
	rightSet := make(map[string]bool, len(right))
	for _, s := range right {
		rightSet[s] = true
	}

	var children []DiffField
	seen := make(map[string]bool)

	for _, s := range left {
		if seen[s] {
			continue
		}
		seen[s] = true
		if rightSet[s] {
			children = append(children, DiffField{Name: s, Status: DiffSame})
		} else {
			children = append(children, DiffField{Name: s, Status: DiffRemoved})
		}
	}
	for _, s := range right {
		if seen[s] {
			continue
		}
		seen[s] = true
		children = append(children, DiffField{Name: s, Status: DiffAdded})
	}

	parentStatus := DiffSame
	for _, c := range children {
		if c.Status != DiffSame {
			parentStatus = DiffChanged
			break
		}
	}

	leftJoined := strings.Join(left, ", ")
	rightJoined := strings.Join(right, ", ")

	return DiffField{
		Name:     name,
		Category: category,
		Left:     leftJoined,
		Right:    rightJoined,
		Status:   parentStatus,
		Children: children,
	}
}

func formatPubKeyAlgo(cert *x509.Certificate) string {
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA-%s", k.Curve.Params().Name)
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return cert.PublicKeyAlgorithm.String()
	}
}

func formatHexBytes(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return fmt.Sprintf("%x", b)
}

func formatPathLength(cert *x509.Certificate) string {
	if !cert.IsCA {
		return "n/a"
	}
	if cert.MaxPathLen <= 0 && !cert.MaxPathLenZero {
		return "unlimited"
	}
	return fmt.Sprintf("%d", cert.MaxPathLen)
}
