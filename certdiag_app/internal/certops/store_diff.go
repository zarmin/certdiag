package certops

import (
	"crypto/x509"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

// Store spec keywords for `store diff` sides. Keywords take precedence over
// bare file paths; use the file: prefix to force a path that collides.
const (
	storeSpecOS         = "os"
	storeSpecJava       = "java"
	storeSpecOpenSSL    = "openssl"
	storeSpecNSS        = "nss"
	storeSpecMozilla    = "mozilla"
	storeSpecChrome     = "chrome"
	storeSpecJavaPrefix = "java:"
	storeSpecFilePrefix = "file:"
)

// storeSpecHelp lists the accepted specs, kept next to the parser so the two
// never drift.
const storeSpecHelp = "os, java, java:<home>, openssl, nss, mozilla, chrome, file:<path>, or an existing file path"

type StoreDiffOptions struct {
	SpecA     string
	SpecB     string
	Passwords []certlib.TaggedPassword
}

// StoreDiffSide describes one resolved side of the comparison.
type StoreDiffSide struct {
	Spec      string
	Name      string
	Path      string
	CertCount int
}

// StoreDiffEntry is one certificate present on only one side.
type StoreDiffEntry struct {
	Subject     string
	Fingerprint string
	NotAfter    time.Time
}

// StoreDiffRotation is a subject present on both sides but with different
// certificates (renewed/rotated root, or a cross-sign variant).
type StoreDiffRotation struct {
	Subject       string
	FingerprintsA []string
	FingerprintsB []string
}

type StoreDiffResult struct {
	SideA     StoreDiffSide
	SideB     StoreDiffSide
	Common    int
	OnlyInA   []StoreDiffEntry
	OnlyInB   []StoreDiffEntry
	Rotated   []StoreDiffRotation
	Identical bool
	Warnings  []string
}

// StoreDiff loads two trust stores and compares their contents by SHA-256
// fingerprint. Read-only; never touches the stores.
func StoreDiff(opts StoreDiffOptions) (*StoreDiffResult, error) {
	sideA, certsA, warnA, err := resolveStoreSide(opts.SpecA, opts.Passwords)
	if err != nil {
		return nil, err
	}
	sideB, certsB, warnB, err := resolveStoreSide(opts.SpecB, opts.Passwords)
	if err != nil {
		return nil, err
	}

	result := &StoreDiffResult{SideA: sideA, SideB: sideB}
	result.Warnings = append(result.Warnings, warnA...)
	result.Warnings = append(result.Warnings, warnB...)

	fpA := fingerprintSet(certsA)
	fpB := fingerprintSet(certsB)

	var onlyA, onlyB []*x509.Certificate
	for fp, cert := range fpA {
		if _, ok := fpB[fp]; ok {
			result.Common++
		} else {
			onlyA = append(onlyA, cert)
		}
	}
	for fp, cert := range fpB {
		if _, ok := fpA[fp]; !ok {
			onlyB = append(onlyB, cert)
		}
	}

	// A subject present in both unique sets is a rotation, not a missing root.
	subjectsA := groupBySubject(onlyA)
	subjectsB := groupBySubject(onlyB)
	rotatedSubjects := make(map[string]bool)
	for subject := range subjectsA {
		if _, ok := subjectsB[subject]; ok {
			rotatedSubjects[subject] = true
			result.Rotated = append(result.Rotated, StoreDiffRotation{
				Subject:       subject,
				FingerprintsA: fingerprints(subjectsA[subject]),
				FingerprintsB: fingerprints(subjectsB[subject]),
			})
		}
	}

	for _, cert := range onlyA {
		if !rotatedSubjects[certlib.FormatDNName(cert.Subject)] {
			result.OnlyInA = append(result.OnlyInA, diffEntry(cert))
		}
	}
	for _, cert := range onlyB {
		if !rotatedSubjects[certlib.FormatDNName(cert.Subject)] {
			result.OnlyInB = append(result.OnlyInB, diffEntry(cert))
		}
	}

	sortDiffEntries(result.OnlyInA)
	sortDiffEntries(result.OnlyInB)
	sort.Slice(result.Rotated, func(i, j int) bool {
		return result.Rotated[i].Subject < result.Rotated[j].Subject
	})

	result.Identical = len(result.OnlyInA) == 0 && len(result.OnlyInB) == 0 && len(result.Rotated) == 0
	return result, nil
}

// resolveStoreSide parses a store spec and loads it into a flat, deduplicated
// certificate list. Multi-store results are unioned for the OS store (one
// logical trust domain); multiple Java stores are an error asking the user to
// pick a JAVA_HOME.
func resolveStoreSide(spec string, passwords []certlib.TaggedPassword) (StoreDiffSide, []*x509.Certificate, []string, error) {
	listOpts, err := parseStoreSpec(spec, passwords)
	if err != nil {
		return StoreDiffSide{}, nil, nil, err
	}

	listResult, err := StoreList(listOpts)
	if err != nil {
		return StoreDiffSide{}, nil, nil, fmt.Errorf("loading %q: %w", spec, err)
	}
	stores := listResult.Stores
	if len(stores) == 0 {
		return StoreDiffSide{}, nil, nil, fmt.Errorf("store %q resolved to no contents", spec)
	}

	if listOpts.StoreType == truststore.StoreTypeJava && len(stores) > 1 {
		var homes []string
		for _, s := range stores {
			homes = append(homes, s.Info.Path)
		}
		return StoreDiffSide{}, nil, nil, fmt.Errorf(
			"%q matches %d Java stores; pick one with java:<home>:\n  %s",
			spec, len(stores), strings.Join(homes, "\n  "))
	}

	side := StoreDiffSide{
		Spec: spec,
		Name: stores[0].Info.Name,
		Path: stores[0].Info.Path,
	}
	if len(stores) > 1 {
		side.Name = fmt.Sprintf("%s (+%d more)", stores[0].Info.Name, len(stores)-1)
	}

	var certs []*x509.Certificate
	seen := make(map[string]bool)
	for _, s := range stores {
		for _, cert := range s.Certificates {
			fp := truststore.CertFingerprint(cert)
			if !seen[fp] {
				seen[fp] = true
				certs = append(certs, cert)
			}
		}
	}
	side.CertCount = len(certs)
	return side, certs, listResult.Warnings, nil
}

func parseStoreSpec(spec string, passwords []certlib.TaggedPassword) (StoreListOptions, error) {
	opts := StoreListOptions{Passwords: passwords}

	switch {
	case spec == storeSpecOS:
		opts.StoreType = truststore.StoreTypeOS
	case spec == storeSpecJava:
		opts.StoreType = truststore.StoreTypeJava
	case spec == storeSpecOpenSSL:
		opts.StoreType = truststore.StoreTypeOpenSSL
	case spec == storeSpecNSS:
		opts.StoreType = truststore.StoreTypeNSS
	case spec == storeSpecMozilla:
		opts.StoreType = truststore.StoreTypeBundle
		opts.BundleID = truststore.BundleMozilla
	case spec == storeSpecChrome:
		opts.StoreType = truststore.StoreTypeBundle
		opts.BundleID = truststore.BundleChrome
	case strings.HasPrefix(spec, storeSpecJavaPrefix):
		opts.StoreType = truststore.StoreTypeJava
		opts.JavaHome = strings.TrimPrefix(spec, storeSpecJavaPrefix)
	case strings.HasPrefix(spec, storeSpecFilePrefix):
		opts.StoreType = truststore.StoreTypeCustom
		opts.FilePath = strings.TrimPrefix(spec, storeSpecFilePrefix)
	default:
		if _, err := os.Stat(spec); err != nil {
			return StoreListOptions{}, fmt.Errorf(
				"invalid store spec %q (valid: %s)", spec, storeSpecHelp)
		}
		opts.StoreType = truststore.StoreTypeCustom
		opts.FilePath = spec
	}
	return opts, nil
}

func fingerprintSet(certs []*x509.Certificate) map[string]*x509.Certificate {
	m := make(map[string]*x509.Certificate, len(certs))
	for _, cert := range certs {
		m[truststore.CertFingerprint(cert)] = cert
	}
	return m
}

func groupBySubject(certs []*x509.Certificate) map[string][]*x509.Certificate {
	m := make(map[string][]*x509.Certificate)
	for _, cert := range certs {
		subject := certlib.FormatDNName(cert.Subject)
		m[subject] = append(m[subject], cert)
	}
	return m
}

func fingerprints(certs []*x509.Certificate) []string {
	fps := make([]string, len(certs))
	for i, cert := range certs {
		fps[i] = truststore.CertFingerprint(cert)
	}
	sort.Strings(fps)
	return fps
}

func diffEntry(cert *x509.Certificate) StoreDiffEntry {
	return StoreDiffEntry{
		Subject:     certlib.FormatDNName(cert.Subject),
		Fingerprint: truststore.CertFingerprint(cert),
		NotAfter:    cert.NotAfter,
	}
}

func sortDiffEntries(entries []StoreDiffEntry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Subject != entries[j].Subject {
			return entries[i].Subject < entries[j].Subject
		}
		return entries[i].Fingerprint < entries[j].Fingerprint
	})
}
