package certops

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

type StoreGrouping string

const (
	GroupByInstance StoreGrouping = "instance"
	GroupByKind     StoreGrouping = "kind"
)

func (g StoreGrouping) Next() StoreGrouping {
	if g == GroupByInstance {
		return GroupByKind
	}
	return GroupByInstance
}

func (g StoreGrouping) Label() string {
	if g == GroupByKind {
		return "kind"
	}
	return "instance"
}

// ParseStoreGrouping accepts a config or flag value, falling back to instance
// grouping for anything unrecognised.
func ParseStoreGrouping(s string) StoreGrouping {
	if strings.EqualFold(strings.TrimSpace(s), string(GroupByKind)) {
		return GroupByKind
	}
	return GroupByInstance
}

type SynthOptions struct {
	Grouping StoreGrouping
}

func kindDisplayName(t truststore.StoreType) string {
	switch t {
	case truststore.StoreTypeOS:
		return "System"
	case truststore.StoreTypeJava:
		return "Java"
	case truststore.StoreTypeOpenSSL:
		return "OpenSSL"
	case truststore.StoreTypeCustom:
		return "Custom"
	case truststore.StoreTypeNSS:
		return "Browser profiles"
	case truststore.StoreTypeBundle:
		return "Root snapshots"
	}
	return string(t)
}

func customStoreName(path string) string {
	base := filepath.Base(path)
	if base == "." || base == string(filepath.Separator) {
		return "Custom"
	}
	return base
}

func storeFormat(info truststore.StoreInfo) certlib.FileFormat {
	switch info.Type {
	case truststore.StoreTypeJava:
		return certlib.FormatJKS
	case truststore.StoreTypeOpenSSL, truststore.StoreTypeBundle:
		return certlib.FormatPEM
	case truststore.StoreTypeNSS:
		return certlib.FormatDER
	}
	if f, ok := certlib.FormatFromExtension(filepath.Ext(info.Path)); ok {
		return f
	}
	return certlib.FormatDER
}

// SynthesizeCertStore turns trust store contents into a CertStore so the whole
// existing tree/detail/check pipeline can render them. Pure: no I/O.
func SynthesizeCertStore(stores []truststore.StoreContents, opts SynthOptions) *certlib.CertStore {
	if opts.Grouping == GroupByKind {
		return synthesizeByKind(stores)
	}
	return synthesizeByInstance(stores)
}

func synthesizeByInstance(stores []truststore.StoreContents) *certlib.CertStore {
	cs := certlib.NewCertStore()
	for i := range stores {
		s := &stores[i]
		c := certlib.CertContainer{
			FilePath:    s.Info.Path,
			Label:       s.Info.Name,
			Format:      storeFormat(s.Info),
			Source:      certlib.SourceTrustStore,
			ParseErrors: append([]string{}, s.Info.Warnings...),
			Items:       buildStoreItems(s.Certificates),
		}
		cs.AddContainer(c)
	}
	return cs
}

func synthesizeByKind(stores []truststore.StoreContents) *certlib.CertStore {
	cs := certlib.NewCertStore()

	var order []truststore.StoreType
	members := make(map[truststore.StoreType][]int)
	for i := range stores {
		t := stores[i].Info.Type
		if _, seen := members[t]; !seen {
			order = append(order, t)
		}
		members[t] = append(members[t], i)
	}

	for _, t := range order {
		idxs := members[t]

		var certs []*x509.Certificate
		var warnings []string
		seen := make(map[[32]byte]bool)
		raw := 0

		for _, i := range idxs {
			s := &stores[i]
			warnings = append(warnings, s.Info.Warnings...)
			raw += len(s.Certificates)
			for _, cert := range s.Certificates {
				fp := sha256.Sum256(cert.Raw)
				if seen[fp] {
					continue
				}
				seen[fp] = true
				certs = append(certs, cert)
			}
		}

		label := kindDisplayName(t)
		path := string(t)
		if len(idxs) > 1 {
			label = fmt.Sprintf("%s (%d stores)", label, len(idxs))
			if raw != len(certs) {
				warnings = append(warnings, fmt.Sprintf("%d certificates across %d stores, %d unique", raw, len(idxs), len(certs)))
			}
		} else {
			path = stores[idxs[0]].Info.Path
		}

		cs.AddContainer(certlib.CertContainer{
			FilePath:    path,
			Label:       label,
			Format:      storeFormat(stores[idxs[0]].Info),
			Source:      certlib.SourceTrustStore,
			ParseErrors: warnings,
			Items:       buildStoreItems(certs),
		})
	}

	return cs
}

func buildStoreItems(certs []*x509.Certificate) []certlib.CertItem {
	items := make([]certlib.CertItem, 0, len(certs))
	used := make(map[string]int)

	for _, cert := range certs {
		alias := certAlias(cert)
		used[alias]++
		if n := used[alias]; n > 1 {
			alias = fmt.Sprintf("%s #%d", alias, n)
		}
		items = append(items, certlib.CertItem{
			Type:        certlib.ContentCertificate,
			Alias:       alias,
			Certificate: cert,
			RawBytes:    cert.Raw,
		})
	}
	return items
}

func certAlias(cert *x509.Certificate) string {
	if cn := strings.TrimSpace(cert.Subject.CommonName); cn != "" {
		return cn
	}
	if len(cert.Subject.Organization) > 0 {
		if o := strings.TrimSpace(cert.Subject.Organization[0]); o != "" {
			return o
		}
	}
	fp := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", fp[:8])
}

// --- cross-store presence ---

type StorePresence struct {
	Tags   []string
	byCert map[[32]byte][]int
	count  int
}

// ComputeStorePresence builds the fingerprint -> store index map behind the
// STORES column, plus the short tag for each store. Tags always name store
// instances, even when the tree is grouped by kind.
func ComputeStorePresence(stores []truststore.StoreContents) StorePresence {
	p := StorePresence{
		Tags:   storeTags(stores),
		byCert: make(map[[32]byte][]int),
		count:  len(stores),
	}
	for i := range stores {
		for _, cert := range stores[i].Certificates {
			fp := sha256.Sum256(cert.Raw)
			if idxs := p.byCert[fp]; len(idxs) > 0 && idxs[len(idxs)-1] == i {
				continue
			}
			p.byCert[fp] = append(p.byCert[fp], i)
		}
	}
	return p
}

func (p StorePresence) TagsFor(cert *x509.Certificate) []string {
	if cert == nil || len(p.byCert) == 0 {
		return nil
	}
	fp := sha256.Sum256(cert.Raw)
	idxs, ok := p.byCert[fp]
	if !ok {
		return nil
	}
	tags := make([]string, 0, len(idxs))
	for _, i := range idxs {
		if i < len(p.Tags) {
			tags = append(tags, p.Tags[i])
		}
	}
	return tags
}

// InAllStores reports whether the cert is present in every loaded store, which
// the UI renders dim because it is the uninteresting case.
func (p StorePresence) InAllStores(cert *x509.Certificate) bool {
	if p.count == 0 {
		return false
	}
	return len(p.TagsFor(cert)) == p.count
}

func (p StorePresence) StoreCount() int { return p.count }

func storeTags(stores []truststore.StoreContents) []string {
	base := make([]string, len(stores))
	for i := range stores {
		base[i] = baseStoreTag(stores[i].Info)
	}

	counts := make(map[string]int)
	for _, b := range base {
		counts[b]++
	}

	seen := make(map[string]int)
	tags := make([]string, len(stores))
	for i, b := range base {
		if counts[b] == 1 {
			tags[i] = b
			continue
		}
		tags[i] = fmt.Sprintf("%s%c", b, 'a'+seen[b])
		seen[b]++
	}
	return tags
}

func baseStoreTag(info truststore.StoreInfo) string {
	switch info.Type {
	case truststore.StoreTypeOS:
		return "OS"
	case truststore.StoreTypeOpenSSL:
		return "SSL"
	case truststore.StoreTypeJava:
		if v := javaTagVersion(info.Name); v != "" {
			return "J" + v
		}
		return "J"
	case truststore.StoreTypeCustom:
		return "F:" + customStoreName(info.Path)
	case truststore.StoreTypeNSS:
		return "FF"
	case truststore.StoreTypeBundle:
		switch info.ID {
		case truststore.BundleMozilla:
			return "MOZ"
		case truststore.BundleChrome:
			return "CHR"
		}
		return "BDL"
	}
	return strings.ToUpper(string(info.Type))
}

// javaTagVersion pulls the major version out of a store name like
// "Java 21 (Temurin)".
func javaTagVersion(name string) string {
	fields := strings.Fields(name)
	for _, f := range fields {
		f = strings.Trim(f, "()")
		if f == "" {
			continue
		}
		allDigits := true
		for _, r := range f {
			if r < '0' || r > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return f
		}
	}
	return ""
}
