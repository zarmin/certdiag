package certlib

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"path/filepath"
	"strings"
)

func DetectRelations(store *CertStore) []CertRelation {
	var relations []CertRelation
	relations = append(relations, detectSignedBy(store)...)
	relations = append(relations, detectKeyCertPairs(store)...)
	relations = append(relations, detectKeyCSRPairs(store)...)
	relations = append(relations, detectCSRCertPairs(store)...)
	relations = append(relations, detectDuplicates(store)...)
	return relations
}

func detectSignedBy(store *CertStore) []CertRelation {
	type certRef struct {
		ref  ItemRef
		cert *x509.Certificate
	}

	var certs []certRef
	for ci, c := range store.Containers {
		for ii, item := range c.Items {
			if item.Type == ContentCertificate && item.Certificate != nil {
				certs = append(certs, certRef{
					ref: ItemRef{
						ContainerIdx: ci,
						ItemIdx:      ii,
						FilePath:     c.FilePath,
						Alias:        item.Alias,
					},
					cert: item.Certificate,
				})
			}
		}
	}

	var relations []CertRelation
	for _, child := range certs {
		if IsSelfSigned(child.cert) {
			continue
		}
		for _, parent := range certs {
			if child.ref == parent.ref {
				continue
			}
			if matchesIssuer(child.cert, parent.cert) {
				relations = append(relations, CertRelation{
					Type:   RelationSignedBy,
					Source: child.ref,
					Target: parent.ref,
				})
			}
		}
	}
	return relations
}

func matchesIssuer(child, parent *x509.Certificate) bool {
	if child.Issuer.String() != parent.Subject.String() {
		return false
	}

	if len(child.AuthorityKeyId) > 0 && len(parent.SubjectKeyId) > 0 &&
		!bytes.Equal(child.AuthorityKeyId, parent.SubjectKeyId) {
		return false
	}

	return child.CheckSignatureFrom(parent) == nil
}

// IsSelfSigned reports whether a certificate names itself as issuer: subject
// equals issuer and, when both key identifiers are present, they match. It is
// deliberately not a signature check: CheckSignatureFrom rejects SHA-1 and
// MD5 signed roots as insecure, which would turn every legacy root into
// "not self-signed" across relations and checks. This is the only self-signed
// predicate in the tree (M31 R5).
func IsSelfSigned(cert *x509.Certificate) bool {
	if cert.Subject.String() != cert.Issuer.String() {
		return false
	}
	if len(cert.SubjectKeyId) > 0 && len(cert.AuthorityKeyId) > 0 {
		return bytes.Equal(cert.SubjectKeyId, cert.AuthorityKeyId)
	}
	return true
}

func detectKeyCertPairs(store *CertStore) []CertRelation {
	type pubkeyEntry struct {
		ref ItemRef
	}

	certsByPubkey := make(map[[32]byte][]pubkeyEntry)
	var keys []struct {
		ref    ItemRef
		pubkey [32]byte
	}

	for ci, c := range store.Containers {
		for ii, item := range c.Items {
			ref := ItemRef{
				ContainerIdx: ci,
				ItemIdx:      ii,
				FilePath:     c.FilePath,
				Alias:        item.Alias,
			}

			if item.Type == ContentCertificate && item.Certificate != nil {
				der, err := x509.MarshalPKIXPublicKey(item.Certificate.PublicKey)
				if err == nil {
					hash := sha256.Sum256(der)
					certsByPubkey[hash] = append(certsByPubkey[hash], pubkeyEntry{ref: ref})
				}
			}

			if item.Type == ContentPrivateKey && item.PrivateKey != nil {
				if pk, ok := item.PrivateKey.(crypto.Signer); ok {
					der, err := x509.MarshalPKIXPublicKey(pk.Public())
					if err == nil {
						hash := sha256.Sum256(der)
						keys = append(keys, struct {
							ref    ItemRef
							pubkey [32]byte
						}{ref: ref, pubkey: hash})
					}
				}
			}
		}
	}

	var relations []CertRelation
	for _, key := range keys {
		if entries, ok := certsByPubkey[key.pubkey]; ok {
			for _, entry := range entries {
				relations = append(relations, CertRelation{
					Type:   RelationKeyCert,
					Source: key.ref,
					Target: entry.ref,
				})
			}
		}
	}
	return relations
}

func detectKeyCSRPairs(store *CertStore) []CertRelation {
	type pubkeyEntry struct {
		ref ItemRef
	}

	csrsByPubkey := make(map[[32]byte][]pubkeyEntry)
	var keys []struct {
		ref    ItemRef
		pubkey [32]byte
	}

	for ci, c := range store.Containers {
		for ii, item := range c.Items {
			ref := ItemRef{
				ContainerIdx: ci,
				ItemIdx:      ii,
				FilePath:     c.FilePath,
				Alias:        item.Alias,
			}

			if item.Type == ContentCSR && item.CSR != nil {
				der, err := x509.MarshalPKIXPublicKey(item.CSR.PublicKey)
				if err == nil {
					hash := sha256.Sum256(der)
					csrsByPubkey[hash] = append(csrsByPubkey[hash], pubkeyEntry{ref: ref})
				}
			}

			if item.Type == ContentPrivateKey && item.PrivateKey != nil {
				if pk, ok := item.PrivateKey.(crypto.Signer); ok {
					der, err := x509.MarshalPKIXPublicKey(pk.Public())
					if err == nil {
						hash := sha256.Sum256(der)
						keys = append(keys, struct {
							ref    ItemRef
							pubkey [32]byte
						}{ref: ref, pubkey: hash})
					}
				}
			}
		}
	}

	var relations []CertRelation
	for _, key := range keys {
		if entries, ok := csrsByPubkey[key.pubkey]; ok {
			for _, entry := range entries {
				relations = append(relations, CertRelation{
					Type:   RelationKeyCSR,
					Source: key.ref,
					Target: entry.ref,
				})
			}
		}
	}
	return relations
}

func detectCSRCertPairs(store *CertStore) []CertRelation {
	type pubkeyEntry struct {
		ref ItemRef
	}

	certsByPubkey := make(map[[32]byte][]pubkeyEntry)
	var csrs []struct {
		ref    ItemRef
		pubkey [32]byte
	}

	for ci, c := range store.Containers {
		for ii, item := range c.Items {
			ref := ItemRef{
				ContainerIdx: ci,
				ItemIdx:      ii,
				FilePath:     c.FilePath,
				Alias:        item.Alias,
			}

			if item.Type == ContentCertificate && item.Certificate != nil {
				der, err := x509.MarshalPKIXPublicKey(item.Certificate.PublicKey)
				if err == nil {
					hash := sha256.Sum256(der)
					certsByPubkey[hash] = append(certsByPubkey[hash], pubkeyEntry{ref: ref})
				}
			}

			if item.Type == ContentCSR && item.CSR != nil {
				der, err := x509.MarshalPKIXPublicKey(item.CSR.PublicKey)
				if err == nil {
					hash := sha256.Sum256(der)
					csrs = append(csrs, struct {
						ref    ItemRef
						pubkey [32]byte
					}{ref: ref, pubkey: hash})
				}
			}
		}
	}

	var relations []CertRelation
	for _, csr := range csrs {
		if entries, ok := certsByPubkey[csr.pubkey]; ok {
			for _, entry := range entries {
				relations = append(relations, CertRelation{
					Type:   RelationCSRCert,
					Source: csr.ref,
					Target: entry.ref,
				})
			}
		}
	}
	return relations
}

func detectDuplicates(store *CertStore) []CertRelation {
	type certEntry struct {
		ref ItemRef
	}

	groups := make(map[[32]byte][]certEntry)

	for ci, c := range store.Containers {
		for ii, item := range c.Items {
			if item.Type == ContentCertificate && item.Certificate != nil {
				hash := sha256.Sum256(item.Certificate.Raw)
				ref := ItemRef{
					ContainerIdx: ci,
					ItemIdx:      ii,
					FilePath:     c.FilePath,
					Alias:        item.Alias,
				}
				groups[hash] = append(groups[hash], certEntry{ref: ref})
			}
		}
	}

	var relations []CertRelation
	for _, entries := range groups {
		if len(entries) < 2 {
			continue
		}
		for i := range len(entries) {
			for j := i + 1; j < len(entries); j++ {
				relations = append(relations, CertRelation{
					Type:   RelationSameCert,
					Source: entries[i].ref,
					Target: entries[j].ref,
				})
			}
		}
	}
	return relations
}

func BuildRelationIndex(relations []CertRelation, store *CertStore) RelationIndex {
	index := make(RelationIndex)

	for _, rel := range relations {
		switch rel.Type {
		case RelationSignedBy:
			index[rel.Source] = append(index[rel.Source], ResolvedRelation{
				Type:      RelationSignedBy,
				Direction: DirectionOutgoing,
				Peer:      rel.Target,
				Label:     formatSignedByLabel(rel.Target, rel.Source, store),
			})
			index[rel.Target] = append(index[rel.Target], ResolvedRelation{
				Type:      RelationSignedBy,
				Direction: DirectionIncoming,
				Peer:      rel.Source,
				Label:     formatIssuerOfLabel(rel.Source, rel.Target, store),
			})

		case RelationKeyCert:
			index[rel.Source] = append(index[rel.Source], ResolvedRelation{
				Type:      RelationKeyCert,
				Direction: DirectionOutgoing,
				Peer:      rel.Target,
				Label:     formatKeyCertLabel(rel.Target, rel.Source, store, "cert"),
			})
			index[rel.Target] = append(index[rel.Target], ResolvedRelation{
				Type:      RelationKeyCert,
				Direction: DirectionIncoming,
				Peer:      rel.Source,
				Label:     formatKeyCertLabel(rel.Source, rel.Target, store, "key"),
			})

		case RelationKeyCSR:
			index[rel.Source] = append(index[rel.Source], ResolvedRelation{
				Type:      RelationKeyCSR,
				Direction: DirectionOutgoing,
				Peer:      rel.Target,
				Label:     formatKeyCSRLabel(rel.Target, rel.Source, store, "csr"),
			})
			index[rel.Target] = append(index[rel.Target], ResolvedRelation{
				Type:      RelationKeyCSR,
				Direction: DirectionIncoming,
				Peer:      rel.Source,
				Label:     formatKeyCSRLabel(rel.Source, rel.Target, store, "key"),
			})

		case RelationCSRCert:
			index[rel.Source] = append(index[rel.Source], ResolvedRelation{
				Type:      RelationCSRCert,
				Direction: DirectionOutgoing,
				Peer:      rel.Target,
				Label:     formatCSRCertLabel(rel.Target, rel.Source, store, "cert"),
			})
			index[rel.Target] = append(index[rel.Target], ResolvedRelation{
				Type:      RelationCSRCert,
				Direction: DirectionIncoming,
				Peer:      rel.Source,
				Label:     formatCSRCertLabel(rel.Source, rel.Target, store, "csr"),
			})

		case RelationSameCert:
			index[rel.Source] = append(index[rel.Source], ResolvedRelation{
				Type:      RelationSameCert,
				Direction: DirectionOutgoing,
				Peer:      rel.Target,
				Label:     formatDuplicateLabel(rel.Target, rel.Source, store),
			})
			index[rel.Target] = append(index[rel.Target], ResolvedRelation{
				Type:      RelationSameCert,
				Direction: DirectionOutgoing,
				Peer:      rel.Source,
				Label:     formatDuplicateLabel(rel.Source, rel.Target, store),
			})
		}
	}

	return index
}

// AssembleChains returns one chain per leaf: the first path found upward. It is
// the compatibility view over AssembleChainAlternatives, which every caller that
// only wants "the" chain can keep using.
func AssembleChains(index RelationIndex, store *CertStore) map[ItemRef][]ItemRef {
	chains := make(map[ItemRef][]ItemRef)
	for ref, alts := range AssembleChainAlternatives(index, store) {
		if len(alts) > 0 {
			chains[ref] = alts[0]
		}
	}
	return chains
}

// FirstChains reduces the alternatives to one chain per leaf.
func FirstChains(alternatives map[ItemRef][][]ItemRef) map[ItemRef][]ItemRef {
	out := make(map[ItemRef][]ItemRef, len(alternatives))
	for ref, alts := range alternatives {
		if len(alts) > 0 {
			out[ref] = alts[0]
		}
	}
	return out
}

// AssembleChainAlternatives returns every path from each leaf up to a root.
//
// More than one is not an oddity: a CA rolling a new root publishes it both
// self-signed and cross-signed by the old one, and both copies may be in the
// scan. Following only the first found is what makes a chain line disagree with
// its own trust verdict, since x509.Verify explores all of them.
func AssembleChainAlternatives(index RelationIndex, store *CertStore) map[ItemRef][][]ItemRef {
	chains := make(map[ItemRef][][]ItemRef)

	for ci, c := range store.Containers {
		for ii, item := range c.Items {
			if item.Type != ContentCertificate || item.Certificate == nil {
				continue
			}
			if item.Certificate.IsCA || IsSelfSigned(item.Certificate) {
				continue
			}

			ref := ItemRef{
				ContainerIdx: ci,
				ItemIdx:      ii,
				FilePath:     c.FilePath,
				Alias:        item.Alias,
			}

			seen := map[[32]byte]bool{sha256.Sum256(item.Certificate.Raw): true}
			paths := walkChains(ref, []ItemRef{ref}, map[ItemRef]bool{ref: true}, seen, index, store)
			for _, p := range paths {
				if len(p) >= 2 {
					chains[ref] = append(chains[ref], p)
				}
			}
		}
	}

	return chains
}

// maxChainAlternatives caps the branching. A pathological graph could otherwise
// produce a combinatorial number of paths, and nobody reads more than a few.
const maxChainAlternatives = 8

// walkChains explores every issuer of current, returning the paths reachable
// from it. Both ref identity and certificate bytes guard against loops, so a
// duplicated certificate in two files cannot make a chain circle forever.
func walkChains(current ItemRef, path []ItemRef, visited map[ItemRef]bool, seen map[[32]byte]bool, index RelationIndex, store *CertStore) [][]ItemRef {
	var parents []ItemRef
	for _, r := range index[current] {
		if r.Type != RelationSignedBy || r.Direction != DirectionOutgoing {
			continue
		}
		peer := r.Peer
		if visited[peer] {
			continue
		}
		if peerItem := store.SafeItem(peer); peerItem != nil && peerItem.Certificate != nil {
			if seen[sha256.Sum256(peerItem.Certificate.Raw)] {
				continue
			}
		}
		parents = append(parents, peer)
	}

	if len(parents) == 0 {
		return [][]ItemRef{append([]ItemRef(nil), path...)}
	}

	var out [][]ItemRef
	for _, parent := range parents {
		if len(out) >= maxChainAlternatives {
			break
		}
		visited[parent] = true
		var hash [32]byte
		var hashed bool
		if item := store.SafeItem(parent); item != nil && item.Certificate != nil {
			hash = sha256.Sum256(item.Certificate.Raw)
			seen[hash] = true
			hashed = true
		}

		out = append(out, walkChains(parent, append(path, parent), visited, seen, index, store)...)

		delete(visited, parent)
		if hashed {
			delete(seen, hash)
		}
	}
	return out
}

// ChainsContaining inverts the chain map: for any certificate, which assembled
// chains pass through it. A leaf has its own chain; an intermediate or a root
// belongs to every chain beneath it, and had no chain line at all before.
func ChainsContaining(alternatives map[ItemRef][][]ItemRef) map[ItemRef][][]ItemRef {
	out := make(map[ItemRef][][]ItemRef)
	for _, alts := range alternatives {
		for _, chain := range alts {
			for _, member := range chain {
				out[member] = append(out[member], chain)
			}
		}
	}
	return out
}

func formatPeerRef(peer, self ItemRef, store *CertStore) string {
	peerFilename := filepath.Base(peer.FilePath)

	if peer.FilePath == self.FilePath {
		if peer.Alias != "" {
			return fmt.Sprintf("[%s] in this file", peer.Alias)
		}
		return fmt.Sprintf("#%d in this file", peer.ItemIdx+1)
	}

	if peer.Alias != "" {
		return fmt.Sprintf("%s [%s]", peerFilename, peer.Alias)
	}
	if peer.ContainerIdx >= 0 && peer.ContainerIdx < len(store.Containers) {
		container := store.Containers[peer.ContainerIdx]
		if len(container.Items) == 1 {
			return peerFilename
		}
	}
	return fmt.Sprintf("%s (#%d)", peerFilename, peer.ItemIdx+1)
}

func formatCompactRef(peer, self ItemRef, store *CertStore) string {
	if peer.FilePath == self.FilePath {
		if peer.Alias != "" {
			return fmt.Sprintf("[%s] this file", peer.Alias)
		}
		return fmt.Sprintf("#%d this file", peer.ItemIdx+1)
	}

	peerFilename := filepath.Base(peer.FilePath)
	if peer.Alias != "" {
		return fmt.Sprintf("%s [%s]", peerFilename, peer.Alias)
	}
	if peer.ContainerIdx >= 0 && peer.ContainerIdx < len(store.Containers) {
		container := store.Containers[peer.ContainerIdx]
		if len(container.Items) == 1 {
			return peerFilename
		}
	}
	return fmt.Sprintf("%s #%d", peerFilename, peer.ItemIdx+1)
}

// RefDisplayName names an item for relation output. Synthesized containers
// (trust stores, bundles) have no file path, so fall back to the container
// label and then to the certificate subject.
func RefDisplayName(ref ItemRef, store *CertStore) string {
	if ref.FilePath != "" {
		return filepath.Base(ref.FilePath)
	}
	if store != nil && ref.ContainerIdx >= 0 && ref.ContainerIdx < len(store.Containers) {
		if label := store.Containers[ref.ContainerIdx].Label; label != "" {
			return label
		}
	}
	if ref.Alias != "" {
		return ref.Alias
	}
	return certSubject(ref, store)
}

// RefFromTrustStore reports whether a relation peer lives in a synthesized
// trust store container rather than in a real scanned file.
func RefFromTrustStore(ref ItemRef, store *CertStore) bool {
	if store == nil || ref.ContainerIdx < 0 || ref.ContainerIdx >= len(store.Containers) {
		return false
	}
	return store.Containers[ref.ContainerIdx].Source == SourceTrustStore
}

func certSubject(ref ItemRef, store *CertStore) string {
	item := store.SafeItem(ref)
	if item != nil && item.Certificate != nil {
		if item.Certificate.Subject.CommonName != "" {
			return item.Certificate.Subject.CommonName
		}
		return FormatDNName(item.Certificate.Subject)
	}
	return "unknown"
}

func csrSubject(ref ItemRef, store *CertStore) string {
	item := store.SafeItem(ref)
	if item != nil && item.CSR != nil {
		if item.CSR.Subject.CommonName != "" {
			return item.CSR.Subject.CommonName
		}
		return FormatDNName(item.CSR.Subject)
	}
	return "unknown"
}

func formatSignedByLabel(parent, self ItemRef, store *CertStore) string {
	return fmt.Sprintf("signed by: %s (%s)", certSubject(parent, store), formatPeerRef(parent, self, store))
}

func formatIssuerOfLabel(child, self ItemRef, store *CertStore) string {
	return fmt.Sprintf("issuer of: %s (%s)", certSubject(child, store), formatPeerRef(child, self, store))
}

func formatKeyCertLabel(peer, self ItemRef, store *CertStore, peerType string) string {
	if peerType == "cert" {
		return fmt.Sprintf("cert: %s (%s)", certSubject(peer, store), formatPeerRef(peer, self, store))
	}
	return fmt.Sprintf("key: %s", formatPeerRef(peer, self, store))
}

func formatKeyCSRLabel(peer, self ItemRef, store *CertStore, peerType string) string {
	if peerType == "csr" {
		return fmt.Sprintf("csr: %s (%s)", csrSubject(peer, store), formatPeerRef(peer, self, store))
	}
	return fmt.Sprintf("key: %s", formatPeerRef(peer, self, store))
}

func formatCSRCertLabel(peer, self ItemRef, store *CertStore, peerType string) string {
	if peerType == "cert" {
		return fmt.Sprintf("cert: %s (%s)", certSubject(peer, store), formatPeerRef(peer, self, store))
	}
	return fmt.Sprintf("csr: %s (%s)", csrSubject(peer, store), formatPeerRef(peer, self, store))
}

func formatDuplicateLabel(peer, self ItemRef, store *CertStore) string {
	return fmt.Sprintf("duplicate: %s", formatPeerRef(peer, self, store))
}

func FormatCompactRelation(rel ResolvedRelation, self ItemRef, store *CertStore) string {
	ref := formatCompactRef(rel.Peer, self, store)
	switch {
	case rel.Type == RelationSignedBy && rel.Direction == DirectionOutgoing:
		return fmt.Sprintf("signed_by(%s)", ref)
	case rel.Type == RelationSignedBy && rel.Direction == DirectionIncoming:
		return fmt.Sprintf("issuer_of(%s)", ref)
	case rel.Type == RelationKeyCert && rel.Direction == DirectionOutgoing:
		return fmt.Sprintf("cert(%s)", ref)
	case rel.Type == RelationKeyCert && rel.Direction == DirectionIncoming:
		return fmt.Sprintf("key(%s)", ref)
	case rel.Type == RelationKeyCSR && rel.Direction == DirectionOutgoing:
		return fmt.Sprintf("csr(%s)", ref)
	case rel.Type == RelationKeyCSR && rel.Direction == DirectionIncoming:
		return fmt.Sprintf("key(%s)", ref)
	case rel.Type == RelationCSRCert && rel.Direction == DirectionOutgoing:
		return fmt.Sprintf("cert(%s)", ref)
	case rel.Type == RelationCSRCert && rel.Direction == DirectionIncoming:
		return fmt.Sprintf("csr(%s)", ref)
	case rel.Type == RelationSameCert:
		return fmt.Sprintf("dup(%s)", ref)
	}
	return ""
}

// RelationGroup holds a group of relations sharing the same display key.
type RelationGroup struct {
	Key       string // e.g. "signed_by", "issuer_of"
	Relations []ResolvedRelation
}

// GroupRelations groups relations by type+direction, returned in a fixed display order.
func GroupRelations(rels []ResolvedRelation) []RelationGroup {
	order := []string{"signed_by", "issuer_of", "key_cert_pair", "key_csr_pair", "csr_cert_pair", "same_cert"}
	grouped := map[string][]ResolvedRelation{}
	for _, rel := range rels {
		key := RelationDisplayKey(rel.Type, rel.Direction)
		grouped[key] = append(grouped[key], rel)
	}
	var result []RelationGroup
	for _, key := range order {
		if rels, ok := grouped[key]; ok {
			result = append(result, RelationGroup{Key: key, Relations: rels})
			delete(grouped, key)
		}
	}
	for key, rels := range grouped {
		result = append(result, RelationGroup{Key: key, Relations: rels})
	}
	return result
}

// compactHeader maps a RelationDisplayKey to the shorter label used for compact output.
var compactHeader = map[string]string{
	"signed_by":     "signed_by",
	"issuer_of":     "issuer_of",
	"key_cert_pair": "cert",
	"key_csr_pair":  "csr",
	"csr_cert_pair": "csr",
	"same_cert":     "dups",
}

func FormatGroupedRelations(rels []ResolvedRelation, self ItemRef, store *CertStore) string {
	var lines []string
	for _, group := range GroupRelations(rels) {
		header := compactHeader[group.Key]
		if header == "" {
			continue
		}
		if len(group.Relations) == 1 {
			lines = append(lines, FormatCompactRelation(group.Relations[0], self, store))
		} else {
			lines = append(lines, header)
			for _, rel := range group.Relations {
				lines = append(lines, "* "+formatCompactRef(rel.Peer, self, store))
			}
		}
	}
	return strings.Join(lines, "\n")
}

func FormatChainCompact(chain []ItemRef) string {
	return fmt.Sprintf("chain(%d)", len(chain))
}

func FormatChainTable(chain []ItemRef, store *CertStore) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "chain(%d):", len(chain))
	for i := len(chain) - 1; i >= 1; i-- {
		sb.WriteString("\n -> ")
		sb.WriteString(certSubject(chain[i], store))
	}
	return sb.String()
}

func FormatChainLabel(chain []ItemRef, store *CertStore, selfStyle func(string) string) string {
	var self ItemRef
	if len(chain) > 0 {
		self = chain[0]
	}
	return FormatChainLabelFor(chain, self, store, selfStyle)
}

// FormatChainLabelFor renders a chain in issuance order, highlighting the
// certificate the reader is looking at. Highlighting by reference rather than by
// position is what lets an intermediate show the chains it belongs to and still
// point at itself.
func FormatChainLabelFor(chain []ItemRef, self ItemRef, store *CertStore, selfStyle func(string) string) string {
	var sb strings.Builder
	sb.WriteString("chain: ")
	for i := len(chain) - 1; i >= 0; i-- {
		if i < len(chain)-1 {
			sb.WriteString(" -> ")
		}
		subj := certSubject(chain[i], store)
		if chain[i] == self && selfStyle != nil {
			subj = selfStyle(subj)
		}
		sb.WriteString(subj)
	}
	return sb.String()
}
