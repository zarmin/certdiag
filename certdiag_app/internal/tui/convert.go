package tui

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
)

type TreeNode struct {
	ContainerIdx int
	ItemIdx      int
	Ref          certlib.ItemRef

	// Skipped rows carry a path the scan could not read and the reason; they
	// have no container and no item.
	Skipped    bool
	SkipReason string

	Filename    string
	ContentType string
	Subject     string
	Issuer      string
	Expiry      string
	ExpiryTime  time.Time
	Algo        string

	ValidFrom string
	SANs      []string
	Usage     string
	Relations []string
	Warnings  []string

	// Fingerprints holds every supported digest, already rendered in the
	// configured display format. Empty for non-certificate items.
	Fingerprints map[certlib.FingerprintAlgo]string

	// Trust store only; empty for file scans.
	Stores        []string
	StoresInAll   bool
	Trust         string
	TrustPolicies []string
	StoreKind     string

	IsBundle   bool
	IsChild    bool
	Expanded   bool
	ChildCount int
	Locked     bool

	Container *certlib.CertContainer
	Item      *certlib.CertItem

	Searchable string
}

func formatPath(path, mode string) string {
	switch mode {
	case "relative":
		if filepath.IsAbs(path) {
			cwd, err := os.Getwd()
			if err == nil {
				if rel, err := filepath.Rel(cwd, path); err == nil {
					return rel
				}
			}
		}
		return filepath.Clean(path)
	case "absolute":
		if !filepath.IsAbs(path) {
			abs, err := filepath.Abs(path)
			if err == nil {
				return abs
			}
		}
		return path
	default:
		return filepath.Base(path)
	}
}

// buildNodeFingerprints renders every digest once per node, so the column
// renderer never hashes during a draw.
func buildNodeFingerprints(cert *x509.Certificate, format certlib.FingerprintFormat) map[certlib.FingerprintAlgo]string {
	out := make(map[certlib.FingerprintAlgo]string, len(certlib.FingerprintAlgos))
	for _, algo := range certlib.FingerprintAlgos {
		out[algo] = certlib.CertFingerprint(cert, algo, format)
	}
	return out
}

// isReadOnlySource reports whether the node came from a trust store. Trust
// stores are never mutated, so every write action is suppressed for these
// nodes regardless of which root view is active.
// isReadOnlySource reports whether a row came from somewhere certdiag must not
// write back to. The guard is on the data, never on the active root view.
func (n TreeNode) isReadOnlySource() bool {
	if n.Container == nil {
		return false
	}
	switch n.Container.Source {
	case certlib.SourceTrustStore, certlib.SourceRemote:
		return true
	}
	return false
}

// containerLabel prefers an explicit human label (trust stores) over the file
// path formatting used for scanned files.
func containerLabel(c *certlib.CertContainer, pathDisplay string) string {
	if c.Label != "" {
		return c.Label
	}
	return formatPath(c.FilePath, pathDisplay)
}

func ConvertStore(store *certlib.CertStore, opts output.OutputOptions, pathDisplay string) []TreeNode {
	var nodes []TreeNode

	for ci := range store.Containers {
		c := &store.Containers[ci]
		if c.RelationsOnly {
			continue
		}

		filename := containerLabel(c, pathDisplay)
		// Trust store containers always render as a group, even when they hold
		// zero or one certificate.
		isBundle := len(c.Items) > 1 || c.Format.IsBundleFormat() || c.Source == certlib.SourceTrustStore

		if isBundle {
			header := TreeNode{
				ContainerIdx: ci,
				ItemIdx:      -1,
				Filename:     filename,
				ContentType:  string(c.Format),
				Subject:      "---",
				Issuer:       "---",
				Expiry:       "---",
				Algo:         "---",
				IsBundle:     true,
				// Trust store containers open folded: a store is a long flat
				// list of roots, so the store names are the useful overview.
				Expanded:   c.Source != certlib.SourceTrustStore,
				ChildCount: len(c.Items),
				Container:  c,
				// A bundle whose password was refused has nothing to expand; the
				// row must say so instead of looking empty (M31 M13).
				Locked: len(c.Items) == 0 && certlib.HasPasswordErrors(c),
			}
			header.Searchable = buildSearchable(header)
			nodes = append(nodes, header)

			for ii := range c.Items {
				item := &c.Items[ii]
				child := buildItemNode(ci, ii, c, item, opts, pathDisplay)
				child.IsChild = true
				nodes = append(nodes, child)
			}
		} else if len(c.Items) == 1 {
			item := &c.Items[0]
			node := buildItemNode(ci, 0, c, item, opts, pathDisplay)
			nodes = append(nodes, node)
		} else {
			locked := len(c.Items) == 0 && certlib.HasPasswordErrors(c)
			node := TreeNode{
				ContainerIdx: ci,
				ItemIdx:      -1,
				Filename:     filename,
				ContentType:  string(c.Format),
				Subject:      "---",
				Issuer:       "---",
				Expiry:       "---",
				Algo:         "---",
				Locked:       locked,
				Container:    c,
			}
			node.Searchable = buildSearchable(node)
			nodes = append(nodes, node)
		}
	}

	nodes = append(nodes, skippedNodes(store)...)
	return nodes
}

func buildItemNode(ci, ii int, c *certlib.CertContainer, item *certlib.CertItem, opts output.OutputOptions, pathDisplay string) TreeNode {
	filename := containerLabel(c, pathDisplay)
	ref := certlib.ItemRef{
		ContainerIdx: ci,
		ItemIdx:      ii,
		FilePath:     c.FilePath,
		Alias:        item.Alias,
	}
	node := TreeNode{
		ContainerIdx: ci,
		ItemIdx:      ii,
		Ref:          ref,
		Filename:     filename,
		ContentType:  output.FormatContentType(item, c.Format),
		Container:    c,
		Item:         item,
	}

	switch item.Type {
	case certlib.ContentCertificate:
		if item.Certificate != nil {
			cert := item.Certificate
			node.Subject = output.FormatSubject(cert)
			node.Issuer = output.FormatIssuer(cert)
			node.Expiry = cert.NotAfter.Format("2006-01-02")
			node.ExpiryTime = cert.NotAfter
			node.Algo = output.FormatKeyAlgo(cert.PublicKey)
			node.ValidFrom = cert.NotBefore.Format("2006-01-02")
			node.SANs = buildNodeSANs(cert)
			node.Usage = buildNodeUsage(cert)
			node.Fingerprints = buildNodeFingerprints(cert, opts.FingerprintFormat)
		} else {
			node.Subject = "---"
			node.Issuer = "---"
			node.Expiry = "---"
			node.Algo = "---"
			node.ValidFrom = "---"
		}
	case certlib.ContentPrivateKey:
		node.Subject = "---"
		node.Issuer = "---"
		node.Expiry = "---"
		node.ValidFrom = "---"
		if item.PrivateKey != nil {
			node.Algo = output.FormatPrivateKeyAlgo(item.PrivateKey)
		} else if item.Encrypted {
			node.Algo = "(encrypted)"
			node.Locked = true
		}
	case certlib.ContentCSR:
		if item.CSR != nil {
			node.Subject = item.CSR.Subject.CommonName
			if node.Subject == "" {
				node.Subject = certlib.FormatDNName(item.CSR.Subject)
			}
			node.Algo = output.FormatKeyAlgo(item.CSR.PublicKey)
		}
		node.Issuer = "---"
		node.Expiry = "---"
		node.ValidFrom = "---"
	case certlib.ContentPublicKey:
		node.Subject = "---"
		node.Issuer = "---"
		node.Expiry = "---"
		node.ValidFrom = "---"
		if item.PublicKey != nil {
			node.Algo = output.FormatKeyAlgo(item.PublicKey)
		}
	}

	node.Relations = buildNodeRelations(ref, opts, pathDisplay)
	node.Warnings = buildNodeWarnings(ref, opts)

	if item.Alias != "" {
		node.Filename = item.Alias
	}

	node.Searchable = buildSearchable(node)
	return node
}

func buildNodeSANs(cert *x509.Certificate) []string {
	return certlib.FormatSANs(cert)
}

func buildNodeUsage(cert *x509.Certificate) string {
	var parts []string
	ku := cert.KeyUsage
	if ku&x509.KeyUsageDigitalSignature != 0 {
		parts = append(parts, "DigSig")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		parts = append(parts, "NonRep")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		parts = append(parts, "KeyEnc")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		parts = append(parts, "DataEnc")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		parts = append(parts, "KeyAgr")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		parts = append(parts, "CertSign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		parts = append(parts, "CRLSign")
	}
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			parts = append(parts, "ServerAuth")
		case x509.ExtKeyUsageClientAuth:
			parts = append(parts, "ClientAuth")
		case x509.ExtKeyUsageCodeSigning:
			parts = append(parts, "CodeSign")
		case x509.ExtKeyUsageEmailProtection:
			parts = append(parts, "EmailProt")
		case x509.ExtKeyUsageTimeStamping:
			parts = append(parts, "TimeStamp")
		case x509.ExtKeyUsageOCSPSigning:
			parts = append(parts, "OCSPSign")
		}
	}
	return strings.Join(parts, ", ")
}

func buildNodeRelations(ref certlib.ItemRef, opts output.OutputOptions, pathDisplay string) []string {
	if opts.RelationIndex == nil {
		return nil
	}
	var lines []string

	if chain, ok := opts.Chains[ref]; ok {
		bold := lipgloss.NewStyle().Bold(true)
		lines = append(lines, certlib.FormatChainLabel(chain, opts.Store, func(s string) string { return bold.Render(s) }))
	}

	hasChain := len(lines) > 0
	for _, rel := range opts.RelationIndex[ref] {
		if hasChain && rel.Type == certlib.RelationSignedBy && rel.Direction == certlib.DirectionOutgoing {
			continue
		}
		peerFilename := formatPath(rel.Peer.FilePath, pathDisplay)
		switch {
		case rel.Type == certlib.RelationSignedBy && rel.Direction == certlib.DirectionOutgoing:
			lines = append(lines, "signed-by: "+peerFilename)
		case rel.Type == certlib.RelationSignedBy && rel.Direction == certlib.DirectionIncoming:
			lines = append(lines, "issuer-of: "+peerFilename)
		case rel.Type == certlib.RelationKeyCert:
			lines = append(lines, "key-pair: "+peerFilename)
		case rel.Type == certlib.RelationKeyCSR:
			lines = append(lines, "key-csr: "+peerFilename)
		case rel.Type == certlib.RelationCSRCert:
			lines = append(lines, "csr-cert: "+peerFilename)
		case rel.Type == certlib.RelationSameCert:
			lines = append(lines, "same-cert: "+peerFilename)
		}
	}
	return lines
}

func buildNodeWarnings(ref certlib.ItemRef, opts output.OutputOptions) []string {
	if opts.CheckResult == nil {
		return nil
	}
	var lines []string
	for _, issue := range opts.CheckResult.Issues {
		if issue.ItemRef == ref {
			sev := strings.ToUpper(string(issue.Severity))
			lines = append(lines, fmt.Sprintf("%s: %s", sev, issue.Message))
		}
	}
	return lines
}

func needsPassword(node TreeNode) bool {
	if node.Locked {
		return true
	}
	if node.Item != nil && node.Item.Encrypted && node.Item.PrivateKey == nil {
		return true
	}
	if node.IsBundle && node.Container != nil && certlib.HasPasswordErrors(node.Container) {
		return true
	}
	return false
}

func buildSearchable(n TreeNode) string {
	parts := []string{n.Filename, n.ContentType, n.Subject, n.Issuer, n.Algo}
	parts = append(parts, n.SANs...)
	parts = append(parts, n.Stores...)
	if n.Trust != "" {
		parts = append(parts, n.Trust)
	}
	if n.Locked {
		parts = append(parts, "locked")
	}
	return strings.ToLower(strings.Join(parts, " "))
}

// skippedNodes renders what the scan could not read as a folded group at the
// end of the tree, one row per path with the reason as its subject, so a
// missing file is never mistaken for an empty one (M31 E2).
func skippedNodes(store *certlib.CertStore) []TreeNode {
	if len(store.Skipped) == 0 {
		return nil
	}
	header := TreeNode{
		ContainerIdx: -1,
		ItemIdx:      -1,
		Filename:     fmt.Sprintf("skipped (%d)", len(store.Skipped)),
		ContentType:  "skipped",
		Subject:      "files the scan could not read",
		Issuer:       "---",
		Expiry:       "---",
		Algo:         "---",
		IsBundle:     true,
		Expanded:     false,
		ChildCount:   len(store.Skipped),
		Skipped:      true,
		SkipReason:   "expand to see the reasons",
	}
	header.Searchable = buildSearchable(header)
	nodes := []TreeNode{header}
	for _, sk := range store.Skipped {
		n := TreeNode{
			ContainerIdx: -1,
			ItemIdx:      -1,
			Filename:     filepath.Base(sk.Path),
			ContentType:  "skipped",
			Subject:      sk.Reason,
			Issuer:       "---",
			Expiry:       "---",
			Algo:         "---",
			IsChild:      true,
			Skipped:      true,
			SkipReason:   sk.Path + ": " + sk.Reason,
			// A synthetic container so file actions (delete) see the path.
			Container: &certlib.CertContainer{FilePath: sk.Path, ParseErrors: []string{sk.Reason}},
		}
		n.Searchable = strings.ToLower(sk.Path + " " + sk.Reason + " skipped")
		nodes = append(nodes, n)
	}
	return nodes
}
