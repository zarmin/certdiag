package certops

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"sort"
	"strings"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/stringutil"
)

type BundleOptions struct {
	InputPaths      []string
	InputItems      []certlib.CertItem // explicit, already-parsed items to bundle (bypasses reading InputPaths)
	InputPasswords  []certlib.TaggedPassword
	AutoAssembleDir string
	AutoChain       bool
	IncludeRoot     bool
	OutputPath      string
	OutputFormat    certlib.FileFormat
	OutputPassword  []byte
	Alias           string
	Aliases         map[int]string
	LegacyPKCS12    bool
	Overwrite       bool
}

type BundleResult struct {
	OutputPath string
	ItemCount  int
	ChainOrder []string
	Warnings   []string
}

func Bundle(opts BundleOptions) (*BundleResult, error) {
	if opts.OutputPath == "" {
		return nil, &OperationError{Op: "bundle", Message: "--output-file is required"}
	}
	if len(opts.InputItems) == 0 && len(opts.InputPaths) == 0 && opts.AutoAssembleDir == "" {
		return nil, &OperationError{Op: "bundle", Message: "provide input files or --auto-assemble directory"}
	}
	if len(opts.InputPaths) > 0 && opts.AutoAssembleDir != "" {
		return nil, &OperationError{Op: "bundle", Message: "cannot use both input files and --auto-assemble"}
	}

	var items []certlib.CertItem
	var warnings []string
	result := &BundleResult{OutputPath: opts.OutputPath}

	tagged := withEmptyPasswordFallback(opts.InputPasswords)

	if opts.AutoAssembleDir != "" {
		// Auto-assemble mode: scan directory, find leaf chain + matching key
		provider := &staticPasswordProvider{passwords: tagged}
		store, err := certlib.ScanPathWithOptions(opts.AutoAssembleDir, certlib.ScanOptions{
			Recursive:        false,
			PasswordProvider: provider,
		})
		if err != nil {
			return nil, &OperationError{Op: "bundle", Message: "scan auto-assemble directory failed", Err: err}
		}
		if store.TotalItems() == 0 {
			return nil, &OperationError{Op: "bundle", Message: "no certificate items found in directory"}
		}

		relations := certlib.DetectRelations(store)
		index := certlib.BuildRelationIndex(relations, store)
		chains := certlib.AssembleChains(index, store)

		// Find the best chain (longest)
		var bestLeaf certlib.ItemRef
		var bestChain []certlib.ItemRef
		for _, leaf := range sortedChainLeaves(chains) {
			chain := chains[leaf]
			if len(chain) > len(bestChain) {
				bestLeaf = leaf
				bestChain = chain
			}
		}

		if bestChain == nil {
			// No chain found -- collect only certificates (not keys/CSRs)
			warnings = append(warnings, "no certificate chain found, collecting all certificates")
			for _, c := range store.Containers {
				for _, item := range c.Items {
					if item.Type == certlib.ContentCertificate && item.Certificate != nil {
						if !opts.IncludeRoot && isCertSelfSigned(item.Certificate) {
							continue
						}
						items = append(items, item)
					}
				}
			}
		} else {
			// Find matching key for the leaf
			for _, rel := range index[bestLeaf] {
				if rel.Type == certlib.RelationKeyCert && rel.Direction == certlib.DirectionIncoming {
					keyItem := store.SafeItem(rel.Peer)
					if keyItem != nil && keyItem.PrivateKey != nil {
						items = append(items, *keyItem)
					}
				}
			}

			// Add chain certs in order
			for _, ref := range bestChain {
				certItem := store.SafeItem(ref)
				if certItem == nil {
					continue
				}
				if !opts.IncludeRoot && certItem.Certificate != nil && isCertSelfSigned(certItem.Certificate) {
					continue
				}
				items = append(items, *certItem)
				if certItem.Certificate != nil {
					result.ChainOrder = append(result.ChainOrder, certItem.Certificate.Subject.CommonName)
				}
			}
		}
	} else if len(opts.InputItems) > 0 {
		// Explicit-items mode: bundle exactly the items provided (e.g. the items
		// the user selected in the TUI), not whole files. This avoids pulling in
		// unselected items and keeps aliases aligned to the selected items.
		items = append(items, opts.InputItems...)
	} else {
		// Normal mode: read each input file
		for _, path := range opts.InputPaths {
			container, err := certlib.ReadFile(path, tagged)
			if err != nil {
				return nil, &OperationError{Op: "bundle", Message: fmt.Sprintf("read %s failed", path), Err: err}
			}
			if len(container.Items) == 0 {
				if len(container.ParseErrors) > 0 {
					warnings = append(warnings, fmt.Sprintf("%s: %s", path, strings.Join(container.ParseErrors, "; ")))
				} else {
					warnings = append(warnings, fmt.Sprintf("%s: no items found", path))
				}
				continue
			}
			items = append(items, container.Items...)
		}

		if len(items) == 0 {
			return nil, &OperationError{Op: "bundle", Message: "no items found in any input file"}
		}
	}

	if opts.AutoAssembleDir == "" {
		// Stamp user aliases onto items before reorder so they survive autoChain
		if len(opts.Aliases) > 0 {
			for i, alias := range opts.Aliases {
				if i < len(items) {
					items[i].Alias = alias
				}
			}
		}

		// Auto-chain: reorder certs in chain order
		if opts.AutoChain {
			items, result.ChainOrder = autoChainItems(items, opts.IncludeRoot)
		}

		// Rebuild aliases map from items after reorder
		if len(opts.Aliases) > 0 {
			rebuilt := make(map[int]string)
			for i, item := range items {
				if item.Alias != "" {
					rebuilt[i] = item.Alias
				}
			}
			opts.Aliases = rebuilt
		}
	}

	// Remove root if requested
	if !opts.IncludeRoot && !opts.AutoChain && opts.AutoAssembleDir == "" {
		items = removeRootCerts(items)
	}

	// Apply conversion matrix
	items, matrixWarnings := applyConversionMatrix(items, certlib.FormatPEM, opts.OutputFormat)
	warnings = append(warnings, matrixWarnings...)

	result.ItemCount = len(items)
	result.Warnings = warnings

	// Encode
	convOpts := ConvertOptions{
		OutputFormat:   opts.OutputFormat,
		OutputPassword: opts.OutputPassword,
		Alias:          opts.Alias,
		LegacyPKCS12:   opts.LegacyPKCS12,
	}
	if opts.OutputFormat == certlib.FormatJKS && opts.Alias == "" {
		if len(opts.Aliases) > 0 {
			convOpts.Aliases = opts.Aliases
		} else {
			convOpts.Aliases = generateAliases(items)
		}
	}
	encoded, err := encodeItems(items, convOpts)
	if err != nil {
		return nil, &OperationError{Op: "bundle", Message: "encoding failed", Err: err}
	}

	if err := certlib.WriteToFile(opts.OutputPath, encoded, opts.Overwrite); err != nil {
		return nil, &OperationError{Op: "bundle", Message: "write failed", Err: err}
	}

	return result, nil
}

func autoChainItems(items []certlib.CertItem, includeRoot bool) ([]certlib.CertItem, []string) {
	// Separate keys and certs
	var keys []certlib.CertItem
	var nonCerts []certlib.CertItem
	var certs []certlib.CertItem

	for _, item := range items {
		switch item.Type {
		case certlib.ContentCertificate:
			certs = append(certs, item)
		case certlib.ContentPrivateKey:
			keys = append(keys, item)
		default:
			nonCerts = append(nonCerts, item)
		}
	}

	if len(certs) < 2 {
		// Nothing to chain, return original order
		var result []certlib.CertItem
		result = append(result, keys...)
		result = append(result, certs...)
		result = append(result, nonCerts...)
		var chainOrder []string
		for _, c := range certs {
			if c.Certificate != nil {
				chainOrder = append(chainOrder, c.Certificate.Subject.CommonName)
			}
		}
		return result, chainOrder
	}

	// Build a CertStore for relation detection
	store := certlib.NewCertStore()
	store.AddContainer(certlib.CertContainer{
		FilePath: "bundle-input",
		Items:    certs,
	})

	relations := certlib.DetectRelations(store)
	index := certlib.BuildRelationIndex(relations, store)
	chains := certlib.AssembleChains(index, store)

	// Find the longest chain
	var bestChain []certlib.ItemRef
	for _, leaf := range sortedChainLeaves(chains) {
		chain := chains[leaf]
		if len(chain) > len(bestChain) {
			bestChain = chain
		}
	}

	var orderedCerts []certlib.CertItem
	var chainOrder []string
	usedIdx := make(map[int]bool)

	if bestChain != nil {
		for _, ref := range bestChain {
			cert := certs[ref.ItemIdx]
			if !includeRoot && cert.Certificate != nil && isCertSelfSigned(cert.Certificate) {
				usedIdx[ref.ItemIdx] = true
				continue
			}
			orderedCerts = append(orderedCerts, cert)
			usedIdx[ref.ItemIdx] = true
			if cert.Certificate != nil {
				chainOrder = append(chainOrder, cert.Certificate.Subject.CommonName)
			}
		}
	}

	// Add any certs not part of the chain
	for i, cert := range certs {
		if !usedIdx[i] {
			if !includeRoot && cert.Certificate != nil && isCertSelfSigned(cert.Certificate) {
				continue
			}
			orderedCerts = append(orderedCerts, cert)
			if cert.Certificate != nil {
				chainOrder = append(chainOrder, cert.Certificate.Subject.CommonName)
			}
		}
	}

	var result []certlib.CertItem
	result = append(result, keys...)
	result = append(result, orderedCerts...)
	result = append(result, nonCerts...)

	return result, chainOrder
}

func generateAliases(items []certlib.CertItem) map[int]string {
	aliases := make(map[int]string)
	used := make(map[string]int)

	// First pass: match keys to certs by public key fingerprint
	certCNByKey := make(map[int]string)
	certPubkeys := make(map[[32]byte]string) // pubkey hash -> CN
	for _, item := range items {
		if item.Type == certlib.ContentCertificate && item.Certificate != nil {
			der, err := x509.MarshalPKIXPublicKey(item.Certificate.PublicKey)
			if err == nil {
				certPubkeys[sha256.Sum256(der)] = item.Certificate.Subject.CommonName
			}
		}
	}
	for j, item := range items {
		if item.Type == certlib.ContentPrivateKey && item.PrivateKey != nil {
			if signer, ok := item.PrivateKey.(crypto.Signer); ok {
				der, err := x509.MarshalPKIXPublicKey(signer.Public())
				if err == nil {
					if cn, found := certPubkeys[sha256.Sum256(der)]; found {
						certCNByKey[j] = cn
					}
				}
			}
		}
	}

	for i, item := range items {
		var base string
		switch item.Type {
		case certlib.ContentCertificate:
			if item.Certificate != nil && item.Certificate.Subject.CommonName != "" {
				base = stringutil.SanitizeAlias(item.Certificate.Subject.CommonName)
			} else {
				base = fmt.Sprintf("entry-%d", i+1)
			}
		case certlib.ContentPrivateKey:
			if cn, ok := certCNByKey[i]; ok && cn != "" {
				base = "key-" + stringutil.SanitizeAlias(cn)
			} else {
				base = fmt.Sprintf("key-%d", i+1)
			}
		default:
			base = fmt.Sprintf("entry-%d", i+1)
		}

		final := base
		if count, exists := used[base]; exists {
			final = fmt.Sprintf("%s-%d", base, count+1)
			used[base] = count + 1
		} else {
			used[base] = 1
		}
		aliases[i] = final
	}
	return aliases
}

func sortedChainLeaves(chains map[certlib.ItemRef][]certlib.ItemRef) []certlib.ItemRef {
	leaves := make([]certlib.ItemRef, 0, len(chains))
	for leaf := range chains {
		leaves = append(leaves, leaf)
	}
	sort.Slice(leaves, func(i, j int) bool {
		a, b := leaves[i], leaves[j]
		if a.FilePath != b.FilePath {
			return a.FilePath < b.FilePath
		}
		if a.ContainerIdx != b.ContainerIdx {
			return a.ContainerIdx < b.ContainerIdx
		}
		return a.ItemIdx < b.ItemIdx
	})
	return leaves
}

func removeRootCerts(items []certlib.CertItem) []certlib.CertItem {
	var result []certlib.CertItem
	for _, item := range items {
		if item.Type == certlib.ContentCertificate && item.Certificate != nil && isCertSelfSigned(item.Certificate) {
			continue
		}
		result = append(result, item)
	}
	// Only filter if we'd still have certs remaining
	hasCerts := false
	for _, item := range result {
		if item.Type == certlib.ContentCertificate {
			hasCerts = true
			break
		}
	}
	if !hasCerts {
		return items // Don't remove all certs
	}
	return result
}
