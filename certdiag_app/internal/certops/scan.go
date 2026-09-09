package certops

import (
	"fmt"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

// TrustConfig turns on trust evaluation for a scan. Nothing is loaded unless
// Enabled is set: a plain scan must not pay for reading the OS trust store.
type TrustConfig struct {
	Enabled   bool
	BundleDir string
	JavaHome  string
	Passwords []certlib.TaggedPassword
	Readers   StoreReaders
	// AIA fetches missing issuers over the network. Off unless asked, and a
	// path that completes only because of it is labelled rather than silently
	// accepted.
	AIA        bool
	AIAOptions certlib.AIAOptions
}

type ScanOptions struct {
	Paths          []string
	Scan           certlib.ScanOptions
	Discover       bool
	AssembleChains bool
	Check          bool
	CheckOptions   certlib.CheckOptions
	Revocation     RevocationConfig
	Trust          TrustConfig
}

type ScanResult struct {
	Store    *certlib.CertStore
	RelIndex certlib.RelationIndex
	Chains   map[certlib.ItemRef][]certlib.ItemRef
	// ChainsContaining maps any certificate to the chains it belongs to, not
	// only leaves.
	ChainsContaining map[certlib.ItemRef][][]certlib.ItemRef
	CheckResult      *certlib.CheckResult
	// CheckOptions is the effective options RunChecks was called with, including
	// the resolved revocation fields. Reuse it to re-run checks (e.g. --strict)
	// without recomputing revocation, which would repeat the network work.
	CheckOptions certlib.CheckOptions
	PathErrors   []string
	ParseErrors  []string
	// Skipped is what the directory walks passed over, with reasons.
	Skipped []certlib.SkippedFile

	// Trust results, populated only when ScanOptions.Trust.Enabled was set.
	TrustIndex    *truststore.TrustIndex
	TrustStores   []truststore.StoreContents
	StorePresence StorePresence
	TrustWarnings []string
}

// Scan runs the standard file-scan pipeline: scan each path, optionally scan
// siblings, detect relations, and optionally assemble chains and run checks.
// It is the single home for scan semantics shared by the root and check
// commands. Parse errors are collected only when signature-scan is off, matching
// the caller convention.
func Scan(opts ScanOptions) *ScanResult {
	store := certlib.NewCertStore()
	res := &ScanResult{Store: store}

	for _, path := range opts.Paths {
		s, err := certlib.ScanPathWithOptions(path, opts.Scan)
		if err != nil {
			res.PathErrors = append(res.PathErrors, fmt.Sprintf("%s: %v", path, err))
			continue
		}
		res.Skipped = append(res.Skipped, s.Skipped...)
		for i := range s.Containers {
			container := &s.Containers[i]
			if len(container.ParseErrors) > 0 && !opts.Scan.UseSignatureScan {
				for _, e := range container.ParseErrors {
					res.ParseErrors = append(res.ParseErrors, fmt.Sprintf("%s: %s", container.FilePath, e))
				}
			}
			store.AddContainer(s.Containers[i])
		}
	}

	if opts.Discover {
		var filePaths []string
		for _, c := range store.Containers {
			filePaths = append(filePaths, c.FilePath)
		}
		siblings, err := certlib.ScanSiblings(filePaths, opts.Scan)
		if err == nil {
			for _, c := range siblings.Containers {
				store.AddContainer(c)
			}
		}
	}

	analyzeInto(res, store, opts)
	return res
}

// Analyze runs the analysis half of Scan on a store that was assembled some
// other way (a pcap capture, the TUI's own walk): trust, relations, chains and
// checks, with the same options and the same semantics. Paths in opts are
// ignored.
func Analyze(store *certlib.CertStore, opts ScanOptions) *ScanResult {
	res := &ScanResult{Store: store, Skipped: store.Skipped}
	analyzeInto(res, store, opts)
	return res
}

func analyzeInto(res *ScanResult, store *certlib.CertStore, opts ScanOptions) {
	if opts.Trust.Enabled {
		evaluateScanTrust(store, opts.Trust, res)
		opts.CheckOptions.TrustIndex = res.TrustIndex
	}

	if store.TotalItems() >= 2 {
		relations := certlib.DetectRelations(store)
		store.Relations = relations
		res.RelIndex = certlib.BuildRelationIndex(relations, store)
		if opts.AssembleChains {
			alts := certlib.AssembleChainAlternatives(res.RelIndex, store)
			res.Chains = certlib.FirstChains(alts)
			res.ChainsContaining = certlib.ChainsContaining(alts)
		}
	}

	if opts.Check {
		if opts.Revocation.Enabled {
			opts.CheckOptions.RevocationEnabled = true
			opts.CheckOptions.RevocationRequire = opts.Revocation.Require
			opts.CheckOptions.RevocationResults = computeRevocation(store, opts.Revocation)
		}
		res.CheckOptions = opts.CheckOptions
		res.CheckResult = certlib.RunChecks(store, res.RelIndex, opts.CheckOptions)
	}
}

// evaluateScanTrust loads the trust stores, injects the relevant anchors into
// the relation graph and resolves a verdict per certificate. It runs before
// relation detection so chains can complete up to a root the machine trusts.
func evaluateScanTrust(store *certlib.CertStore, cfg TrustConfig, res *ScanResult) {
	loaded, err := StoreLoadAll(StoreLoadAllOptions{
		Passwords: cfg.Passwords,
		JavaHome:  cfg.JavaHome,
		BundleDir: cfg.BundleDir,
		Readers:   cfg.Readers,
	})
	if err != nil {
		res.TrustWarnings = append(res.TrustWarnings, err.Error())
		return
	}

	res.TrustStores = loaded.Stores
	res.StorePresence = ComputeStorePresence(loaded.Stores)
	// loaded.Warnings carries the informational per-store notes (snapshot dates,
	// NSS scope). Those belong on the store views, not on every scan, so only
	// hard failures reach TrustWarnings.

	// AIA runs before the anchors go in, so a fetched issuer is an ordinary row
	// with relations and a verdict of its own.
	var aia *certlib.AIAResult
	if cfg.AIA {
		fetched := certlib.ChaseAIA(storeCertificates(store), cfg.AIAOptions)
		if len(fetched.Fetched) > 0 {
			aia = &fetched
		}
		if c := AIAContainer(fetched); c != nil {
			store.AddContainer(*c)
		}
		for _, f := range fetched.Failures {
			res.TrustWarnings = append(res.TrustWarnings,
				fmt.Sprintf("AIA %s: %s", f.URL, f.Reason))
		}
	}

	if anchors := AnchorContainer(store, loaded.Stores); anchors != nil {
		store.AddContainer(*anchors)
	}

	index, err := EvaluateTrust(TrustEvalOptions{Store: store, Stores: loaded.Stores, AIA: aia})
	if err != nil {
		res.TrustWarnings = append(res.TrustWarnings, err.Error())
		return
	}
	res.TrustIndex = index
}
