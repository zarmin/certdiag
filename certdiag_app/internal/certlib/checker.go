package certlib

import (
	"path/filepath"
	"sort"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

type CheckSeverity string

const (
	SeverityInfo     CheckSeverity = "info"
	SeverityWarning  CheckSeverity = "warning"
	SeverityCritical CheckSeverity = "critical"
)

func (s CheckSeverity) Rank() int {
	switch s {
	case SeverityInfo:
		return 0
	case SeverityWarning:
		return 1
	case SeverityCritical:
		return 2
	default:
		return -1
	}
}

type CheckIssue struct {
	Severity  CheckSeverity
	Category  string
	CheckID   string
	FilePath  string
	Filename  string
	ItemIndex int
	DN        string
	ItemRef   ItemRef
	Message   string
	Details   map[string]any
}

const (
	DefaultExpiryCriticalDays = 7
	DefaultExpiryWarnDays     = 30
	DefaultExpiryNoticeZone   = 90
)

type CheckOptions struct {
	ExpiryWarnDays     int
	ExpiryCriticalDays int
	MinSeverity        CheckSeverity
	Categories         []string
	DisabledChecks     []string

	// Revocation results are precomputed by the certops layer (network lives
	// there, never inside a check func). RevocationEnabled distinguishes "not
	// requested" from "requested but undetermined".
	RevocationEnabled bool
	RevocationRequire bool
	RevocationResults map[ItemRef]*RevocationResult

	// TrustIndex is precomputed by the certops layer when trust evaluation was
	// requested. Nil means trust was not evaluated, and the trust checks stay
	// silent rather than guessing.
	TrustIndex *truststore.TrustIndex
}

func (o CheckOptions) Defaults() CheckOptions {
	if o.ExpiryWarnDays == 0 {
		o.ExpiryWarnDays = DefaultExpiryWarnDays
	}
	if o.ExpiryCriticalDays == 0 {
		o.ExpiryCriticalDays = DefaultExpiryCriticalDays
	}
	return o
}

type CheckResult struct {
	Issues       []CheckIssue
	FilesScanned int
	Summary      CheckSummary
	Revocations  []RevocationRecord
}

type CheckSummary struct {
	Critical        int
	Warning         int
	Info            int
	FilesWithIssues int
}

// ItemKind is what a check applies to. A check declares its kinds so it can
// never fire on an item it was not written for (a CA is not a leaf, a key is
// not a certificate); the runner enforces it before the check runs.
type ItemKind string

const (
	KindLeaf ItemKind = "leaf"
	KindCA   ItemKind = "ca"
	KindKey  ItemKind = "key"
	KindCSR  ItemKind = "csr"
)

var (
	kindsCert = []ItemKind{KindLeaf, KindCA}
	kindsLeaf = []ItemKind{KindLeaf}
	kindsCA   = []ItemKind{KindCA}
	kindsKey  = []ItemKind{KindKey}
	kindsAny  = []ItemKind{KindLeaf, KindCA, KindKey, KindCSR}
)

// ItemKindOf classifies an item for AppliesTo. Unknown content is "" and
// matches no check.
func ItemKindOf(item *CertItem) ItemKind {
	switch item.Type {
	case ContentPrivateKey:
		return KindKey
	case ContentCSR:
		return KindCSR
	case ContentCertificate:
		if item.Certificate != nil && item.Certificate.IsCA {
			return KindCA
		}
		return KindLeaf
	}
	return ""
}

type CheckDefinition struct {
	ID          string
	Category    string
	Severity    CheckSeverity
	Description string
	// AppliesTo lists the item kinds the check is written for; every check
	// must declare it (see TestEveryCheckDeclaresWhatItAppliesTo).
	AppliesTo []ItemKind
	check     checkFunc
}

func (d CheckDefinition) appliesTo(kind ItemKind) bool {
	for _, k := range d.AppliesTo {
		if k == kind {
			return true
		}
	}
	return false
}

type checkFunc func(container *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, relIndex RelationIndex, store *CertStore) []CheckIssue

var allChecks []CheckDefinition

func registerCheck(def CheckDefinition) {
	allChecks = append(allChecks, def)
}

func AllChecks() []CheckDefinition {
	return allChecks
}

func RunChecks(store *CertStore, relIndex RelationIndex, opts CheckOptions) *CheckResult {
	opts = opts.Defaults()

	disabledSet := make(map[string]bool, len(opts.DisabledChecks))
	for _, id := range opts.DisabledChecks {
		disabledSet[id] = true
	}

	categorySet := make(map[string]bool, len(opts.Categories))
	for _, cat := range opts.Categories {
		categorySet[cat] = true
	}

	var enabledChecks []CheckDefinition
	for _, def := range allChecks {
		if disabledSet[def.ID] {
			continue
		}
		if len(categorySet) > 0 && !categorySet[def.Category] {
			continue
		}
		enabledChecks = append(enabledChecks, def)
	}

	result := &CheckResult{}
	filesWithIssues := make(map[string]bool)

	for ci, c := range store.Containers {
		if c.RelationsOnly {
			continue
		}
		result.FilesScanned++

		for ii, item := range c.Items {
			ref := ItemRef{
				ContainerIdx: ci,
				ItemIdx:      ii,
				FilePath:     c.FilePath,
				Alias:        item.Alias,
			}

			kind := ItemKindOf(&item)
			for _, def := range enabledChecks {
				if !def.appliesTo(kind) {
					continue
				}
				issues := def.check(&c, &item, ref, opts, relIndex, store)
				for _, issue := range issues {
					if opts.MinSeverity != "" && issue.Severity.Rank() < opts.MinSeverity.Rank() {
						continue
					}
					result.Issues = append(result.Issues, issue)
					filesWithIssues[c.FilePath] = true
				}
			}

			if opts.RevocationEnabled && item.Certificate != nil {
				if rr := opts.RevocationResults[ref]; rr != nil {
					result.Revocations = append(result.Revocations, RevocationRecord{
						FilePath:  c.FilePath,
						Filename:  filepath.Base(c.FilePath),
						ItemIndex: ref.ItemIdx,
						DN:        FormatDNName(item.Certificate.Subject),
						Result:    rr,
					})
				}
			}
		}
	}

	sort.SliceStable(result.Issues, func(i, j int) bool {
		return result.Issues[i].Severity.Rank() > result.Issues[j].Severity.Rank()
	})

	for _, issue := range result.Issues {
		switch issue.Severity {
		case SeverityCritical:
			result.Summary.Critical++
		case SeverityWarning:
			result.Summary.Warning++
		case SeverityInfo:
			result.Summary.Info++
		}
	}
	result.Summary.FilesWithIssues = len(filesWithIssues)

	return result
}

func makeIssue(sev CheckSeverity, category, checkID string, container *CertContainer, item *CertItem, ref ItemRef, msg string, details map[string]any) CheckIssue {
	dn := ""
	if item.Certificate != nil {
		dn = FormatDNName(item.Certificate.Subject)
	}
	return CheckIssue{
		Severity:  sev,
		Category:  category,
		CheckID:   checkID,
		FilePath:  container.FilePath,
		Filename:  filepath.Base(container.FilePath),
		ItemIndex: ref.ItemIdx,
		DN:        dn,
		ItemRef:   ref,
		Message:   msg,
		Details:   details,
	}
}

func EnabledCheckCount(disabledChecks []string) (total, enabled, disabled int) {
	disabledSet := make(map[string]bool, len(disabledChecks))
	for _, id := range disabledChecks {
		disabledSet[id] = true
	}
	total = len(allChecks)
	for _, def := range allChecks {
		if disabledSet[def.ID] {
			disabled++
		} else {
			enabled++
		}
	}
	return
}
