package certlib

import (
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

func trustCheckStore(t *testing.T, certs ...*trustTestCert) *CertStore {
	t.Helper()
	cs := NewCertStore()
	items := make([]CertItem, 0, len(certs))
	for _, c := range certs {
		items = append(items, CertItem{
			Type:        ContentCertificate,
			Alias:       c.cn,
			Certificate: c.cert,
			RawBytes:    c.cert.Raw,
		})
	}
	cs.AddContainer(CertContainer{
		FilePath: "/scan/trust.pem",
		Format:   FormatPEM,
		Source:   SourceFile,
		Items:    items,
	})
	return cs
}

func issuesFor(result *CheckResult, checkID string) []CheckIssue {
	var out []CheckIssue
	for _, i := range result.Issues {
		if i.CheckID == checkID {
			out = append(out, i)
		}
	}
	return out
}

// TestTrustChecks_SilentWithoutTrustIndex is the property that keeps a plain
// `certdiag check` unaffected: no trust data means no trust findings, rather
// than a guess.
func TestTrustChecks_SilentWithoutTrustIndex(t *testing.T) {
	leaf := newTrustTestCert(t, "silent.test", false)
	store := trustCheckStore(t, leaf)

	result := RunChecks(store, nil, CheckOptions{})
	if got := issuesFor(result, "untrusted_chain"); len(got) != 0 {
		t.Errorf("expected no trust findings without an index, got %v", got)
	}
	if got := issuesFor(result, "distrusted_root"); len(got) != 0 {
		t.Errorf("expected no distrust findings without an index, got %v", got)
	}
}

func TestTrustChecks_UntrustedChain(t *testing.T) {
	leaf := newTrustTestCert(t, "untrusted.test", false)
	store := trustCheckStore(t, leaf)

	idx := truststore.NewTrustIndex()
	idx.Set(leaf.cert, truststore.VerdictUntrusted, nil)

	result := RunChecks(store, nil, CheckOptions{TrustIndex: idx})

	issues := issuesFor(result, "untrusted_chain")
	if len(issues) != 1 {
		t.Fatalf("expected exactly one finding, got %d", len(issues))
	}
	if issues[0].Severity != SeverityWarning {
		t.Errorf("expected a warning, got %q", issues[0].Severity)
	}
	if issues[0].Category != "trust" {
		t.Errorf("expected the trust category, got %q", issues[0].Category)
	}
	if issues[0].Details["issuer"] == nil {
		t.Error("the finding must name the issuer that is not trusted")
	}
}

func TestTrustChecks_DistrustedRoot(t *testing.T) {
	root := newTrustTestCert(t, "distrusted.test", true)
	store := trustCheckStore(t, root)

	idx := truststore.NewTrustIndex()
	idx.Set(root.cert, truststore.VerdictDenied, nil)

	result := RunChecks(store, nil, CheckOptions{TrustIndex: idx})

	issues := issuesFor(result, "distrusted_root")
	if len(issues) != 1 {
		t.Fatalf("expected exactly one finding, got %d", len(issues))
	}
	// An explicitly distrusted certificate is the strongest signal certdiag
	// can produce about trust, so it is critical rather than a warning.
	if issues[0].Severity != SeverityCritical {
		t.Errorf("expected a critical finding, got %q", issues[0].Severity)
	}
	if issues[0].Details["subject"] == nil {
		t.Error("the finding must name the distrusted subject")
	}
}

// TestTrustChecks_QuietForTrustedVerdicts: anchor, trusted and expired are not
// trust findings. Expired is already the expiry checks' job.
func TestTrustChecks_QuietForTrustedVerdicts(t *testing.T) {
	for _, verdict := range []truststore.TrustVerdict{
		truststore.VerdictAnchor,
		truststore.VerdictTrusted,
		truststore.VerdictExpired,
		truststore.VerdictUnknown,
	} {
		t.Run(string(verdict)+"_", func(t *testing.T) {
			cert := newTrustTestCert(t, "quiet.test", false)
			store := trustCheckStore(t, cert)

			idx := truststore.NewTrustIndex()
			idx.Set(cert.cert, verdict, nil)

			result := RunChecks(store, nil, CheckOptions{TrustIndex: idx})
			if got := issuesFor(result, "untrusted_chain"); len(got) != 0 {
				t.Errorf("verdict %q must not raise untrusted_chain, got %v", verdict, got)
			}
			if got := issuesFor(result, "distrusted_root"); len(got) != 0 {
				t.Errorf("verdict %q must not raise distrusted_root, got %v", verdict, got)
			}
		})
	}
}

func TestTrustChecks_Registered(t *testing.T) {
	want := map[string]CheckSeverity{
		"untrusted_chain": SeverityWarning,
		"distrusted_root": SeverityCritical,
	}
	found := map[string]bool{}
	for _, def := range AllChecks() {
		if sev, ok := want[def.ID]; ok {
			found[def.ID] = true
			if def.Severity != sev {
				t.Errorf("%s: expected severity %q, got %q", def.ID, sev, def.Severity)
			}
			if def.Category != "trust" {
				t.Errorf("%s: expected the trust category, got %q", def.ID, def.Category)
			}
			if def.Description == "" {
				t.Errorf("%s: needs a description for the check catalog", def.ID)
			}
		}
	}
	for id := range want {
		if !found[id] {
			t.Errorf("check %q is not registered", id)
		}
	}
}

func TestTrustChecks_Disableable(t *testing.T) {
	leaf := newTrustTestCert(t, "disable.test", false)
	store := trustCheckStore(t, leaf)

	idx := truststore.NewTrustIndex()
	idx.Set(leaf.cert, truststore.VerdictUntrusted, nil)

	result := RunChecks(store, nil, CheckOptions{
		TrustIndex:     idx,
		DisabledChecks: []string{"untrusted_chain"},
	})
	if got := issuesFor(result, "untrusted_chain"); len(got) != 0 {
		t.Errorf("a disabled check must not fire, got %v", got)
	}
}

// --- chain_incomplete interaction -------------------------------------------

// TestChainIncomplete_IgnoresTrustStorePeers keeps chain_incomplete a
// file-level check. An issuer that came from an injected trust store completes
// the chain for trust purposes but not for the bundle on disk, and the TRUST
// column already carries the trust answer.
func TestChainIncomplete_IgnoresTrustStorePeers(t *testing.T) {
	root := newTrustTestCA(t, "Chain Check Root")
	leaf := root.sign(t, "leaf.chaincheck.test")

	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "/scan/leaf.pem",
		Format:   FormatPEM,
		Source:   SourceFile,
		Items: []CertItem{{
			Type: ContentCertificate, Alias: "leaf", Certificate: leaf.cert, RawBytes: leaf.cert.Raw,
		}},
	})
	// The issuer arrives only through a synthesized trust store container.
	store.AddContainer(CertContainer{
		Label:         "OS Trust Store",
		Source:        SourceTrustStore,
		RelationsOnly: true,
		Items: []CertItem{{
			Type: ContentCertificate, Alias: "root", Certificate: root.cert, RawBytes: root.cert.Raw,
		}},
	})

	relIndex := BuildRelationIndex(DetectRelations(store), store)
	result := RunChecks(store, relIndex, CheckOptions{})

	if got := issuesFor(result, "chain_incomplete"); len(got) == 0 {
		t.Error("a bundle missing its root on disk is still incomplete, even when the OS supplies the issuer")
	}
}

// TestChainIncomplete_SatisfiedByScannedPeer is the control: a real scanned
// issuer does satisfy the check, so the fix above did not simply break it.
func TestChainIncomplete_SatisfiedByScannedPeer(t *testing.T) {
	root := newTrustTestCA(t, "Scanned Root")
	leaf := root.sign(t, "leaf.scanned.test")

	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "/scan/chain.pem",
		Format:   FormatPEM,
		Source:   SourceFile,
		Items: []CertItem{
			{Type: ContentCertificate, Alias: "leaf", Certificate: leaf.cert, RawBytes: leaf.cert.Raw},
			{Type: ContentCertificate, Alias: "root", Certificate: root.cert, RawBytes: root.cert.Raw},
		},
	})

	relIndex := BuildRelationIndex(DetectRelations(store), store)
	result := RunChecks(store, relIndex, CheckOptions{})

	for _, issue := range issuesFor(result, "chain_incomplete") {
		if issue.ItemRef.Alias == "leaf" {
			t.Errorf("a scanned issuer must satisfy chain_incomplete, got %q", issue.Message)
		}
	}
}

// --- relation helpers --------------------------------------------------------

func TestRefDisplayName(t *testing.T) {
	root := newTrustTestCA(t, "Display Root")

	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "/scan/some/file.pem",
		Items:    []CertItem{{Type: ContentCertificate, Alias: "a", Certificate: root.cert}},
	})
	store.AddContainer(CertContainer{
		Label: "OS Trust Store",
		Items: []CertItem{{Type: ContentCertificate, Alias: "b", Certificate: root.cert}},
	})
	store.AddContainer(CertContainer{
		Items: []CertItem{{Type: ContentCertificate, Alias: "", Certificate: root.cert}},
	})

	// A real file uses its base name.
	if got := RefDisplayName(ItemRef{ContainerIdx: 0, FilePath: "/scan/some/file.pem"}, store); got != "file.pem" {
		t.Errorf("expected the file base name, got %q", got)
	}
	// A synthesized container has no path, so the label stands in.
	if got := RefDisplayName(ItemRef{ContainerIdx: 1, Alias: "b"}, store); got != "OS Trust Store" {
		t.Errorf("expected the container label, got %q", got)
	}
	// No path and no label: the alias.
	if got := RefDisplayName(ItemRef{ContainerIdx: 2, Alias: "aliased"}, store); got != "aliased" {
		t.Errorf("expected the alias, got %q", got)
	}
	// Nothing at all: the subject, so output is never blank.
	if got := RefDisplayName(ItemRef{ContainerIdx: 2, ItemIdx: 0}, store); got != "Display Root" {
		t.Errorf("expected the subject as the last resort, got %q", got)
	}
	// Out of range must not panic.
	if got := RefDisplayName(ItemRef{ContainerIdx: 99}, store); got == "" {
		t.Error("expected a non-empty fallback for an out-of-range ref")
	}
}

func TestRefFromTrustStore(t *testing.T) {
	store := NewCertStore()
	store.AddContainer(CertContainer{FilePath: "/scan/f.pem", Source: SourceFile})
	store.AddContainer(CertContainer{Label: "OS Trust Store", Source: SourceTrustStore})

	if RefFromTrustStore(ItemRef{ContainerIdx: 0}, store) {
		t.Error("a scanned file is not a trust store peer")
	}
	if !RefFromTrustStore(ItemRef{ContainerIdx: 1}, store) {
		t.Error("expected the synthesized container to be recognised")
	}
	if RefFromTrustStore(ItemRef{ContainerIdx: 99}, store) {
		t.Error("an out-of-range ref must be false, not a panic")
	}
	if RefFromTrustStore(ItemRef{ContainerIdx: 0}, nil) {
		t.Error("a nil store must be false")
	}
}
