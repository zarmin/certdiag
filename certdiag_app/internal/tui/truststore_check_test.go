package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

func issueIDs(result *certlib.CheckResult) []string {
	if result == nil {
		return nil
	}
	var ids []string
	for _, issue := range result.Issues {
		ids = append(ids, issue.CheckID)
	}
	return ids
}

func countIssue(result *certlib.CheckResult, id string) int {
	n := 0
	for _, got := range issueIDs(result) {
		if got == id {
			n++
		}
	}
	return n
}

func TestCheckOptions_DisablesMissingSANsInStoreView(t *testing.T) {
	m, _ := multiStoreModel(t)

	disabled := m.checkDisabledList()
	if !slicesContains(disabled, "missing_sans") {
		t.Errorf("expected missing_sans suppressed in the store view, got %v", disabled)
	}
}

func TestCheckOptions_UnchangedInCertLister(t *testing.T) {
	m := makeTestRootModel()

	if got := m.checkDisabledList(); len(got) != 0 {
		t.Errorf("the cert lister must not inherit store suppressions, got %v", got)
	}
}

func TestCheckOptions_MergesUserDisabled(t *testing.T) {
	m, _ := multiStoreModel(t)
	m.disabledChecks = []string{"sha1_sig", "long_validity"}

	disabled := m.checkDisabledList()

	for _, want := range []string{"sha1_sig", "long_validity", "missing_sans"} {
		if !slicesContains(disabled, want) {
			t.Errorf("expected %q in the merged list, got %v", want, disabled)
		}
	}
	if len(disabled) != 3 {
		t.Errorf("expected exactly 3 entries, got %v", disabled)
	}
}

func TestCheckOptions_NoDuplicateWhenUserAlreadyDisabled(t *testing.T) {
	m, _ := multiStoreModel(t)
	m.disabledChecks = []string{"missing_sans"}

	if got := m.checkDisabledList(); len(got) != 1 {
		t.Errorf("expected no duplicate entry, got %v", got)
	}
}

func TestCheckOptions_UserListNotMutated(t *testing.T) {
	m, _ := multiStoreModel(t)
	original := []string{"sha1_sig"}
	m.disabledChecks = original

	_ = m.checkDisabledList()

	if len(original) != 1 || original[0] != "sha1_sig" {
		t.Errorf("the user's disabled list must not be mutated, got %v", original)
	}
}

func TestCheck_NoMissingSANsNoiseFromRoots(t *testing.T) {
	// Every root CA is CN-only, so without the suppression the check view
	// would be flooded.
	m := newStoreTestModel(t,
		tsStore("macOS System Roots", truststore.StoreTypeOS, "/kc",
			tsCert(t, "Root A"), tsCert(t, "Root B"), tsCert(t, "Root C")),
	)

	if n := countIssue(m.opts.CheckResult, "missing_sans"); n != 0 {
		t.Errorf("expected no missing_sans noise, got %d issues", n)
	}
}

func TestCheck_NoLongValidityNoiseFromRoots(t *testing.T) {
	// Roots legitimately run for decades; the check skips CA certs, so this
	// must produce nothing even with a 25-year validity.
	longRoot := tsCertValid(t, "Ancient Root",
		time.Now().Add(-24*time.Hour), time.Now().Add(25*365*24*time.Hour))

	m := newStoreTestModel(t,
		tsStore("OS", truststore.StoreTypeOS, "/kc", longRoot),
	)

	if n := countIssue(m.opts.CheckResult, "long_validity"); n != 0 {
		t.Errorf("expected no long_validity noise for CA roots, got %d", n)
	}
}

func TestCheck_NoChainIncompleteNoiseFromSelfSignedRoots(t *testing.T) {
	m := newStoreTestModel(t,
		tsStore("OS", truststore.StoreTypeOS, "/kc", tsCert(t, "Root A"), tsCert(t, "Root B")),
	)

	if n := countIssue(m.opts.CheckResult, "chain_incomplete"); n != 0 {
		t.Errorf("self-signed roots must not trip chain_incomplete, got %d", n)
	}
}

func TestCheck_ExpiredRootDetected(t *testing.T) {
	expired := tsCertValid(t, "Expired Root",
		time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))

	m := newStoreTestModel(t,
		tsStore("Java 21", truststore.StoreTypeJava, "/jdk21", expired, tsCert(t, "Good Root")),
	)

	if n := countIssue(m.opts.CheckResult, "expired"); n != 1 {
		t.Errorf("expected the expired root flagged once, got %d (%v)",
			n, issueIDs(m.opts.CheckResult))
	}
}

func TestCheck_CoversAllLoadedStores(t *testing.T) {
	expiredA := tsCertValid(t, "Expired In OS",
		time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	expiredB := tsCertValid(t, "Expired In Java",
		time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))

	m := newStoreTestModel(t,
		tsStore("macOS System Roots", truststore.StoreTypeOS, "/kc", expiredA),
		tsStore("Java 21", truststore.StoreTypeJava, "/jdk21", expiredB),
	)

	// Checks span every store, not just the group under the cursor.
	if n := countIssue(m.opts.CheckResult, "expired"); n != 2 {
		t.Errorf("expected both stores checked, got %d expired issues", n)
	}
}

func TestCheck_IssuesAttributableToStore(t *testing.T) {
	expired := tsCertValid(t, "Expired Root",
		time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))

	m := newStoreTestModel(t,
		tsStore("Java 21 (Temurin)", truststore.StoreTypeJava, "/jdk21/cacerts", expired),
	)

	result := m.opts.CheckResult
	if result == nil || len(result.Issues) == 0 {
		t.Fatal("expected at least one issue")
	}

	var found bool
	for _, issue := range result.Issues {
		if issue.CheckID != "expired" {
			continue
		}
		found = true
		// The issue must carry enough to name the store it came from.
		if issue.FilePath != "/jdk21/cacerts" {
			t.Errorf("expected the store path on the issue, got %q", issue.FilePath)
		}
	}
	if !found {
		t.Errorf("expected an expired issue, got %v", issueIDs(result))
	}
}

func TestOpenCheckView_UsesStoreDisabledList(t *testing.T) {
	m := newStoreTestModel(t,
		tsStore("OS", truststore.StoreTypeOS, "/kc", tsCert(t, "Root A"), tsCert(t, "Root B")),
	)
	m.openCheckView()

	if m.state != stateCheckView {
		t.Fatalf("expected the check view, got %v", m.state)
	}
	for _, issue := range m.checkView.allIssues {
		if issue.CheckID == "missing_sans" {
			t.Error("the check view must honour the store-mode suppression")
		}
	}
}

func TestCheck_RelationsDetectedAcrossStores(t *testing.T) {
	// The same root in two stores is a duplicate, which the relation engine
	// should see once the containers are synthesized.
	shared := tsCert(t, "Shared Root")
	m := newStoreTestModel(t,
		tsStore("macOS System Roots", truststore.StoreTypeOS, "/kc", shared),
		tsStore("Java 21", truststore.StoreTypeJava, "/jdk21", shared),
	)

	var sameCert int
	for _, rel := range m.store.Relations {
		if rel.Type == certlib.RelationSameCert {
			sameCert++
		}
	}
	if sameCert == 0 {
		t.Error("expected a same_cert relation between the two stores")
	}
}

func TestCheck_StoreWarningsInGroupDetail(t *testing.T) {
	locked := truststore.StoreContents{
		Info: truststore.StoreInfo{
			Type:     truststore.StoreTypeJava,
			Name:     "Java 17 (Corretto)",
			Path:     "/jdk17/cacerts",
			Warnings: []string{"jssecacerts detected at /jdk17/lib/security/jssecacerts"},
		},
	}
	m := newStoreTestModel(t, locked)

	header := nodeByFilename(m, "Java 17 (Corretto)")
	if header == nil {
		t.Fatal("expected the group header")
	}
	joined := strings.Join(header.Container.ParseErrors, " ")
	if !strings.Contains(joined, "jssecacerts") {
		t.Errorf("expected the store warning on the group, got %v", header.Container.ParseErrors)
	}
}
