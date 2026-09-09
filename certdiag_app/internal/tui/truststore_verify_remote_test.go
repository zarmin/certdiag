package tui

import (
	"crypto/x509"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
)

// Verifying a live endpoint against a chosen trust store: the "would this work
// in Java" question, asked from the store the user is already looking at.

func storeVerifyModel(t *testing.T, roots ...*x509.Certificate) RootModel {
	t.Helper()
	m := newStoreTestModel(t, tsStore("OS Trust Store", truststore.StoreTypeOS, "/os", roots...))
	m.width, m.height = 120, 40
	m.tree.cursor = 0
	return m
}

func TestStoreVerify_SubmenuOpens(t *testing.T) {
	m := storeVerifyModel(t, tsCert(t, "Root A"))

	handled, model, _ := m.trustStoreKey(runes("V"), stateTree)
	if !handled {
		t.Fatal("V must be handled in the trust store view")
	}
	m = model.(RootModel)

	if m.state != stateVerifyPick {
		t.Fatalf("V must ask what to verify, got state %d", m.state)
	}
	if len(m.menu.items) != 2 {
		t.Fatalf("expected a file and a remote entry, got %d", len(m.menu.items))
	}
	if m.menu.items[0].key != "f" || m.menu.items[1].key != "r" {
		t.Errorf("unexpected entries: %+v", m.menu.items)
	}
}

// TestStoreVerify_RemoteOpensSharedForm: the same form the Cert Lister uses, so
// proxy, STARTTLS, SNI, IP family, timeout and the target history all carry
// over rather than being reimplemented.
func TestStoreVerify_RemoteOpensSharedForm(t *testing.T) {
	root := tsCert(t, "Root A")
	m := storeVerifyModel(t, root)
	m.openStoreVerifyMenu()

	model, _ := m.handleVerifyPickKey(runes("r"))
	m = model.(RootModel)

	if m.state != stateRemoteForm {
		t.Fatalf("expected the remote form, got state %d", m.state)
	}
	if m.activeFormKind != formRemote {
		t.Error("it must be the shared remote form, not a new one")
	}
	if !m.pendingVerify {
		t.Error("the chosen store must be remembered for the answer")
	}
	if m.pendingVerifyPool == nil {
		t.Error("the store group's pool must be attached")
	}
}

func TestStoreVerify_FileStillWorks(t *testing.T) {
	m := storeVerifyModel(t, tsCert(t, "Root A"))
	m.openStoreVerifyMenu()

	model, cmd := m.handleVerifyPickKey(runes("f"))
	if got := model.(RootModel); got.state == stateVerifyPick {
		t.Error("choosing File must leave the picker")
	}
	if cmd == nil {
		t.Error("choosing File must open the file picker")
	}
}

// TestStoreVerify_RemoteResultUsesHostname: a chain that reaches the store's
// root but was issued for another name is not a pass.
func TestStoreVerify_RemoteResultUsesHostname(t *testing.T) {
	ca, leaf := makeSignedPair(t)
	m := storeVerifyModel(t, ca)
	m.pendingVerify = true
	m.pendingVerifyInfo = truststore.StoreInfo{Type: truststore.StoreTypeOS, Name: "OS Trust Store"}
	m.pendingVerifyPool = truststore.BuildCertPool([]*x509.Certificate{ca})

	result := &certops.FetchRemoteCertResult{TargetResults: []certops.TargetFetchResult{
		remoteTargetResult("other.example:443", []string{"leaf", "intermediate"},
			[]*x509.Certificate{leaf, ca}),
	}}

	if !m.verifyFetchedAgainstPending(result, "other.example") {
		t.Fatal("the fetch should have been verified")
	}
	if m.state != stateTrustVerify {
		t.Fatalf("expected the verify result view, got state %d", m.state)
	}
	if m.trustVerify.Trusted {
		t.Error("a chain issued for leaf.example.com must not verify for other.example")
	}

	m.pendingVerify = true
	m.pendingVerifyPool = truststore.BuildCertPool([]*x509.Certificate{ca})
	matching := &certops.FetchRemoteCertResult{TargetResults: []certops.TargetFetchResult{
		remoteTargetResult("leaf.example.com:443", []string{"leaf", "intermediate"},
			[]*x509.Certificate{leaf, ca}),
	}}
	if !m.verifyFetchedAgainstPending(matching, "leaf.example.com") {
		t.Fatal("the fetch should have been verified")
	}
	if !m.trustVerify.Trusted {
		t.Errorf("the matching name under a trusted root must verify: %s", m.trustVerify.Reason)
	}
}

func TestStoreVerify_EscReturnsToStoreView(t *testing.T) {
	ca, leaf := makeSignedPair(t)
	m := storeVerifyModel(t, ca)
	m.pendingVerify = true
	m.pendingVerifyPool = truststore.BuildCertPool([]*x509.Certificate{ca})
	m.verifyFetchedAgainstPending(&certops.FetchRemoteCertResult{
		TargetResults: []certops.TargetFetchResult{
			remoteTargetResult("leaf.example.com:443", []string{"leaf", "intermediate"},
				[]*x509.Certificate{leaf, ca}),
		},
	}, "leaf.example.com")

	model, _ := m.handleTrustVerifyKey(tea.KeyMsg{Type: tea.KeyEsc})
	got := model.(RootModel)

	if got.currentRoot != rootTrustStore {
		t.Error("Esc must return to the trust store view it was started from")
	}
	if got.state != stateTree {
		t.Errorf("expected the tree, got state %d", got.state)
	}
}

// TestStoreVerify_EnterOpensRemoteResult: the verified endpoint is still a
// fetched result, so Enter goes to it instead of making the user fetch again.
func TestStoreVerify_EnterOpensRemoteResult(t *testing.T) {
	ca, leaf := makeSignedPair(t)
	m := storeVerifyModel(t, ca)
	m.remoteResult = &certops.FetchRemoteCertResult{TargetResults: []certops.TargetFetchResult{
		remoteTargetResult("leaf.example.com:443", []string{"leaf", "intermediate"},
			[]*x509.Certificate{leaf, ca}),
	}}
	m.remoteHasResult = true
	m.pendingVerify = true
	m.pendingVerifyPool = truststore.BuildCertPool([]*x509.Certificate{ca})
	m.verifyFetchedAgainstPending(m.remoteResult, "leaf.example.com")

	model, _ := m.handleTrustVerifyKey(tea.KeyMsg{Type: tea.KeyEnter})
	got := model.(RootModel)

	if got.currentRoot != rootRemoteFetch || got.state != stateTree {
		t.Errorf("Enter must open the fetched result, got root %d state %d", got.currentRoot, got.state)
	}
}

// TestStoreVerify_NSSScopeWarningSurvives: an NSS profile holds only what the
// user added, so an untrusted verdict there is not a fact about Firefox.
func TestStoreVerify_NSSScopeWarningSurvives(t *testing.T) {
	root := tsCert(t, "Profile Root")
	store := tsStore("Firefox profile", truststore.StoreTypeNSS, "/profile", root)
	store.Info.Warnings = []string{"contains only the certificates added to this profile"}

	m := newStoreTestModel(t, store)
	m.width, m.height = 120, 40
	m.tree.cursor = 0

	info, pool := m.poolForCursorGroup()
	if pool == nil {
		t.Fatal("expected a pool for the NSS profile")
	}
	if len(info.Warnings) == 0 {
		t.Error("the scope warning must reach the verify result, or an untrusted verdict reads as a fact about the browser")
	}
	if !strings.Contains(strings.Join(info.Warnings, " "), "added to this profile") {
		t.Errorf("unexpected warnings: %v", info.Warnings)
	}
}

// TestStoreVerify_ViewShowsScopeWarning: the warning has to be on screen, not
// merely carried in the struct.
func TestStoreVerify_ViewShowsScopeWarning(t *testing.T) {
	ca, leaf := makeSignedPair(t)
	m := storeVerifyModel(t, ca)
	m.pendingVerify = true
	m.pendingVerifyInfo = truststore.StoreInfo{
		Type:     truststore.StoreTypeNSS,
		Name:     "Firefox profile",
		Warnings: []string{"contains only the certificates added to this profile"},
	}
	m.pendingVerifyPool = truststore.BuildCertPool([]*x509.Certificate{ca})
	// A remote verification always follows a fetch, so the result is in hand.
	m.remoteResult = &certops.FetchRemoteCertResult{
		TargetResults: []certops.TargetFetchResult{
			remoteTargetResult("leaf.example.com:443", []string{"leaf", "intermediate"},
				[]*x509.Certificate{leaf, ca}),
		},
	}
	m.remoteHasResult = true
	m.verifyFetchedAgainstPending(m.remoteResult, "leaf.example.com")

	view := m.viewTrustVerify()
	if !strings.Contains(view, "added to this profile") {
		t.Errorf("the scope warning must be visible in the result:\n%s", view)
	}
	if !strings.Contains(view, "Enter") {
		t.Errorf("the result must offer the way into the fetched chain:\n%s", view)
	}
}

// Leaving the remote form. It used to answer Esc with "Use F to switch views",
// and F is not bound in a form at all, so a form opened with nothing behind it
// - which is exactly what the trust store's verify action does - had no way out.

func TestRemoteForm_EscFromStoreVerifyReturnsToStore(t *testing.T) {
	m := storeVerifyModel(t, tsCert(t, "Root A"))
	m.openStoreVerifyMenu()
	model, _ := m.handleVerifyPickKey(runes("r"))
	m = model.(RootModel)

	if m.state != stateRemoteForm {
		t.Fatalf("test setup: expected the remote form, got %d", m.state)
	}

	model, _ = m.handleRemoteFormKey(tea.KeyMsg{Type: tea.KeyEsc})
	got := model.(RootModel)

	if got.state != stateTree {
		t.Errorf("Esc must leave the form, got state %d", got.state)
	}
	if got.currentRoot != rootTrustStore {
		t.Errorf("a cancelled verification returns to the store it started from, got root %d", got.currentRoot)
	}
	if got.pendingVerify {
		t.Error("the pending verification must be cleared, or the next fetch would be measured against it")
	}
	if got.activeForm != nil {
		t.Error("the form must be closed")
	}
}

func TestRemoteForm_EscWithNoResultReturnsToPreviousRoot(t *testing.T) {
	m := makeTestRootModel()
	m.width, m.height = 120, 40
	m.currentRoot = rootCertLister
	m.state = stateTree
	m.openRemoteForm()
	m.currentRoot = rootRemoteFetch // what the functions menu does

	model, _ := m.handleRemoteFormKey(tea.KeyMsg{Type: tea.KeyEsc})
	got := model.(RootModel)

	if got.state != stateTree {
		t.Errorf("Esc must leave the form even with no result, got state %d", got.state)
	}
	if got.currentRoot != rootCertLister {
		t.Errorf("expected to return to the Cert Lister, got root %d", got.currentRoot)
	}
}

func TestRemoteForm_EscWithResultReturnsToResult(t *testing.T) {
	ca, leaf := makeSignedPair(t)
	m := remoteTreeModel(t, remoteTargetResult("example.com:443",
		[]string{"leaf", "intermediate"}, []*x509.Certificate{leaf, ca}))
	m.openRemoteForm()

	model, _ := m.handleRemoteFormKey(tea.KeyMsg{Type: tea.KeyEsc})
	got := model.(RootModel)

	if got.state != stateTree || got.currentRoot != rootRemoteFetch {
		t.Errorf("Esc over an existing result returns to it, got root %d state %d", got.currentRoot, got.state)
	}
	if len(got.visible) == 0 {
		t.Error("the result must still be on screen")
	}
}

// TestRemoteForm_LettersStillType guards the fix: capturing F as a hotkey here
// would make file paths and hostnames untypeable, which is why Esc carries this
// instead.
func TestRemoteForm_LettersStillType(t *testing.T) {
	m := makeTestRootModel()
	m.width, m.height = 120, 40
	m.openRemoteForm()

	for _, r := range "F" {
		model, _ := m.handleRemoteFormKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		m = model.(RootModel)
	}

	if m.state != stateRemoteForm {
		t.Errorf("typing must not leave the form, got state %d", m.state)
	}
	if got := m.activeForm.fieldValue(fieldKeyTarget); got != "F" {
		t.Errorf("the letter must reach the field, got %q", got)
	}
}
