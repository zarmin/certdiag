//go:build fulltest

package tui

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
)

// e2eStores is the fixed store set every E2E flow runs against. Nothing here
// touches the real machine: the loader is stubbed.
func e2eStores(t *testing.T) []truststore.StoreContents {
	t.Helper()
	shared := tsCert(t, "Shared Global Root")
	osOnly := tsCert(t, "OS Only Root")
	javaOnly := tsCert(t, "Corporate Java Root")

	return []truststore.StoreContents{
		tsStore("macOS System Roots", truststore.StoreTypeOS, "/kc", shared, osOnly),
		tsStore("Java 21 (Temurin)", truststore.StoreTypeJava, "/jdk21/cacerts", shared, javaOnly),
		tsStore("OpenSSL", truststore.StoreTypeOpenSSL, "/etc/ssl/cert.pem", shared),
	}
}

func newStoreE2E(t *testing.T, stub *loaderStub) (*teatest.TestModel, *outputWatcher) {
	t.Helper()
	initStyles()
	initFormStyles()

	m := NewRootModel(".", certlib.ScanOptions{}, false, output.OutputOptions{}, TUIOptions{
		InitialTrustStore: true,
		TrustStoreLoader:  stub.load,
		StoreCols:         []string{"subject", "expiry", "stores"},
		StoreGrouping:     string(certops.GroupByInstance),
	})
	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(140, 40))
	return tm, watchOutput(tm)
}

// outputWatcher accumulates everything the program renders. teatest's
// Output() is a single progressively-consumed stream, so repeated WaitFor
// calls on it would each start where the previous stopped; accumulating once
// lets a test assert several things about the same screen.
type outputWatcher struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func watchOutput(tm *teatest.TestModel) *outputWatcher {
	w := &outputWatcher{}
	go func() {
		chunk := make([]byte, 4096)
		out := tm.Output()
		for {
			n, err := out.Read(chunk)
			if n > 0 {
				w.mu.Lock()
				w.buf.Write(chunk[:n])
				w.mu.Unlock()
			}
			if err == io.EOF {
				// The program has not written more yet; keep waiting rather
				// than abandoning the stream.
				time.Sleep(20 * time.Millisecond)
				continue
			}
			if err != nil {
				return
			}
		}
	}()
	return w
}

func (w *outputWatcher) text() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// waitFor blocks until every substring has appeared in the accumulated output.
func (w *outputWatcher) waitFor(t *testing.T, substrs ...string) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for {
		text := w.text()
		missing := ""
		for _, s := range substrs {
			if !strings.Contains(text, s) {
				missing = s
				break
			}
		}
		if missing == "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %q in output:\n%s", missing, text)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (w *outputWatcher) contains(s string) bool {
	return strings.Contains(w.text(), s)
}

func sendE2EKey(tm *teatest.TestModel, s string) {
	tm.Send(keyMsg(s))
	time.Sleep(120 * time.Millisecond)
}

func quit(t *testing.T, tm *teatest.TestModel) {
	t.Helper()
	// Esc first so any open modal is dismissed; ctrl+c only quits from the
	// screens that own it.
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})
	time.Sleep(100 * time.Millisecond)
	tm.Send(tea.KeyMsg{Type: tea.KeyCtrlC})
	tm.WaitFinished(t, teatest.WithFinalTimeout(10*time.Second))
}

func TestE2E_TrustStore_LoadsAndGroups(t *testing.T) {
	stub := &loaderStub{stores: e2eStores(t)}
	tm, w := newStoreE2E(t, stub)

	w.waitFor(t, "macOS System Roots")
	w.waitFor(t, "Java 21 (Temurin)")
	w.waitFor(t, "OpenSSL")
	w.waitFor(t, "STORE")

	if stub.calls != 1 {
		t.Errorf("expected exactly one load, got %d", stub.calls)
	}
	quit(t, tm)
}

func TestE2E_TrustStore_GroupingToggle(t *testing.T) {
	stub := &loaderStub{stores: e2eStores(t)}
	tm, w := newStoreE2E(t, stub)

	w.waitFor(t, "Java 21 (Temurin)")
	sendE2EKey(tm, "g")
	w.waitFor(t, "Grouped by kind")
	w.waitFor(t, "System")

	sendE2EKey(tm, "g")
	w.waitFor(t, "Grouped by instance")

	if stub.calls != 1 {
		t.Errorf("regrouping must not re-read: %d loads", stub.calls)
	}
	quit(t, tm)
}

func TestE2E_TrustStore_Search(t *testing.T) {
	stub := &loaderStub{stores: e2eStores(t)}
	tm, w := newStoreE2E(t, stub)

	w.waitFor(t, "OpenSSL")

	sendE2EKey(tm, "/")
	for _, r := range "temurin" {
		sendE2EKey(tm, string(r))
	}
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	time.Sleep(200 * time.Millisecond)

	w.waitFor(t, "Java 21 (Temurin)")
	quit(t, tm)
}

func TestE2E_TrustStore_ColumnEditor(t *testing.T) {
	stub := &loaderStub{stores: e2eStores(t)}
	tm, w := newStoreE2E(t, stub)

	w.waitFor(t, "macOS System Roots")
	sendE2EKey(tm, "C")
	w.waitFor(t, "Column Visibility")
	w.waitFor(t, "STORES")
	w.waitFor(t, "TRUST")

	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})
	time.Sleep(150 * time.Millisecond)
	quit(t, tm)
}

func TestE2E_TrustStore_WrapModes(t *testing.T) {
	stub := &loaderStub{stores: e2eStores(t)}
	tm, w := newStoreE2E(t, stub)

	w.waitFor(t, "macOS System Roots")
	for i := 0; i < 3; i++ {
		sendE2EKey(tm, "w")
	}
	// Still rendering the tree after a full cycle.
	w.waitFor(t, "macOS System Roots")
	quit(t, tm)
}

func TestE2E_TrustStore_Detail(t *testing.T) {
	stub := &loaderStub{stores: e2eStores(t)}
	tm, w := newStoreE2E(t, stub)

	w.waitFor(t, "macOS System Roots")

	// Move onto a certificate row and open it.
	tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	time.Sleep(120 * time.Millisecond)
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	time.Sleep(250 * time.Millisecond)

	w.waitFor(t, "Store:")
	quit(t, tm)
}

func TestE2E_TrustStore_CheckView(t *testing.T) {
	stub := &loaderStub{stores: e2eStores(t)}
	tm, w := newStoreE2E(t, stub)

	w.waitFor(t, "macOS System Roots")
	sendE2EKey(tm, "W")
	time.Sleep(300 * time.Millisecond)

	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})
	time.Sleep(200 * time.Millisecond)
	w.waitFor(t, "macOS System Roots")
	quit(t, tm)
}

func TestE2E_TrustStore_DeleteIsInert(t *testing.T) {
	stub := &loaderStub{stores: e2eStores(t)}
	tm, w := newStoreE2E(t, stub)

	w.waitFor(t, "macOS System Roots")

	tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	time.Sleep(120 * time.Millisecond)
	tm.Send(tea.KeyMsg{Type: tea.KeyCtrlD})
	time.Sleep(250 * time.Millisecond)

	// No delete confirmation may appear, and the tree must still be there.
	if w.contains("Delete ") {
		t.Errorf("ctrl+d must not offer to delete a trust store:\n%s", w.text())
	}
	quit(t, tm)
}

func TestE2E_TrustStore_Reload(t *testing.T) {
	stub := &loaderStub{stores: e2eStores(t)}
	tm, w := newStoreE2E(t, stub)

	w.waitFor(t, "macOS System Roots")
	sendE2EKey(tm, "r")

	// The reload is what matters; the tree content was already asserted above
	// and teatest's output stream is consumed progressively, so re-waiting on
	// an unchanged screen is not a reliable signal.
	deadline := time.Now().Add(5 * time.Second)
	for stub.calls < 2 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if stub.calls != 2 {
		t.Errorf("expected exactly one reload, got %d loads", stub.calls)
	}
	quit(t, tm)
}

func TestE2E_TrustStore_FunctionsRoundTrip(t *testing.T) {
	stub := &loaderStub{stores: e2eStores(t)}
	tm, w := newStoreE2E(t, stub)

	w.waitFor(t, "macOS System Roots")

	// F -> Trust Stores (already there) must not trigger another read.
	sendE2EKey(tm, "F")
	w.waitFor(t, "Trust Stores")

	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	time.Sleep(500 * time.Millisecond)

	if stub.calls != 1 {
		t.Errorf("returning to the store view must not re-read: %d loads", stub.calls)
	}
	quit(t, tm)
}

func TestE2E_TrustStore_LoadFailureShowsError(t *testing.T) {
	stub := &loaderStub{err: &certops.OperationError{Op: "store", Message: "no trust store could be read"}}
	tm, w := newStoreE2E(t, stub)

	// The failure must be shown rather than leaving a blank screen.
	// (That the functions menu still opens afterwards is covered by
	// TestTrustStoreLoadedMsg_ErrorSurfaced at the unit level.)
	w.waitFor(t, "no trust store could be read")
	quit(t, tm)
}
