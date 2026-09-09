package tui

import (
	"errors"
	"fmt"
	"os/exec"
	"testing"
)

func makeExitError(t *testing.T) *exec.ExitError {
	t.Helper()
	err := exec.Command("sh", "-c", "exit 3").Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected *exec.ExitError, got %T (%v)", err, err)
	}
	return exitErr
}

func TestShellExit_NonzeroExitRescans(t *testing.T) {
	m := makeTestRootModel()

	result, cmd := m.Update(shellExitMsg{err: makeExitError(t)})
	rm := result.(RootModel)

	if rm.state != stateLoading {
		t.Fatalf("expected stateLoading (rescan), got %d", rm.state)
	}
	if cmd == nil {
		t.Fatal("expected non-nil cmd for rescan")
	}
	if rm.popup.kind == popupError {
		t.Fatalf("expected no error popup on nonzero exit, got %q", rm.popup.message)
	}
}

func TestShellExit_SpawnFailureShowsPopup(t *testing.T) {
	m := makeTestRootModel()

	result, _ := m.Update(shellExitMsg{err: fmt.Errorf("exec: \"badshell\": executable file not found")})
	rm := result.(RootModel)

	if rm.popup.kind != popupError {
		t.Fatalf("expected error popup on spawn failure, got kind %d", rm.popup.kind)
	}
	if rm.state == stateLoading {
		t.Fatal("expected no rescan on spawn failure")
	}
}

func TestShellExit_CleanExitRescans(t *testing.T) {
	m := makeTestRootModel()

	result, cmd := m.Update(shellExitMsg{err: nil})
	rm := result.(RootModel)

	if rm.state != stateLoading {
		t.Fatalf("expected stateLoading (rescan), got %d", rm.state)
	}
	if cmd == nil {
		t.Fatal("expected non-nil cmd for rescan")
	}
	if rm.popup.kind == popupError {
		t.Fatalf("expected no error popup on clean exit, got %q", rm.popup.message)
	}
}
