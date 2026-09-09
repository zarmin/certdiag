package tui

import (
	"errors"
	"fmt"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func TestFormResultFileExists(t *testing.T) {
	// A wrapped ErrFileExists (as produced by WriteToFile and re-wrapped by
	// certops) must set the FileExists flag via errors.Is, not a string match.
	wrapped := fmt.Errorf("write cert failed: %w", fmt.Errorf("%w: /tmp/x (use --no-confirm)", certlib.ErrFileExists))
	msg := formResult(wrapped, "ok")
	if !msg.FileExists {
		t.Errorf("expected FileExists=true for wrapped ErrFileExists, got %+v", msg)
	}
	if msg.Success {
		t.Error("expected Success=false on error")
	}

	other := formResult(errors.New("some other failure"), "ok")
	if other.FileExists {
		t.Error("expected FileExists=false for unrelated error")
	}

	ok := formResult(nil, "done")
	if !ok.Success || ok.Message != "done" {
		t.Errorf("expected success result, got %+v", ok)
	}
}

func TestFormResultWithPasswords_Empty(t *testing.T) {
	msg := formResultWithPasswords(nil, "ok", []byte(""))
	if len(msg.Passwords) != 1 {
		t.Fatalf("passwords count = %d, want 1", len(msg.Passwords))
	}
	if len(msg.Passwords[0]) != 0 {
		t.Error("expected empty password in result")
	}
}

func TestFormResultWithPasswords_Nil(t *testing.T) {
	msg := formResultWithPasswords(nil, "ok", nil)
	if len(msg.Passwords) != 0 {
		t.Fatalf("passwords count = %d, want 0 (nil should be excluded)", len(msg.Passwords))
	}
}

func TestNilIfEmpty(t *testing.T) {
	if got := nilIfEmpty(""); got != nil {
		t.Errorf("nilIfEmpty(\"\") = %v, want nil", got)
	}
	if got := nilIfEmpty("abc"); string(got) != "abc" {
		t.Errorf("nilIfEmpty(\"abc\") = %q, want \"abc\"", got)
	}
}
