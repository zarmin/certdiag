package cmd

import (
	"io"
	"os"
	"strings"
	"testing"
)

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	fn()
	w.Close()
	os.Stderr = old
	data, _ := io.ReadAll(r)
	return string(data)
}

func TestResolveMasterPasswordFlagWarns(t *testing.T) {
	old := masterPasswordFlag
	t.Cleanup(func() { masterPasswordFlag = old })
	masterPasswordFlag = "s3cret"

	var pw []byte
	out := captureStderr(t, func() {
		pw = resolveMasterPassword(false)
	})

	if string(pw) != "s3cret" {
		t.Errorf("resolveMasterPassword() = %q, want %q", pw, "s3cret")
	}
	if !strings.Contains(out, "visible in process listing") {
		t.Errorf("expected process-listing warning for --master-password, got %q", out)
	}
}

func TestResolveMasterPasswordNoFlagNoWarn(t *testing.T) {
	oldFlag := masterPasswordFlag
	oldEnv, hadEnv := os.LookupEnv("CERTDIAG_MASTER_KEY")
	t.Cleanup(func() {
		masterPasswordFlag = oldFlag
		if hadEnv {
			os.Setenv("CERTDIAG_MASTER_KEY", oldEnv)
		} else {
			os.Unsetenv("CERTDIAG_MASTER_KEY")
		}
	})
	masterPasswordFlag = ""
	os.Unsetenv("CERTDIAG_MASTER_KEY")

	out := captureStderr(t, func() {
		resolveMasterPassword(false)
	})

	if strings.Contains(out, "visible in process listing") {
		t.Errorf("did not expect warning when --master-password unset, got %q", out)
	}
}
