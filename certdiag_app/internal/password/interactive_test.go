package password

import (
	"bufio"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRestoreOnSignal_CleanupRestores(t *testing.T) {
	var calls int32
	cleanup := restoreOnSignal(func() { atomic.AddInt32(&calls, 1) })
	cleanup()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected restore called once on cleanup, got %d", got)
	}
}

func TestRestoreOnSignal_NoGoroutineLeak(t *testing.T) {
	// Warm up so the runtime's persistent signal-watcher goroutine is already
	// running and does not skew the baseline.
	restoreOnSignal(func() {})()
	settle()

	baseline := runtime.NumGoroutine()
	for i := 0; i < 50; i++ {
		restoreOnSignal(func() {})()
	}
	settle()

	if grown := runtime.NumGoroutine() - baseline; grown > 0 {
		t.Errorf("goroutine leak: %d extra goroutines after 50 install/cleanup cycles", grown)
	}
}

func TestInstallTerminalRestore_NonTTY_NoOp(t *testing.T) {
	r, _, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	settle()
	baseline := runtime.NumGoroutine()
	cleanup := installTerminalRestore(int(r.Fd()))
	cleanup()
	settle()

	if runtime.NumGoroutine() > baseline {
		t.Errorf("no goroutine should be installed for a non-terminal fd")
	}
}

func settle() {
	deadline := time.Now().Add(500 * time.Millisecond)
	prev := runtime.NumGoroutine()
	for time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		cur := runtime.NumGoroutine()
		if cur == prev {
			return
		}
		prev = cur
	}
}

// resetStdinScanner replaces the package-level scanner with one reading from r,
// and returns a cleanup function that restores the original os.Stdin.
func resetStdinScanner(t *testing.T, r *os.File) func() {
	t.Helper()
	origStdin := os.Stdin
	os.Stdin = r
	// Reset sync.Once so the scanner gets re-created from new stdin
	stdinOnce = sync.Once{}
	stdinScanner = nil
	return func() {
		os.Stdin = origStdin
		stdinOnce = sync.Once{}
		stdinScanner = nil
	}
}

func TestReadLineFromStdin_SingleLine(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cleanup := resetStdinScanner(t, r)
	defer cleanup()

	go func() {
		w.WriteString("mypassword\n")
		w.Close()
	}()

	pw, err := readLineFromStdin()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(pw) != "mypassword" {
		t.Errorf("expected 'mypassword', got %q", pw)
	}
}

func TestReadLineFromStdin_MultipleLines(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cleanup := resetStdinScanner(t, r)
	defer cleanup()

	go func() {
		w.WriteString("first-password\nsecond-password\n")
		w.Close()
	}()

	pw1, err := readLineFromStdin()
	if err != nil {
		t.Fatalf("first read error: %v", err)
	}
	if string(pw1) != "first-password" {
		t.Errorf("first: expected 'first-password', got %q", pw1)
	}

	pw2, err := readLineFromStdin()
	if err != nil {
		t.Fatalf("second read error: %v", err)
	}
	if string(pw2) != "second-password" {
		t.Errorf("second: expected 'second-password', got %q", pw2)
	}
}

func TestReadLineFromStdin_EmptyPassword(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cleanup := resetStdinScanner(t, r)
	defer cleanup()

	go func() {
		w.WriteString("\n")
		w.Close()
	}()

	pw, err := readLineFromStdin()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(pw) != "" {
		t.Errorf("expected empty password, got %q", pw)
	}
}

func TestReadLineFromStdin_EOF(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cleanup := resetStdinScanner(t, r)
	defer cleanup()

	w.Close() // immediate EOF

	_, err = readLineFromStdin()
	if err == nil {
		t.Error("expected error on EOF")
	}
}

func TestReadLineFromStdin_WindowsCRLF(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cleanup := resetStdinScanner(t, r)
	defer cleanup()

	go func() {
		w.WriteString("winpass\r\n")
		w.Close()
	}()

	pw, err := readLineFromStdin()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(pw) != "winpass" {
		t.Errorf("expected 'winpass', got %q", pw)
	}
}

func TestReadLineFromStdin_NoTrailingNewline(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cleanup := resetStdinScanner(t, r)
	defer cleanup()

	go func() {
		w.WriteString("noterminated")
		w.Close()
	}()

	pw, err := readLineFromStdin()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(pw) != "noterminated" {
		t.Errorf("expected 'noterminated', got %q", pw)
	}
}

func TestPromptPassword_NonTTY(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cleanup := resetStdinScanner(t, r)
	defer cleanup()

	go func() {
		w.WriteString("piped-pass\n")
		w.Close()
	}()

	pw, err := PromptPassword("Enter password: ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(pw) != "piped-pass" {
		t.Errorf("expected 'piped-pass', got %q", pw)
	}
}

func TestPromptPassword_NonTTY_MultipleSequential(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cleanup := resetStdinScanner(t, r)
	defer cleanup()

	go func() {
		w.WriteString("old-password\nnew-password\nconfirm-password\n")
		w.Close()
	}()

	pw1, _ := PromptPassword("Old: ")
	pw2, _ := PromptPassword("New: ")
	pw3, _ := PromptPassword("Confirm: ")

	if string(pw1) != "old-password" {
		t.Errorf("first: expected 'old-password', got %q", pw1)
	}
	if string(pw2) != "new-password" {
		t.Errorf("second: expected 'new-password', got %q", pw2)
	}
	if string(pw3) != "confirm-password" {
		t.Errorf("third: expected 'confirm-password', got %q", pw3)
	}
}

func TestPromptRetryMenu_NonTTY_ReturnsSkip(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cleanup := resetStdinScanner(t, r)
	defer cleanup()

	w.Close()

	result := promptRetryMenu()
	if result != 's' {
		t.Errorf("expected 's' (skip) for non-TTY, got %q", result)
	}
}

func TestGetStdinScanner_ReturnsSameInstance(t *testing.T) {
	r, _, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cleanup := resetStdinScanner(t, r)
	defer cleanup()

	s1 := getStdinScanner()
	s2 := getStdinScanner()
	if s1 != s2 {
		t.Error("getStdinScanner should return the same instance")
	}
}

func TestStdinIsTerminal_WithPipe(t *testing.T) {
	r, _, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cleanup := resetStdinScanner(t, r)
	defer cleanup()

	if stdinIsTerminal() {
		t.Error("pipe should not be detected as terminal")
	}
}

func TestReadLineFromStdin_SharedScanner_NoSplit(t *testing.T) {
	// Verify that the shared scanner correctly handles sequential reads
	// without splitting or losing data
	r, w := io.Pipe()

	origStdin := os.Stdin
	pr, pw, _ := os.Pipe()
	os.Stdin = pr
	stdinOnce = sync.Once{}
	stdinScanner = nil
	pw.Close()
	defer func() {
		r.Close()
		pr.Close()
		os.Stdin = origStdin
		stdinOnce = sync.Once{}
		stdinScanner = nil
	}()

	// Manually create a scanner from the reader for direct testing
	scanner := bufio.NewScanner(r)
	stdinOnce.Do(func() { stdinScanner = scanner })

	go func() {
		w.Write([]byte("line1\nline2\nline3\n"))
		w.Close()
	}()

	for i, expected := range []string{"line1", "line2", "line3"} {
		if !stdinScanner.Scan() {
			t.Fatalf("scan %d: unexpected EOF", i)
		}
		got := stdinScanner.Text()
		if got != expected {
			t.Errorf("scan %d: expected %q, got %q", i, expected, got)
		}
	}
}
