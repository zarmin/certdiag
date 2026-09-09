package password

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/term"
)

var (
	stdinOnce    sync.Once
	stdinScanner *bufio.Scanner
)

func getStdinScanner() *bufio.Scanner {
	stdinOnce.Do(func() {
		stdinScanner = bufio.NewScanner(os.Stdin)
	})
	return stdinScanner
}

func stdinIsTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

func readLineFromStdin() ([]byte, error) {
	scanner := getStdinScanner()
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("EOF reading password from stdin")
	}
	return []byte(strings.TrimRight(scanner.Text(), "\r\n")), nil
}

func installTerminalRestore(fd int) func() {
	oldState, err := term.GetState(fd)
	if err != nil {
		return func() {}
	}
	return restoreOnSignal(func() { term.Restore(fd, oldState) })
}

func restoreOnSignal(restore func()) func() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		select {
		case sig := <-sigCh:
			restore()
			signal.Stop(sigCh)
			signal.Reset(syscall.SIGINT, syscall.SIGTERM)
			if p, err := os.FindProcess(os.Getpid()); err == nil {
				p.Signal(sig)
			}
		case <-done:
		}
	}()
	return func() {
		signal.Stop(sigCh)
		close(done)
		restore()
	}
}

func PromptPassword(prompt string) ([]byte, error) {
	if stdinIsTerminal() {
		fd := int(os.Stdin.Fd())
		restore := installTerminalRestore(fd)
		defer restore()
		fmt.Fprint(os.Stderr, prompt)
		pw, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}
		return pw, nil
	}
	return readLineFromStdin()
}

func promptRetryMenu() rune {
	if !stdinIsTerminal() {
		return 's'
	}
	fmt.Fprint(os.Stderr, "  [r]etry / [s]kip / [S]kip all / [q]uit: ")
	reader := bufio.NewReader(os.Stdin)
	ch, _, err := reader.ReadRune()
	if err != nil {
		return 'q'
	}
	fmt.Fprintln(os.Stderr)
	return ch
}
