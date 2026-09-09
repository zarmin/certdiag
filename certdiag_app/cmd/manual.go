package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var manualFlag bool

// showManual renders the full command tree and displays it through a pager.
func showManual(root *cobra.Command) {
	pageText(renderManual(root))
}

func renderManual(root *cobra.Command) string {
	var b strings.Builder
	writeCommandManual(&b, root)
	return b.String()
}

func writeCommandManual(b *strings.Builder, cmd *cobra.Command) {
	if cmd.Hidden {
		return
	}

	b.WriteString(strings.Repeat("=", 70))
	b.WriteString("\n")
	b.WriteString(cmd.CommandPath())
	b.WriteString("\n")
	b.WriteString(strings.Repeat("=", 70))
	b.WriteString("\n\n")

	if cmd.Short != "" {
		b.WriteString(cmd.Short)
		b.WriteString("\n\n")
	}
	if cmd.Long != "" && cmd.Long != cmd.Short {
		b.WriteString(cmd.Long)
		b.WriteString("\n\n")
	}

	b.WriteString("Usage:\n  ")
	b.WriteString(cmd.UseLine())
	b.WriteString("\n\n")

	if cmd.Example != "" {
		b.WriteString("Examples:\n")
		b.WriteString(cmd.Example)
		b.WriteString("\n\n")
	}

	if usage := cmd.LocalFlags().FlagUsages(); usage != "" {
		b.WriteString("Flags:\n")
		b.WriteString(usage)
		b.WriteString("\n")
	}

	for _, sub := range cmd.Commands() {
		// Skip cobra's auto-generated boilerplate commands; they are not part of
		// certdiag's own surface and only pad the manual.
		if sub.Name() == "completion" || sub.Name() == "help" {
			continue
		}
		writeCommandManual(b, sub)
	}
}

// pageText sends text to the user's pager, falling back to direct output when
// stdout is not a terminal or no pager is available.
func pageText(text string) {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Print(text)
		return
	}

	name, args := resolvePager()

	c := exec.Command(name, args...)
	c.Stdin = strings.NewReader(text)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		// Only re-dump when the pager could not be launched. If it ran and exited
		// nonzero (user quit, broken pipe), the text was already displayed - a
		// re-dump would print the whole manual a second time.
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			fmt.Print(text)
		}
	}
}

// resolvePager returns the pager command and args. A PAGER value that is itself
// an existing path is used verbatim (handles paths with spaces, e.g. on
// Windows); otherwise it is split into command + args.
func resolvePager() (string, []string) {
	pager := os.Getenv("PAGER")
	if pager != "" {
		if _, err := os.Stat(pager); err == nil {
			return pager, nil
		}
		if fields := strings.Fields(pager); len(fields) > 0 {
			return fields[0], fields[1:]
		}
	}
	if runtime.GOOS == "windows" {
		return "more", nil
	}
	return "less", []string{"-R"}
}
