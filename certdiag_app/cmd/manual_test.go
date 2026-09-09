package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestResolvePager is the L17 regression: a PAGER value that is an existing path
// (possibly containing spaces) is used verbatim rather than split on whitespace.
func TestResolvePager(t *testing.T) {
	t.Run("command with flags is split", func(t *testing.T) {
		t.Setenv("PAGER", "less -R")
		name, args := resolvePager()
		if name != "less" || len(args) != 1 || args[0] != "-R" {
			t.Errorf("got name=%q args=%v", name, args)
		}
	})

	t.Run("existing spaced path used verbatim", func(t *testing.T) {
		dir := t.TempDir()
		spaced := filepath.Join(dir, "my pager")
		if err := os.WriteFile(spaced, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PAGER", spaced)
		name, args := resolvePager()
		if name != spaced || len(args) != 0 {
			t.Errorf("spaced path should be used verbatim, got name=%q args=%v", name, args)
		}
	})
}

// TestRenderManualSkipsBoilerplate is the LOW regression: the manual must not
// include cobra's auto-generated completion/help commands.
func TestRenderManualSkipsBoilerplate(t *testing.T) {
	root := &cobra.Command{Use: "certdiag", Short: "root"}
	root.AddCommand(&cobra.Command{Use: "convert", Short: "convert things"})
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()

	out := renderManual(root)
	if !strings.Contains(out, "convert") {
		t.Error("manual should include real subcommands")
	}
	if strings.Contains(out, "certdiag completion") {
		t.Error("manual must not include the generated completion command")
	}
	if strings.Contains(out, "certdiag help") {
		t.Error("manual must not include the generated help command")
	}
}
