package certlib

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestSingleDefinitions guards M31 R5: the self-signed predicate and the
// filename sanitiser exist exactly once in the tree. A second copy is how two
// commands came to disagree about what "self-signed" means.
func TestSingleDefinitions(t *testing.T) {
	root := filepath.Join("..", "..")
	patterns := map[string]*regexp.Regexp{
		"self-signed predicate": regexp.MustCompile(`(?m)^func (?:\([^)]*\) )?[iI]sSelfSigned\w*\(`),
		"filename sanitiser":    regexp.MustCompile(`(?m)^func (?:\([^)]*\) )?[sS]anitizeFilename\w*\(`),
		"built-in password":     regexp.MustCompile(`\[\]byte\("changeit"\)`),
	}
	found := map[string][]string{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			base := info.Name()
			if base == "vendor" || base == "dist" || base == "testdata" || strings.HasPrefix(base, ".") && base != "." && base != ".." {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for what, re := range patterns {
			if re.Match(src) {
				found[what] = append(found[what], path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for what := range patterns {
		if n := len(found[what]); n != 1 {
			t.Errorf("%s defined %d times, want exactly one: %v", what, n, found[what])
		}
	}
}
