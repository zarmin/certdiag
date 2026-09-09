//go:build !windows

package filepicker

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPassesFilter(t *testing.T) {
	tests := []struct {
		name      string
		entry     fileEntry
		filter    []string
		filterAll bool
		dt        DialogType
		want      bool
	}{
		{"dir always passes", fileEntry{name: "subdir", isDir: true}, []string{".pem"}, false, TypeOpenFile, true},
		{"no filter passes", fileEntry{name: "file.txt"}, nil, false, TypeOpenFile, true},
		{"filterAll override", fileEntry{name: "file.txt"}, []string{".pem"}, true, TypeOpenFile, true},
		{"TypeOpenDir files fail", fileEntry{name: "file.pem"}, nil, false, TypeOpenDir, false},
		{"matching ext", fileEntry{name: "cert.pem"}, []string{".pem", ".crt"}, false, TypeOpenFile, true},
		{"non-matching ext", fileEntry{name: "file.txt"}, []string{".pem", ".crt"}, false, TypeOpenFile, false},
		{"case-insensitive", fileEntry{name: "file.PEM"}, []string{".pem"}, false, TypeOpenFile, true},
		{"empty filter", fileEntry{name: "file.txt"}, []string{}, false, TypeOpenFile, true},
		{"dir passes with OpenDir", fileEntry{name: "subdir", isDir: true}, nil, false, TypeOpenDir, true},
		{"file with filterAll and OpenDir", fileEntry{name: "f.txt"}, []string{".pem"}, true, TypeOpenDir, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := passesFilter(tt.entry, tt.filter, tt.filterAll, tt.dt)
			if got != tt.want {
				t.Errorf("passesFilter()=%v, want %v", got, tt.want)
			}
		})
	}
}

func TestApplyNameFilter(t *testing.T) {
	entries := []fileEntry{
		{name: ".."},
		{name: "alpha.pem"},
		{name: "beta.crt"},
		{name: "gamma.key"},
		{name: "ALPHA.txt"},
	}

	// Empty query returns all
	result := applyNameFilter(entries, "")
	if len(result) != len(entries) {
		t.Errorf("empty query: got %d entries, want %d", len(result), len(entries))
	}

	// Substring match
	result = applyNameFilter(entries, "alpha")
	names := entryNames(result)
	if !containsName(names, "..") {
		t.Error("'..' should always be included")
	}
	if !containsName(names, "alpha.pem") {
		t.Error("alpha.pem should match")
	}
	if !containsName(names, "ALPHA.txt") {
		t.Error("ALPHA.txt should match (case-insensitive)")
	}

	// ".." always included
	result = applyNameFilter(entries, "zzz")
	if len(result) != 1 || result[0].name != ".." {
		t.Errorf("no-match: got %v, want only '..'", entryNames(result))
	}

	// Case-insensitive
	result = applyNameFilter(entries, "BETA")
	if !containsName(entryNames(result), "beta.crt") {
		t.Error("case-insensitive match should find beta.crt")
	}
}

func TestFormatSize(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
		{2516582, "2.4 MB"},
	}

	for _, tt := range tests {
		got := formatSize(tt.input)
		if got != tt.want {
			t.Errorf("formatSize(%d)=%q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFormatModTime(t *testing.T) {
	tm := time.Date(2024, 6, 15, 14, 30, 45, 0, time.UTC)
	got := formatModTime(tm)
	want := "2024-06-15 14:30:45"
	if got != want {
		t.Errorf("formatModTime()=%q, want %q", got, want)
	}
}

func TestReadDir(t *testing.T) {
	dir := setupTestDir(t)

	// Basic read with hidden excluded
	entries, err := readDir(dir, false, nil, false, TypeOpenFile)
	if err != nil {
		t.Fatal(err)
	}

	// ".." should be first
	if len(entries) == 0 || entries[0].name != ".." {
		t.Error("first entry should be '..'")
	}

	// Dirs sorted before files
	names := entryNames(entries)
	dirIdx := -1
	fileIdx := -1
	for i, n := range names {
		if n == "adir" {
			dirIdx = i
		}
		if n == "file1.pem" {
			fileIdx = i
		}
	}
	if dirIdx > fileIdx {
		t.Error("dirs should sort before files")
	}

	// Hidden excluded by default
	if containsName(names, ".hidden") {
		t.Error(".hidden should be excluded when showHidden=false")
	}
	if containsName(names, ".hiddendir") {
		t.Error(".hiddendir should be excluded when showHidden=false")
	}

	// Hidden included
	entriesH, _ := readDir(dir, true, nil, false, TypeOpenFile)
	namesH := entryNames(entriesH)
	if !containsName(namesH, ".hidden") {
		t.Error(".hidden should be included when showHidden=true")
	}

	// Filter applied
	entriesF, _ := readDir(dir, false, []string{".pem"}, false, TypeOpenFile)
	for _, e := range entriesF {
		if !e.isDir && e.name != ".." && !e.passesFilter {
			if filepath.Ext(e.name) == ".pem" {
				t.Errorf("%s should pass filter", e.name)
			}
		}
		if e.passesFilter && !e.isDir && filepath.Ext(e.name) != ".pem" {
			t.Errorf("%s should not pass .pem filter", e.name)
		}
	}
}

func TestIsHiddenFile(t *testing.T) {
	if !isHiddenFile(".hidden", "") {
		t.Error(".hidden should be hidden")
	}
	if !isHiddenFile(".gitignore", "") {
		t.Error(".gitignore should be hidden")
	}
	if isHiddenFile("normal.txt", "") {
		t.Error("normal.txt should not be hidden")
	}
	if isHiddenFile("file.pem", "") {
		t.Error("file.pem should not be hidden")
	}
}

func TestReadDir_Symlinks(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "target.pem"), []byte("target"), 0644)
	os.MkdirAll(filepath.Join(dir, "targetdir"), 0755)
	os.Symlink(filepath.Join(dir, "target.pem"), filepath.Join(dir, "link.pem"))
	os.Symlink(filepath.Join(dir, "targetdir"), filepath.Join(dir, "linkdir"))

	entries, err := readDir(dir, false, nil, false, TypeOpenFile)
	if err != nil {
		t.Fatal(err)
	}

	for _, e := range entries {
		if e.name == "link.pem" {
			if !e.isSymlink {
				t.Error("link.pem should be a symlink")
			}
			if e.isDir {
				t.Error("link.pem should not be a directory")
			}
		}
		if e.name == "linkdir" {
			if !e.isSymlink {
				t.Error("linkdir should be a symlink")
			}
			if !e.isDir {
				t.Error("linkdir should be a directory")
			}
		}
	}
}

func entryNames(entries []fileEntry) []string {
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.name
	}
	return names
}

func containsName(names []string, target string) bool {
	for _, n := range names {
		if n == target {
			return true
		}
	}
	return false
}
