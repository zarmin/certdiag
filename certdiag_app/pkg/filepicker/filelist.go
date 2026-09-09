package filepicker

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type fileEntry struct {
	name          string
	isDir         bool
	isSymlink     bool
	symlinkTarget string
	size          int64
	modTime       time.Time
	passesFilter  bool
	disabled      bool
}

func readDir(dir string, showHidden bool, filter []string, filterAll bool, dt DialogType) ([]fileEntry, error) {
	// Virtual drive-list root (Windows only; returns nil on non-Windows)
	if dir == "" {
		return listWindowsDrives(), nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var result []fileEntry

	// Always add ".." unless at Unix root or virtual root.
	// At a Windows drive root we DO add ".." so the user can navigate to the drive list.
	if dir != "/" && dir != "" {
		result = append(result, fileEntry{
			name:         "..",
			isDir:        true,
			passesFilter: true,
		})
	}

	for _, e := range entries {
		name := e.Name()
		fullPath := filepath.Join(dir, name)

		// Skip hidden files unless showHidden
		if !showHidden && isHiddenFile(name, fullPath) {
			continue
		}
		info, err := os.Lstat(fullPath)
		if err != nil {
			continue
		}

		entry := fileEntry{
			name:    name,
			modTime: info.ModTime(),
		}

		if info.Mode()&os.ModeSymlink != 0 {
			entry.isSymlink = true
			target, err := filepath.EvalSymlinks(fullPath)
			if err == nil {
				entry.symlinkTarget = target
				// Check if symlink points to a dir
				targetInfo, err := os.Stat(fullPath)
				if err == nil && targetInfo.IsDir() {
					entry.isDir = true
				}
			}
			// For symlink size, use actual file size
			entry.size = info.Size()
		} else {
			entry.isDir = e.IsDir()
			entry.size = info.Size()
		}

		// Determine passesFilter
		entry.passesFilter = passesFilter(entry, filter, filterAll, dt)

		result = append(result, entry)
	}

	// Sort: ".." first, then dirs (alpha), then files (alpha), case-insensitive
	sort.SliceStable(result, func(i, j int) bool {
		a, b := result[i], result[j]
		if a.name == ".." {
			return true
		}
		if b.name == ".." {
			return false
		}
		if a.isDir != b.isDir {
			return a.isDir
		}
		return strings.ToLower(a.name) < strings.ToLower(b.name)
	})

	return result, nil
}

func passesFilter(e fileEntry, filter []string, filterAll bool, dt DialogType) bool {
	// Dirs always pass
	if e.isDir {
		return true
	}
	// For OpenDir, files still shown but can't be selected
	if dt == TypeOpenDir {
		return false
	}
	// No filter = passes
	if len(filter) == 0 {
		return true
	}
	// Override = all files pass
	if filterAll {
		return true
	}
	ext := strings.ToLower(filepath.Ext(e.name))
	for _, f := range filter {
		if strings.ToLower(f) == ext {
			return true
		}
	}
	return false
}

func applyNameFilter(all []fileEntry, query string) []fileEntry {
	if query == "" {
		return all
	}
	q := strings.ToLower(query)
	var result []fileEntry
	for _, e := range all {
		if e.name == ".." || strings.Contains(strings.ToLower(e.name), q) {
			result = append(result, e)
		}
	}
	return result
}

func formatSize(n int64) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	case n < 1024*1024*1024:
		return fmt.Sprintf("%.1f MB", float64(n)/(1024*1024))
	default:
		return fmt.Sprintf("%.1f GB", float64(n)/(1024*1024*1024))
	}
}

func formatModTime(t time.Time) string {
	return t.Format("2006-01-02 15:04:05")
}
