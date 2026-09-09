//go:build !windows

package filepicker

import "strings"

func isHiddenFile(name, _ string) bool {
	return strings.HasPrefix(name, ".")
}

func isDriveRoot(_ string) bool { return false }

func listWindowsDrives() []fileEntry { return nil }

func listReadyDriveBookmarks() []Bookmark { return nil }
