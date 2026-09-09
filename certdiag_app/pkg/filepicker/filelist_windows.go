//go:build windows

package filepicker

import (
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

func isHiddenFile(name, fullPath string) bool {
	if strings.HasPrefix(name, ".") {
		return true
	}
	p, err := syscall.UTF16PtrFromString(fullPath)
	if err != nil {
		return false
	}
	attrs, err := syscall.GetFileAttributes(p)
	if err != nil {
		return false
	}
	return attrs&syscall.FILE_ATTRIBUTE_HIDDEN != 0
}

func isDriveReady(path string) bool {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	var free, total, totalFree uint64
	err = windows.GetDiskFreeSpaceEx(p, &free, &total, &totalFree)
	return err == nil
}

func listWindowsDrives() []fileEntry {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil
	}
	var drives []fileEntry
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) != 0 {
			path := string(rune('A'+i)) + `:\`
			drives = append(drives, fileEntry{
				name:         path,
				isDir:        true,
				passesFilter: true,
				disabled:     !isDriveReady(path),
			})
		}
	}
	return drives
}

// isDriveRoot reports whether dir is a Windows drive root (e.g. "C:\" or "C:/").
func isDriveRoot(dir string) bool {
	return len(dir) == 3 && dir[1] == ':'
}

func listReadyDriveBookmarks() []Bookmark {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil
	}
	var bms []Bookmark
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) != 0 {
			path := string(rune('A'+i)) + `:\`
			if isDriveReady(path) {
				bms = append(bms, Bookmark{Label: path, Path: path})
			}
		}
	}
	return bms
}
