//go:build windows

package certlib

import (
	"os"
	"syscall"
	"time"
)

func fileTimesFromInfo(info os.FileInfo) (atime, ctime time.Time) {
	if data, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
		atime = time.Unix(0, data.LastAccessTime.Nanoseconds())
		ctime = time.Unix(0, data.CreationTime.Nanoseconds())
	}
	return
}
