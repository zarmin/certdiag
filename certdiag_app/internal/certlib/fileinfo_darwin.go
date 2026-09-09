//go:build darwin

package certlib

import (
	"os"
	"syscall"
	"time"
)

func fileTimesFromInfo(info os.FileInfo) (atime, ctime time.Time) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		atime = time.Unix(stat.Atimespec.Sec, stat.Atimespec.Nsec)
		ctime = time.Unix(stat.Birthtimespec.Sec, stat.Birthtimespec.Nsec)
	}
	return
}
