//go:build linux

package certlib

import (
	"os"
	"syscall"
	"time"
)

func fileTimesFromInfo(info os.FileInfo) (atime, ctime time.Time) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		atime = time.Unix(int64(stat.Atim.Sec), int64(stat.Atim.Nsec))
	}
	return
}
