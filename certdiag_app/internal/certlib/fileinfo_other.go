//go:build !darwin && !linux && !windows

package certlib

import (
	"os"
	"time"
)

func fileTimesFromInfo(_ os.FileInfo) (time.Time, time.Time) {
	return time.Time{}, time.Time{}
}
