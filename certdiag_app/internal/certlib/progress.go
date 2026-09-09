package certlib

import "sync/atomic"

type ScanProgress struct {
	DirsScanned    atomic.Int64
	FilesProbed    atomic.Int64
	PasswordChecks atomic.Int64
}
