//go:build !windows

package filepicker

func normalizePathInput(s string) string { return s }
