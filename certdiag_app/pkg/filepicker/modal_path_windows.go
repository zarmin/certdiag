//go:build windows

package filepicker

import "strings"

func normalizePathInput(s string) string { return strings.ReplaceAll(s, `\`, `/`) }
