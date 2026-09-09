package stringutil

import (
	"regexp"
	"strings"
)

var unsafeChars = regexp.MustCompile(`[^a-z0-9._\-]`)
var multiDash = regexp.MustCompile(`[\-_]{2,}`)
var aliasUnsafe = regexp.MustCompile(`[^a-z0-9-]`)

func NormalizeName(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, " ", "-")
	s = unsafeChars.ReplaceAllString(s, "")
	s = multiDash.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-_")
	return s
}

func SanitizeAlias(cn string) string {
	s := strings.ToLower(cn)
	s = aliasUnsafe.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return "entry"
	}
	return s
}

func SanitizeFilename(s string) string {
	replacer := strings.NewReplacer(
		"/", "_", "\\", "_", ":", "_", "*", "_",
		"?", "_", "\"", "_", "<", "_", ">", "_",
		"|", "_", " ", "_",
	)
	return replacer.Replace(s)
}
