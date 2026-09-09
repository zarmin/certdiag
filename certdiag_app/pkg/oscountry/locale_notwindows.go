//go:build !windows && !darwin

package oscountry

import "os"

// localeEnvVars is the env var order for country detection.
// LC_ALL is intentionally excluded: it is a POSIX display-language override
// (developers set LC_ALL=en_US.UTF-8 for English UI while LANG reflects location).
var localeEnvVars = []string{"LANG", "LC_MESSAGES", "LANGUAGE"}

func detectFromGeoName() Detection {
	return Detection{Source: SourceNone}
}

func DetectFromLocale() Detection {
	for _, env := range localeEnvVars {
		val := os.Getenv(env)
		if val == "" {
			continue
		}
		if code := parseRegionFromLocale(val); code != "" {
			return Detection{Code: code, Source: SourceLocaleEnv, Note: val}
		}
	}
	return Detection{Source: SourceNone}
}
