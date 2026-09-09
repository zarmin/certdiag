//go:build darwin

package oscountry

import (
	"os"
	"path/filepath"

	"howett.net/plist"
)

var localeEnvVars = []string{"LANG", "LC_MESSAGES", "LANGUAGE"}

func detectFromGeoName() Detection {
	return Detection{Source: SourceNone}
}

func DetectFromLocale() Detection {
	prefs, err := readGlobalPrefs()
	if err == nil {
		if raw, ok := prefs["AppleLocale"].(string); ok {
			if code := parseRegionFromLocale(raw); code != "" {
				return Detection{Code: code, Source: SourceMacLocale, Note: raw}
			}
		}
		if arr, ok := prefs["AppleLanguages"].([]any); ok && len(arr) > 0 {
			if raw, ok := arr[0].(string); ok {
				if code := parseRegionFromLocale(raw); code != "" {
					return Detection{Code: code, Source: SourceMacLanguages, Note: raw}
				}
			}
		}
	}

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

func readGlobalPrefs() (map[string]any, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(home, "Library", "Preferences", ".GlobalPreferences.plist"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var prefs map[string]any
	err = plist.NewDecoder(f).Decode(&prefs)
	return prefs, err
}
