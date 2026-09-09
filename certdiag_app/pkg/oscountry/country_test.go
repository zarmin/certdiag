//go:build !windows

package oscountry

import (
	"strings"
	"testing"
)

func TestParseZone1970Tab(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]string
	}{
		{
			name:     "single entry",
			input:    "AD\t+4230+00131\tEurope/Andorra",
			expected: map[string]string{"Europe/Andorra": "AD"},
		},
		{
			name:     "multi-country takes first",
			input:    "AE,OM,RE\t+2518+05518\tAsia/Dubai",
			expected: map[string]string{"Asia/Dubai": "AE"},
		},
		{
			name:     "comment line skipped",
			input:    "# comment\nAD\t+4230+00131\tEurope/Andorra",
			expected: map[string]string{"Europe/Andorra": "AD"},
		},
		{
			name:     "empty lines skipped",
			input:    "\nAD\t+4230+00131\tEurope/Andorra\n\n",
			expected: map[string]string{"Europe/Andorra": "AD"},
		},
		{
			name:     "too few fields",
			input:    "AD\t+4230+00131",
			expected: map[string]string{},
		},
		{
			name:  "multiple entries",
			input: "AD\t+4230+00131\tEurope/Andorra\nHU\t+4730+01905\tEurope/Budapest",
			expected: map[string]string{
				"Europe/Andorra":  "AD",
				"Europe/Budapest": "HU",
			},
		},
		{
			name:     "empty input",
			input:    "",
			expected: map[string]string{},
		},
		{
			name:     "whitespace trimmed",
			input:    "AD \t+4230+00131\t Europe/Andorra ",
			expected: map[string]string{"Europe/Andorra": "AD"},
		},
		{
			name:     "fourth field ignored",
			input:    "US\t+404251\tAmerica/New_York\tEastern",
			expected: map[string]string{"America/New_York": "US"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseZone1970Tab(tt.input)
			if len(got) != len(tt.expected) {
				t.Errorf("parseZone1970Tab(%q) returned %d entries, want %d", tt.input, len(got), len(tt.expected))
				return
			}
			for zone, wantCode := range tt.expected {
				if gotCode, ok := got[zone]; !ok {
					t.Errorf("parseZone1970Tab(%q) missing key %q", tt.input, zone)
				} else if gotCode != wantCode {
					t.Errorf("parseZone1970Tab(%q)[%q] = %q, want %q", tt.input, zone, gotCode, wantCode)
				}
			}
		})
	}
}

func TestParseRegionFromLocale(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"underscore + encoding", "en_US.UTF-8", "US"},
		{"underscore no encoding", "de_DE", "DE"},
		{"hyphen format", "en-US", "US"},
		{"hyphen lowercase", "en-gb", "GB"},
		{"C locale", "C", ""},
		{"POSIX locale", "POSIX", ""},
		{"empty string", "", ""},
		{"colon-separated list", "de_AT:en_US:hu_HU", "AT"},
		{"language only no region", "en", ""},
		{"three-letter region rejected", "en_USA", ""},
		{"whitespace padded", "  en_US  ", "US"},
		{"lowercase encoding suffix", "hu_HU.utf8", "HU"},
		{"colon + encoding combined", "de_AT.UTF-8:en_US.UTF-8", "AT"},
		{"numeric region rejected", "en_12", ""},
		{"unusual but valid 2-letter code", "en_XX", "XX"},
		{"modifier only", "de_DE@euro", "DE"},
		{"encoding + modifier", "de_DE.UTF-8@euro", "DE"},
		{"modifier hyphen format", "en_US@foo", "US"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseRegionFromLocale(tt.input)
			if got != tt.want {
				t.Errorf("parseRegionFromLocale(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractZoneFromSymlink(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"standard linux path", "/usr/share/zoneinfo/America/New_York", "America/New_York"},
		{"macOS path", "/var/db/timezone/zoneinfo/Europe/Budapest", "Europe/Budapest"},
		{"deep zone 3 components", "/usr/share/zoneinfo/America/Argentina/Buenos_Aires", "America/Argentina/Buenos_Aires"},
		{"single component rejected", "/usr/share/zoneinfo/UTC", ""},
		{"no zoneinfo marker", "/some/random/path", ""},
		{"empty path", "", ""},
		{"double zoneinfo uses LastIndex", "/a/zoneinfo/b/zoneinfo/Asia/Tokyo", "Asia/Tokyo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractZoneFromSymlink(tt.input)
			if got != tt.want {
				t.Errorf("extractZoneFromSymlink(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestTimezoneToCountryMap(t *testing.T) {
	if len(timezoneToCountry) < 300 {
		t.Errorf("timezoneToCountry has %d entries, want > 300", len(timezoneToCountry))
	}
	checks := map[string]string{
		"America/New_York": "US",
		"Europe/Budapest":  "HU",
		"Asia/Dubai":       "AE",
	}
	for zone, wantCode := range checks {
		if got := timezoneToCountry[zone]; got != wantCode {
			t.Errorf("timezoneToCountry[%q] = %q, want %q", zone, got, wantCode)
		}
	}
}

func TestDetectFromTimezone(t *testing.T) {
	det := DetectFromTimezone()

	if det.Code == "" {
		t.Fatal("DetectFromTimezone() returned empty Code")
	}
	if det.Source != SourceTimezone {
		t.Errorf("DetectFromTimezone().Source = %q, want %q", det.Source, SourceTimezone)
	}
	if !strings.Contains(det.Note, "/") {
		t.Errorf("DetectFromTimezone().Note = %q, want it to contain /", det.Note)
	}
	if len(det.Code) != 2 || det.Code != strings.ToUpper(det.Code) {
		t.Errorf("DetectFromTimezone().Code = %q, want 2-letter uppercase", det.Code)
	}
}

func TestDetectFromLocale(t *testing.T) {
	det := DetectFromLocale()

	if det.Code == "" {
		t.Fatal("DetectFromLocale() returned empty Code")
	}
	validSources := map[Source]bool{
		SourceMacLocale:    true,
		SourceMacLanguages: true,
		SourceLocaleEnv:    true,
	}
	if !validSources[det.Source] {
		t.Errorf("DetectFromLocale().Source = %q, want one of mac-locale, mac-languages, locale-env", det.Source)
	}
	if len(det.Code) != 2 || det.Code != strings.ToUpper(det.Code) {
		t.Errorf("DetectFromLocale().Code = %q, want 2-letter uppercase", det.Code)
	}
	if det.Note == "" {
		t.Error("DetectFromLocale().Note is empty, want non-empty")
	}
}

func TestLocaleEnvVars(t *testing.T) {
	want := []string{"LANG", "LC_MESSAGES", "LANGUAGE"}
	if len(localeEnvVars) != len(want) {
		t.Fatalf("localeEnvVars has %d entries, want %d", len(localeEnvVars), len(want))
	}
	for i, v := range want {
		if localeEnvVars[i] != v {
			t.Errorf("localeEnvVars[%d] = %q, want %q", i, localeEnvVars[i], v)
		}
	}
}

func TestDetect(t *testing.T) {
	result := Detect()
	if len(result) != 2 {
		t.Fatalf("Detect() returned %d detections, want 2", len(result))
	}

	localeSources := map[Source]bool{
		SourceMacLocale:    true,
		SourceMacLanguages: true,
		SourceLocaleEnv:    true,
		SourceNone:         true,
	}
	if !localeSources[result[0].Source] {
		t.Errorf("Detect()[0].Source = %q, want a locale source", result[0].Source)
	}

	tzSources := map[Source]bool{
		SourceTimezone: true,
		SourceNone:     true,
	}
	if !tzSources[result[1].Source] {
		t.Errorf("Detect()[1].Source = %q, want a timezone source", result[1].Source)
	}
}

func TestGuessCountry(t *testing.T) {
	code := GuessCountry()
	if code == "" {
		t.Fatal("GuessCountry() returned empty string")
	}
	if len(code) != 2 || code != strings.ToUpper(code) {
		t.Errorf("GuessCountry() = %q, want 2-letter uppercase", code)
	}
}

func TestSourceConstants(t *testing.T) {
	checks := map[Source]string{
		SourceLocaleEnv:    "locale-env",
		SourceMacLocale:    "mac-locale",
		SourceMacLanguages: "mac-languages",
		SourceWinRegistry:  "win-registry",
		SourceTimezone:     "timezone",
		SourceNone:         "none",
	}
	for src, want := range checks {
		if string(src) != want {
			t.Errorf("Source constant %v = %q, want %q", src, string(src), want)
		}
	}
}
