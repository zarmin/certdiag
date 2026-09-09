package oscountry

import (
	_ "embed"
	"os"
	"strings"
	"time"

	"golang.org/x/text/language"
)

//go:embed zone1970.tab
var zone1970TabData string

var timezoneToCountry map[string]string

func init() {
	timezoneToCountry = parseZone1970Tab(zone1970TabData)
}

func parseZone1970Tab(data string) map[string]string {
	m := make(map[string]string)
	for _, line := range strings.Split(data, "\n") {
		if line == "" || line[0] == '#' {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 3 {
			continue
		}
		codes := strings.SplitN(fields[0], ",", 2)
		country := strings.TrimSpace(codes[0])
		zone := strings.TrimSpace(fields[2])
		if country != "" && zone != "" {
			m[zone] = country
		}
	}
	return m
}

type Source string

const (
	SourceLocaleEnv    Source = "locale-env"
	SourceMacLocale    Source = "mac-locale"    // defaults read -g AppleLocale
	SourceMacLanguages Source = "mac-languages" // defaults read -g AppleLanguages
	SourceWinRegistry  Source = "win-registry"
	SourceWinGeo       Source = "win-geo"
	SourceTimezone     Source = "timezone"
	SourceNone         Source = "none"
)

type Detection struct {
	Code   string
	Source Source
	Note   string
}

// parseRegionFromLocale extracts and validates an ISO 3166 alpha-2 country code
// from a locale string like "en_US.UTF-8", "de_DE", or "en-US".
func parseRegionFromLocale(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "C" || s == "POSIX" {
		return ""
	}
	// LANGUAGE may be colon-separated list — take first
	if idx := strings.Index(s, ":"); idx >= 0 {
		s = s[:idx]
	}
	// Strip modifier suffix (@euro, @cyrillic, etc.)
	if idx := strings.Index(s, "@"); idx >= 0 {
		s = s[:idx]
	}
	// Strip encoding suffix (.UTF-8, .utf8, etc.)
	if idx := strings.Index(s, "."); idx >= 0 {
		s = s[:idx]
	}
	// Split on _ or - to get the region part
	var region string
	if idx := strings.Index(s, "_"); idx >= 0 {
		region = s[idx+1:]
	} else if idx := strings.Index(s, "-"); idx >= 0 {
		region = s[idx+1:]
	} else {
		return ""
	}
	code := strings.ToUpper(region)
	if len(code) != 2 {
		return ""
	}
	r, err := language.ParseRegion(code)
	if err != nil {
		return ""
	}
	return strings.ToUpper(r.String())
}

func DetectFromTimezone() Detection {
	// time.Local respects the TZ env var if set explicitly.
	tz := time.Local.String()
	if tz != "" && tz != "UTC" && tz != "Local" {
		if code, ok := timezoneToCountry[tz]; ok {
			return Detection{Code: code, Source: SourceTimezone, Note: tz}
		}
		// Zone recognized by Go but not in our map — fall through to symlink.
	}
	// /etc/localtime symlink: covers macOS where time.Local.String() returns
	// "Local" when TZ env is not set (macOS manages timezone natively).
	if link, err := os.Readlink("/etc/localtime"); err == nil {
		zone := extractZoneFromSymlink(link)
		if zone != "" {
			if code, ok := timezoneToCountry[zone]; ok {
				return Detection{Code: code, Source: SourceTimezone, Note: zone}
			}
			return Detection{Source: SourceNone, Note: zone}
		}
	}
	return Detection{Source: SourceNone, Note: tz}
}

func extractZoneFromSymlink(path string) string {
	const marker = "/zoneinfo/"
	idx := strings.LastIndex(path, marker)
	if idx < 0 {
		return ""
	}
	zone := path[idx+len(marker):]
	if !strings.Contains(zone, "/") {
		return "" // single-component zones (e.g. "UTC") are not useful
	}
	return zone
}

func Detect() []Detection {
	return []Detection{
		DetectFromLocale(),
		DetectFromTimezone(),
	}
}

func GuessCountry() string {
	geo := detectFromGeoName()
	if geo.Code != "" {
		return geo.Code
	}
	locale := DetectFromLocale()
	tz := DetectFromTimezone()
	if locale.Code == "US" {
		if tz.Code != "" {
			return tz.Code
		}
		return locale.Code
	}
	if locale.Code != "" {
		return locale.Code
	}
	return tz.Code
}
