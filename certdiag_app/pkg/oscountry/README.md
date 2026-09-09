# os_country

Go library that detects the user's country from OS-level signals — locale and timezone — with no external network calls.

## How it works

**macOS** — reads `~/.GlobalPreferences.plist` (`AppleLocale`, `AppleLanguages`); falls back to locale env vars

**Linux / other** — reads `LANG`, `LC_MESSAGES`, `LANGUAGE` env vars

**Windows** — reads `Control Panel\International\LocaleName` from registry; falls back to env vars

**Timezone** — reads `time.Local` / `/etc/localtime` symlink, maps to country via embedded `zone1970.tab`

## Install

```
go get github.com/zarmin/os_country
```

## Usage

```go
// Opinionated single-call entry point
country := oscountry.GuessCountry() // e.g. "HU"

// Or with detail:
results := oscountry.Detect()
locale, tz := results[0], results[1]
fmt.Println(locale.Code, locale.Source, locale.Note)
```

## API

```go
func GuessCountry() string        // ISO 3166-1 alpha-2 best guess
func DetectFromLocale() Detection // locale source only
func DetectFromTimezone() Detection // timezone source only
func Detect() []Detection         // [locale, timezone]

type Detection struct {
    Code   string // e.g. "HU"
    Source Source // where it came from
    Note   string // raw value for debugging
}

type Source string // "locale-env" | "mac-locale" | "mac-languages" | "win-registry" | "timezone" | "none"
```

## GuessCountry heuristic

If locale returns `"US"` (common on developer machines regardless of actual location), it falls back to timezone. Otherwise trusts locale; timezone is last resort.
