//go:build windows

package oscountry

import (
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

var (
	kernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procGetUserDefaultGeoName = kernel32.NewProc("GetUserDefaultGeoName")
)

func detectFromGeoName() Detection {
	if err := procGetUserDefaultGeoName.Find(); err != nil {
		return Detection{Source: SourceNone}
	}
	buf := make([]uint16, 10)
	n, _, _ := procGetUserDefaultGeoName.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if n == 0 {
		return Detection{Source: SourceNone}
	}
	code := syscall.UTF16ToString(buf[:n])
	if len(code) == 2 {
		return Detection{Code: strings.ToUpper(code), Source: SourceWinGeo, Note: code}
	}
	return Detection{Source: SourceNone}
}

var localeEnvVars = []string{"LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"}

func DetectFromLocale() Detection {
	for _, env := range localeEnvVars {
		val := os.Getenv(env)
		if val == "" {
			continue
		}
		code := parseRegionFromLocale(val)
		if code != "" {
			return Detection{Code: code, Source: SourceLocaleEnv, Note: val}
		}
	}

	k, err := registry.OpenKey(registry.CURRENT_USER, `Control Panel\International`, registry.QUERY_VALUE)
	if err == nil {
		defer k.Close()
		val, _, err := k.GetStringValue("LocaleName")
		if err == nil {
			raw := strings.TrimSpace(val)
			code := parseRegionFromLocale(raw)
			if code != "" {
				return Detection{Code: code, Source: SourceWinRegistry, Note: raw}
			}
		}
	}

	return Detection{Source: SourceNone}
}
