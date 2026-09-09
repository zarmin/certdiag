package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/term"
)

const (
	// DirName is the per-user certdiag directory under $HOME.
	DirName = ".certdiag"
	// FileName is the config file inside DirName.
	FileName = "certdiag.yaml"
	// BundleDirName holds installed root CA snapshots.
	BundleDirName = "bundles"
	// AIACacheDirName holds issuer certificates fetched over AIA.
	AIACacheDirName = "aia"
	// LegacyFileName is the single dotfile used before the directory layout.
	LegacyFileName = ".certdiag.yaml"
)

// Dir returns ~/.certdiag. It does not create the directory.
func Dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not determine home directory: %w", err)
	}
	return filepath.Join(home, DirName), nil
}

// BundleDir returns ~/.certdiag/bundles, where `certdiag store update` installs
// refreshed root snapshots. It does not create the directory.
func BundleDir() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, BundleDirName), nil
}

// AIACacheDir returns ~/.certdiag/aia, where fetched issuer certificates are
// remembered when the cache is enabled.
func AIACacheDir() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, AIACacheDirName), nil
}

// DefaultConfigPath returns ~/.certdiag/certdiag.yaml.
func DefaultConfigPath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, FileName), nil
}

// LegacyConfigPath returns ~/.certdiag.yaml.
func LegacyConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not determine home directory: %w", err)
	}
	return filepath.Join(home, LegacyFileName), nil
}

// resolvePath implements the documented order: explicit flag, CERTDIAG_CONFIG,
// the directory layout, then the legacy dotfile. The legacy file is never
// moved automatically -- it can hold passwords, and silently relocating it
// during an unrelated scan is exactly the surprise a diagnostic tool must not
// spring.
func resolvePath(configPath string) (path string, explicit bool, legacy bool, err error) {
	if configPath != "" {
		return configPath, true, false, nil
	}
	if env := os.Getenv("CERTDIAG_CONFIG"); env != "" {
		return env, true, false, nil
	}

	preferred, err := DefaultConfigPath()
	if err != nil {
		return "", false, false, err
	}
	if fileExists(preferred) {
		return preferred, false, false, nil
	}

	if old, err := LegacyConfigPath(); err == nil && fileExists(old) {
		return old, false, true, nil
	}

	return preferred, false, false, nil
}

// ResolveConfigPath returns the config file in effect, which is also where
// writes go. When only the legacy dotfile exists it stays in effect, so an edit
// never lands in a file that is not being read.
func ResolveConfigPath(configPath string) (string, error) {
	path, _, _, err := resolvePath(configPath)
	return path, err
}

// UsingLegacyConfig reports whether the legacy dotfile is the one in effect.
func UsingLegacyConfig(configPath string) bool {
	_, _, legacy, err := resolvePath(configPath)
	return err == nil && legacy
}

var legacyNoticeOnce sync.Once

// noteLegacyConfig prints the migration hint at most once per process, and only
// to a terminal, so piped and -o json use stays clean.
func noteLegacyConfig(path string) {
	legacyNoticeOnce.Do(func() {
		if !term.IsTerminal(int(os.Stderr.Fd())) {
			return
		}
		preferred, err := DefaultConfigPath()
		if err != nil {
			return
		}
		fmt.Fprintf(os.Stderr,
			"certdiag: using legacy config %s; the current location is %s (run 'certdiag config migrate' to move it)\n",
			path, preferred)
	})
}

func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}
