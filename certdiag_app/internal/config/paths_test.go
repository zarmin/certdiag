package config

import (
	"os"
	"path/filepath"
	"testing"
)

const validConfig = "kind: certdiag-config\nversion: \"1\"\npasswords:\n  common_plaintext: [test]\n"

// isolatedHome points HOME (and USERPROFILE on Windows) at a temp directory, so
// no test can read or create anything in the developer's real home.
func isolatedHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CERTDIAG_CONFIG", "")
	return home
}

func writeConfig(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(validConfig), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPaths_Layout(t *testing.T) {
	home := isolatedHome(t)

	dir, err := Dir()
	if err != nil {
		t.Fatal(err)
	}
	if dir != filepath.Join(home, DirName) {
		t.Errorf("expected %s, got %s", filepath.Join(home, DirName), dir)
	}

	bundles, err := BundleDir()
	if err != nil {
		t.Fatal(err)
	}
	if bundles != filepath.Join(home, DirName, BundleDirName) {
		t.Errorf("expected the bundles directory under the config directory, got %s", bundles)
	}

	cfg, err := DefaultConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	if cfg != filepath.Join(home, DirName, FileName) {
		t.Errorf("expected %s, got %s", filepath.Join(home, DirName, FileName), cfg)
	}

	legacy, err := LegacyConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	if legacy != filepath.Join(home, LegacyFileName) {
		t.Errorf("expected %s, got %s", filepath.Join(home, LegacyFileName), legacy)
	}

	// Nothing may be created merely by asking where things live.
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("resolving paths must not create the directory")
	}
}

// TestResolveConfigPath_Order walks the four documented branches in order.
func TestResolveConfigPath_Order(t *testing.T) {
	t.Run("explicit flag wins", func(t *testing.T) {
		home := isolatedHome(t)
		writeConfig(t, filepath.Join(home, DirName, FileName))
		t.Setenv("CERTDIAG_CONFIG", filepath.Join(home, "from-env.yaml"))

		explicit := filepath.Join(home, "from-flag.yaml")
		got, err := ResolveConfigPath(explicit)
		if err != nil {
			t.Fatal(err)
		}
		if got != explicit {
			t.Errorf("expected the flag path, got %s", got)
		}
	})

	t.Run("env wins over the directory layout", func(t *testing.T) {
		home := isolatedHome(t)
		writeConfig(t, filepath.Join(home, DirName, FileName))

		env := filepath.Join(home, "from-env.yaml")
		t.Setenv("CERTDIAG_CONFIG", env)

		got, err := ResolveConfigPath("")
		if err != nil {
			t.Fatal(err)
		}
		if got != env {
			t.Errorf("expected the env path, got %s", got)
		}
	})

	t.Run("directory layout wins over legacy", func(t *testing.T) {
		home := isolatedHome(t)
		writeConfig(t, filepath.Join(home, DirName, FileName))
		writeConfig(t, filepath.Join(home, LegacyFileName))

		got, err := ResolveConfigPath("")
		if err != nil {
			t.Fatal(err)
		}
		if got != filepath.Join(home, DirName, FileName) {
			t.Errorf("expected the new layout to win, got %s", got)
		}
		if UsingLegacyConfig("") {
			t.Error("the legacy file must not be in effect when the new one exists")
		}
	})

	t.Run("legacy is the fallback", func(t *testing.T) {
		home := isolatedHome(t)
		writeConfig(t, filepath.Join(home, LegacyFileName))

		got, err := ResolveConfigPath("")
		if err != nil {
			t.Fatal(err)
		}
		if got != filepath.Join(home, LegacyFileName) {
			t.Errorf("expected the legacy path, got %s", got)
		}
		if !UsingLegacyConfig("") {
			t.Error("expected the legacy file to be reported as in effect")
		}
	})

	t.Run("nothing exists yet", func(t *testing.T) {
		home := isolatedHome(t)

		got, err := ResolveConfigPath("")
		if err != nil {
			t.Fatal(err)
		}
		if got != filepath.Join(home, DirName, FileName) {
			t.Errorf("a fresh machine must resolve to the new layout, got %s", got)
		}
		if UsingLegacyConfig("") {
			t.Error("nothing exists, so nothing is legacy")
		}
	})
}

// TestResolveConfigPath_WriteTargetFollowsRead: when only the legacy file
// exists, a write must land there. Otherwise an edit would go into a file that
// is not being read.
func TestResolveConfigPath_WriteTargetFollowsRead(t *testing.T) {
	home := isolatedHome(t)
	legacy := filepath.Join(home, LegacyFileName)
	writeConfig(t, legacy)

	read, err := ResolveConfigPath("")
	if err != nil {
		t.Fatal(err)
	}
	if read != legacy {
		t.Fatalf("expected the legacy path in effect, got %s", read)
	}

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("the legacy config must still load: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected the legacy config to be parsed")
	}
	if len(cfg.Passwords.CommonPlaintext) != 1 {
		t.Errorf("expected the legacy contents, got %+v", cfg.Passwords)
	}
}

func TestLoadConfig_FromEachLocation(t *testing.T) {
	t.Run("new layout", func(t *testing.T) {
		home := isolatedHome(t)
		writeConfig(t, filepath.Join(home, DirName, FileName))

		cfg, err := LoadConfig("")
		if err != nil {
			t.Fatal(err)
		}
		if cfg == nil {
			t.Fatal("expected the config to load from the new layout")
		}
	})

	t.Run("explicit path", func(t *testing.T) {
		home := isolatedHome(t)
		path := filepath.Join(home, "custom.yaml")
		writeConfig(t, path)

		cfg, err := LoadConfig(path)
		if err != nil {
			t.Fatal(err)
		}
		if cfg == nil {
			t.Fatal("expected the config to load from an explicit path")
		}
	})

	t.Run("explicit missing path is an error", func(t *testing.T) {
		home := isolatedHome(t)
		// An explicit path that does not exist must fail rather than silently
		// creating a template, or a typo would look like an empty config.
		if _, err := LoadConfig(filepath.Join(home, "nope.yaml")); err == nil {
			t.Error("expected an error for an explicit missing path")
		}
	})
}

// TestLoadConfig_MissingFileWritesNothing: a read-only diagnostic never creates
// a file in $HOME on its own. A missing default config means defaults, and
// `config init` is the only way to get the template written.
func TestLoadConfig_MissingFileWritesNothing(t *testing.T) {
	home := isolatedHome(t)

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Errorf("expected nil config for a missing file, got %+v", cfg)
	}
	if _, err := os.Stat(filepath.Join(home, DirName)); !os.IsNotExist(err) {
		t.Errorf("loading must not create %s", filepath.Join(home, DirName))
	}
	if _, err := os.Stat(filepath.Join(home, LegacyFileName)); !os.IsNotExist(err) {
		t.Error("loading must not create the legacy file either")
	}
}

// TestLoadConfig_NeverMovesLegacy: the legacy file can hold passwords.
// Relocating it during an unrelated scan is exactly the surprise a diagnostic
// tool must not spring.
func TestLoadConfig_NeverMovesLegacy(t *testing.T) {
	home := isolatedHome(t)
	legacy := filepath.Join(home, LegacyFileName)
	writeConfig(t, legacy)

	for i := 0; i < 3; i++ {
		if _, err := LoadConfig(""); err != nil {
			t.Fatalf("load %d: %v", i, err)
		}
	}

	if _, err := os.Stat(legacy); err != nil {
		t.Errorf("the legacy file must survive untouched: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, DirName, FileName)); !os.IsNotExist(err) {
		t.Error("loading must not create the new file while the legacy one is in effect")
	}
}

func TestUsingLegacyConfig_ExplicitPathIsNeverLegacy(t *testing.T) {
	home := isolatedHome(t)
	writeConfig(t, filepath.Join(home, LegacyFileName))

	// An explicitly chosen file is whatever the user asked for, legacy or not.
	if UsingLegacyConfig(filepath.Join(home, LegacyFileName)) {
		t.Error("an explicit path must not be reported as the legacy fallback")
	}
}

func TestFileExists(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if !fileExists(file) {
		t.Error("expected true for a file")
	}
	if fileExists(dir) {
		t.Error("a directory is not a config file")
	}
	if fileExists(filepath.Join(dir, "nope")) {
		t.Error("expected false for a missing path")
	}
}

// TestEnvPointsAtAFile documents the compatibility promise: CERTDIAG_CONFIG
// keeps naming a file, not the new directory, so scripted and CI use is
// untouched by the layout change.
func TestEnvPointsAtAFile(t *testing.T) {
	home := isolatedHome(t)
	path := filepath.Join(home, "ci-config.yaml")
	writeConfig(t, path)
	t.Setenv("CERTDIAG_CONFIG", path)

	got, err := ResolveConfigPath("")
	if err != nil {
		t.Fatal(err)
	}
	if got != path {
		t.Errorf("expected the env file, got %s", got)
	}
	if cfg, err := LoadConfig(""); err != nil || cfg == nil {
		t.Errorf("expected the env config to load: %v", err)
	}
}
