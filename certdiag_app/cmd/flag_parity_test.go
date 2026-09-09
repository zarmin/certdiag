package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// TestListIsAFullAliasOfRoot guards M7: `list` is documented as an alias of the
// root scan, so every root scan flag must exist on it with the same shorthand.
func TestListIsAFullAliasOfRoot(t *testing.T) {
	rootCmd.LocalNonPersistentFlags().VisitAll(func(f *pflag.Flag) {
		if f.Name == "help" || f.Name == "version" {
			return
		}
		lf := listCmd.LocalNonPersistentFlags().Lookup(f.Name)
		if lf == nil {
			t.Errorf("list lacks root flag --%s", f.Name)
			return
		}
		if lf.Shorthand != f.Shorthand {
			t.Errorf("list --%s shorthand %q, root has %q", f.Name, lf.Shorthand, f.Shorthand)
		}
	})
}

// TestCheckHasTheScanPasswordFlags guards the other half of M7: check reads
// aiaRefresh and the try-all-passwords policy but only root registers them.
func TestCheckHasTheScanPasswordFlags(t *testing.T) {
	for _, name := range []string{"aia-refresh", "no-try-all-passwords"} {
		if checkCmd.LocalNonPersistentFlags().Lookup(name) == nil {
			t.Errorf("check lacks --%s", name)
		}
	}
}

// TestEveryPasswordFlagHasAFileVariant: a password given with -p lands in the
// shell history, so every command that takes -p also takes -P/--password-file.
// `password encrypt` is exempt: its -p is the value to encrypt, not a file
// password.
func TestEveryPasswordFlagHasAFileVariant(t *testing.T) {
	walkCommands(rootCmd, func(c *cobra.Command) {
		if commandPath(c) == "password encrypt" {
			return
		}
		if c.LocalNonPersistentFlags().Lookup("password") == nil {
			return
		}
		f := c.LocalNonPersistentFlags().Lookup("password-file")
		if f == nil {
			t.Errorf("%s has -p but no --password-file", c.CommandPath())
			return
		}
		if f.Shorthand != "P" {
			t.Errorf("%s --password-file shorthand %q, want P", c.CommandPath(), f.Shorthand)
		}
	})
}

// TestStoreSelectionFlagsAreShared: verify, store, remote fetch and remote
// check register the store selection through one type, so the flag names and
// shorthands agree. The documented differences are the only ones: --nss on
// store alone, --trust and --aia on the remote commands alone, -f on store.
func TestStoreSelectionFlagsAreShared(t *testing.T) {
	shared := []string{"java", "java-home", "openssl", "mozilla", "chrome", "trust-file"}
	cmds := map[string]*cobra.Command{
		"verify": verifyCmd, "store": storeCmd, "remote fetch": remoteFetchCmd, "remote check": remoteCheckCmd,
	}
	for name, c := range cmds {
		for _, flag := range shared {
			f := c.LocalNonPersistentFlags().Lookup(flag)
			if f == nil {
				t.Errorf("%s lacks --%s", name, flag)
				continue
			}
			wantShort := ""
			if flag == "trust-file" && name == "store" {
				wantShort = "f"
			}
			if f.Shorthand != wantShort {
				t.Errorf("%s --%s shorthand %q, want %q", name, flag, f.Shorthand, wantShort)
			}
		}
		hasNSS := c.LocalNonPersistentFlags().Lookup("nss") != nil
		if hasNSS != (name == "store") {
			t.Errorf("%s: --nss present=%v, want %v", name, hasNSS, name == "store")
		}
		remote := strings.HasPrefix(name, "remote ")
		for _, flag := range []string{"trust", "aia"} {
			has := c.LocalNonPersistentFlags().Lookup(flag) != nil
			if has != remote {
				t.Errorf("%s: --%s present=%v, want %v", name, flag, has, remote)
			}
		}
	}
}
