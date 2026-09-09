package cmd

import (
	"strings"
	"testing"
)

// TestRemoteMalformedTargetsAndRootFlagsExitOne guards M6 and H9: a target the parser rejects
// and a root flag that has no remote meaning are usage errors (exit 1), never
// connection errors (exit 3), and no connection is attempted.
func TestRemoteMalformedTargetsAndRootFlagsExitOne(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"remote check http scheme", []string{"remote", "check", "http://example.invalid"}, "unsupported scheme"},
		{"remote fetch ftp scheme", []string{"remote", "fetch", "ftp://example.invalid"}, "unsupported scheme"},
		{"remote probe bad port", []string{"remote", "probe", "example.invalid:notaport"}, "port"},
		{"root autodetect http scheme", []string{"http://example.invalid"}, "unsupported scheme"},
		{"root --trust on remote", []string{"--trust", "https://127.0.0.1:1"}, "--trust does not apply to remote targets"},
		{"root --aia on remote", []string{"--aia", "https://127.0.0.1:1"}, "--aia does not apply to remote targets"},
		{"remote fetch empty --hostname", []string{"remote", "fetch", "--hostname", "", "https://127.0.0.1:1"}, "use --no-sni"},
		{"remote fetch --hostname with --no-sni", []string{"remote", "fetch", "--hostname", "a", "--no-sni", "https://127.0.0.1:1"}, "mutually exclusive"},
		{"verify empty --hostname", []string{"verify", "--hostname", "", "127.0.0.1:1"}, "use --no-sni"},
		{"verify bare name is a file, never dialed", []string{"verify", "example.invalid"}, "host:port"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, code := runInDir(t, t.TempDir(), tc.args...)
			if code != 1 {
				t.Errorf("exit %d, want 1\n%s", code, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("output lacks %q:\n%s", tc.want, out)
			}
		})
	}
}
