package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/cmdutil"
)

func TestLooksLikeRemoteTarget(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"https://example.com", true},
		{"https://example.com/path", true},
		{"tls://host:443", true},
		{"http://example.com", true}, // M12: unsupported scheme still routes to remote (for the right error)
		{"1.2.3.4", true},
		{"10.0.0.1:8443", true},
		{"[::1]:443", true},
		{"localhost", true},
		{"localhost:8080", true},

		{"server.crt", false},  // known cert extension -> file
		{"missing.pem", false}, // known key/cert extension -> file
		{"certs/server.pem", false},
		{"./foo", false},
		{`C:\certs\x.crt`, false},
		{`D:\x`, false}, // drive letter, no extension: a path, not host "D" port "\x"
		{`C:`, false},   // bare drive
		{`C:\`, false},  // drive root
		{`\\server\share\x.pem`, false},
		{"foo", false}, // bare single label, no dot -> treat as path
		{"", false},

		{"request.csr", false},   // M11: CSR is a content type, not a host
		{"backup.tar.gz", false}, // M11: obvious archive file
		{"notes.txt", false},     // M11: obvious text file
		{"config.yaml", false},   // M11: obvious config file
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := looksLikeRemoteTarget(tt.in); got != tt.want {
				t.Errorf("looksLikeRemoteTarget(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestClassifyRootArgs(t *testing.T) {
	dir := t.TempDir()
	existingFile := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(existingFile, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	// A file whose name also looks like a hostname: local must win (stat-first).
	hostNamedFile := filepath.Join(dir, "example.com")
	if err := os.WriteFile(hostNamedFile, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		args       []string
		wantLocal  []string
		wantRemote []string
	}{
		{"existing file is local", []string{existingFile}, []string{existingFile}, nil},
		{"existing dir is local", []string{dir}, []string{dir}, nil},
		{"bare host is remote", []string{"example.com"}, nil, []string{"example.com"}},
		{"missing cert file stays local", []string{"missing.pem"}, []string{"missing.pem"}, nil},
		{"multiple remotes", []string{"example.com", "1.2.3.4"}, nil, []string{"example.com", "1.2.3.4"}},
		{"mixed local and remote", []string{existingFile, "example.com"}, []string{existingFile}, []string{"example.com"}},
		{"local file wins over hostname name", []string{hostNamedFile}, []string{hostNamedFile}, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			local, remote := classifyRootArgs(tt.args)
			if !equalStrings(local, tt.wantLocal) {
				t.Errorf("local = %v, want %v", local, tt.wantLocal)
			}
			if !equalStrings(remote, tt.wantRemote) {
				t.Errorf("remote = %v, want %v", remote, tt.wantRemote)
			}
		})
	}
}

func TestRootFormatToRemote(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{cmdutil.OutputJSON, cmdutil.OutputJSON, false},
		{cmdutil.OutputYAML, cmdutil.OutputYAML, false},
		{cmdutil.OutputList, cmdutil.OutputHuman, false},
		{"", cmdutil.OutputHuman, false},
		// M13: unsupported formats must error, not silently degrade to human.
		{cmdutil.OutputTable, "", true},
		{"jsonpath=$.foo", "", true},
		{"bogus", "", true},
	}
	for _, tt := range tests {
		got, err := rootFormatToRemote(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("rootFormatToRemote(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
		}
		if !tt.wantErr && got != tt.want {
			t.Errorf("rootFormatToRemote(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
