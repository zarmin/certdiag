package stringutil

import "testing"

func TestNormalizeName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"lowercase", "MyServer", "myserver"},
		{"spaces to hyphens", "my server name", "my-server-name"},
		{"unsafe chars removed", "hello@world!", "helloworld"},
		{"multi dash collapsed", "a--b__c", "a-b-c"},
		{"leading trailing trimmed", "-hello-", "hello"},
		{"dots and underscores kept", "my.server_name", "my.server_name"},
		{"empty input", "", ""},
		{"already clean", "clean-name.test", "clean-name.test"},
		{"mixed special chars", " --My Server #1! ", "my-server-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeName(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSanitizeAlias(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"lowercase", "MyAlias", "myalias"},
		{"unsafe to hyphens", "hello@world.com", "hello-world-com"},
		{"leading trailing hyphens trimmed", "!!hello!!", "hello"},
		{"empty returns entry", "", "entry"},
		{"digits kept", "server123", "server123"},
		{"already clean", "clean-alias", "clean-alias"},
		{"uppercase with spaces", "My Cool Server", "my-cool-server"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeAlias(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeAlias(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"forward slash", "path/to/file", "path_to_file"},
		{"backslash", "path\\to\\file", "path_to_file"},
		{"colon", "C:file", "C_file"},
		{"wildcards and question mark", "file*.txt?", "file_.txt_"},
		{"quotes", `say "hello"`, "say__hello_"},
		{"angle brackets and pipe", "<in>|out", "_in__out"},
		{"spaces", "my file name", "my_file_name"},
		{"clean passthrough", "clean-file.pem", "clean-file.pem"},
		{"multiple replacements", `a/b\c:d*e?f"g<h>i|j k`, "a_b_c_d_e_f_g_h_i_j_k"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeFilename(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeFilename(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
