// Package opensslcmd generates the openssl (or keytool) command that reproduces
// an operation certdiag performs. It is a teaching/diagnostic aid: the emitted
// command is behaviourally equivalent, not guaranteed byte-identical. certdiag
// applies defaults (random serial, notBefore backdating, always-on
// subjectKeyIdentifier, PKCS#8 keys) that plain openssl does not, so every
// generator records the relevant caveats as Notes.
package opensslcmd

import "strings"

const (
	ToolOpenSSL = "openssl"
	ToolKeytool = "keytool"
)

const equivalenceHeader = "# openssl equivalent (behaviour, not byte-identical output)"

// Command is a single tool invocation plus the caveats that make it an
// "equivalent" rather than an exact reproduction.
type Command struct {
	Tool  string
	Args  []string
	Notes []string
}

// String renders the command as a single shell-ready line.
func (c Command) String() string {
	parts := make([]string, 0, len(c.Args)+1)
	parts = append(parts, c.Tool)
	for _, a := range c.Args {
		parts = append(parts, shellQuote(a))
	}
	return strings.Join(parts, " ")
}

// Render produces the labelled, copy-pasteable block for a sequence of
// commands: a header, one line per command, then the de-duplicated notes as
// shell comments (so the whole block still pastes into a shell and runs).
func Render(cmds ...Command) string {
	var b strings.Builder
	b.WriteString(equivalenceHeader)
	for _, c := range cmds {
		if c.Tool == "" {
			continue
		}
		b.WriteByte('\n')
		b.WriteString(c.String())
	}
	for _, note := range dedupeNotes(cmds) {
		b.WriteString("\n# note: ")
		b.WriteString(note)
	}
	return b.String()
}

func dedupeNotes(cmds []Command) []string {
	seen := make(map[string]bool)
	var out []string
	for _, c := range cmds {
		for _, n := range c.Notes {
			if seen[n] {
				continue
			}
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		if strings.ContainsRune("@%+=:,./-_", r) {
			continue
		}
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	return s
}
