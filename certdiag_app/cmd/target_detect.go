package cmd

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/cmdutil"
)

const (
	localhostName  = "localhost"
	domainLabelSep = "." // separates labels in a dotted domain name
)

// nonRemoteExtensions marks arguments as intended local files (even when
// missing) so a typo'd path is never TLS-dialed. certdiag's own cert/key
// formats are handled separately via certlib.FormatFromExtension.
var nonRemoteExtensions = map[string]bool{
	".csr": true, ".req": true,
	".p8": true, ".pk8": true, ".pub": true,
	".txt": true, ".bin": true, ".dat": true, ".log": true, ".md": true,
	".gz": true, ".tgz": true, ".tar": true, ".zip": true,
	".json": true, ".yaml": true, ".yml": true,
	".conf": true, ".cnf": true, ".cfg": true, ".config": true,
}

// classifyRootArgs splits root/list arguments into local filesystem paths and
// remote targets (hostnames, IPs, URLs). Anything that exists on disk is always
// treated as a local path, so local files win over ambiguous names. Missing
// arguments route to remote inspection only when they clearly look like a
// host/URL/IP.
func classifyRootArgs(args []string) (local, remote []string) {
	for _, a := range args {
		if _, err := os.Stat(a); err == nil {
			local = append(local, a)
			continue
		}
		if looksLikeRemoteTarget(a) {
			remote = append(remote, a)
			continue
		}
		local = append(local, a)
	}
	return local, remote
}

// looksLikeRemoteTarget reports whether raw resembles a remote endpoint rather
// than a filesystem path. It is only consulted for arguments that do not exist
// on disk.
func looksLikeRemoteTarget(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}

	hasScheme := strings.Contains(raw, "://")

	// A URL scheme is an unambiguous remote intent. Route it to the remote path
	// even for schemes certdiag does not support (http://), so the user gets the
	// remote command's "unsupported scheme" message rather than "path not found".
	if hasScheme {
		return true
	}

	// A path separator (no scheme) is a filesystem path, not a host.
	if strings.ContainsAny(raw, `/\`) {
		return false
	}
	// A bare Windows drive ("C:") is a path too, not host "C" with no port.
	if len(raw) == 2 && raw[1] == ':' && unicode.IsLetter(rune(raw[0])) {
		return false
	}

	// A file extension means the user expected a file that happens to be
	// missing (e.g. "missing.pem", "req.csr", "bundle.tar.gz"), not a dotted
	// hostname (e.g. "example.com"). Covers certdiag's own formats plus common
	// non-hostname extensions so a typo'd path is never TLS-dialed.
	if ext := strings.ToLower(filepath.Ext(raw)); ext != "" {
		if _, ok := certlib.FormatFromExtension(ext); ok {
			return false
		}
		if nonRemoteExtensions[ext] {
			return false
		}
	}

	// Must be parseable as a remote target at all.
	if _, err := certlib.ParseTarget(raw); err != nil {
		return false
	}

	// Explicit host:port (a single colon, not a bare IPv6 address).
	if i := strings.LastIndex(raw, ":"); i > 0 && !strings.Contains(raw[:i], ":") {
		return true
	}
	// Bracketed IPv6, a bare IP, localhost, or a dotted domain name.
	if strings.HasPrefix(raw, "[") {
		return true
	}
	if net.ParseIP(raw) != nil {
		return true
	}
	if raw == localhostName {
		return true
	}
	return strings.Contains(raw, domainLabelSep)
}

// rootFormatToRemote maps the root command's --output value onto the remote
// command's accepted formats. Remote inspection supports only human, json, and
// yaml; anything else (table, jsonpath, an unknown value) is rejected rather
// than silently degraded to human, which would break scripting.
func rootFormatToRemote(f string) (string, error) {
	switch f {
	case "", cmdutil.OutputList:
		return cmdutil.OutputHuman, nil
	case cmdutil.OutputJSON:
		return cmdutil.OutputJSON, nil
	case cmdutil.OutputYAML:
		return cmdutil.OutputYAML, nil
	default:
		return "", fmt.Errorf("remote targets support only json or yaml output (omit -o for human-readable); %q is not supported", f)
	}
}
