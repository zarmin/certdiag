package truststore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// BundleCert is one certificate destined for a root bundle.
type BundleCert struct {
	Label string
	DER   []byte
}

// ParsedBundle is the result of parsing a vendor's published root list.
// Distrusted entries are kept deliberately: they are the records that make a
// distrust event visible, and dropping them would leave the bundle silently
// more permissive than the vendor's list.
type ParsedBundle struct {
	Trusted    []BundleCert
	Distrusted []BundleCert
	Revision   string
	Caveats    []string
}

// --- Mozilla certdata.txt ---

type certdataObject struct {
	class  string
	label  string
	attrs  map[string][]byte
	trusts map[string]string
}

// ParseCertdata parses the NSS builtin trust list. Certificates carry their DER
// in CKA_VALUE; trust records are separate objects joined by CKA_CERT_SHA1_HASH.
func ParseCertdata(data []byte) (*ParsedBundle, error) {
	objects, err := parseCertdataObjects(string(data))
	if err != nil {
		return nil, err
	}

	type certEntry struct {
		label string
		der   []byte
		sha1  string
	}

	var certs []certEntry
	trustBySHA1 := make(map[string]map[string]string)

	for _, obj := range objects {
		switch obj.class {
		case "CKO_CERTIFICATE":
			der := obj.attrs["CKA_VALUE"]
			if len(der) == 0 {
				continue
			}
			certs = append(certs, certEntry{
				label: obj.label,
				der:   der,
				sha1:  hex.EncodeToString(sha1Sum(der)),
			})
		case "CKO_NSS_TRUST":
			h := obj.attrs["CKA_CERT_SHA1_HASH"]
			if len(h) == 0 {
				continue
			}
			trustBySHA1[hex.EncodeToString(h)] = obj.trusts
		}
	}

	out := &ParsedBundle{Revision: certdataRevision(string(data))}

	for _, c := range certs {
		trust := trustBySHA1[c.sha1]
		serverAuth := trust["CKA_TRUST_SERVER_AUTH"]

		switch serverAuth {
		case "CKT_NSS_TRUSTED_DELEGATOR", "CKT_NSS_TRUSTED", "CKT_NSS_VALID_DELEGATOR":
			out.Trusted = append(out.Trusted, BundleCert{Label: c.label, DER: c.der})
		case "CKT_NSS_NOT_TRUSTED":
			out.Distrusted = append(out.Distrusted, BundleCert{Label: c.label, DER: c.der})
		default:
			// Trusted for some other purpose only (email, code signing) or not
			// trusted for server auth. Not a TLS anchor, so it is neither
			// shipped as trusted nor claimed as distrusted.
			if isDistrustedForAnyPurpose(trust) {
				out.Distrusted = append(out.Distrusted, BundleCert{Label: c.label, DER: c.der})
			}
		}
	}

	if len(out.Trusted) == 0 {
		return nil, fmt.Errorf("certdata.txt yielded no server-auth trust anchors")
	}

	out.Caveats = append(out.Caveats,
		"name constraints that Firefox applies in NSS code are not expressed in certdata.txt and are not carried here")

	return out, nil
}

func isDistrustedForAnyPurpose(trust map[string]string) bool {
	for _, v := range trust {
		if v == "CKT_NSS_NOT_TRUSTED" {
			return true
		}
	}
	return false
}

var certdataRevisionRe = regexp.MustCompile(`(?m)^#\s*(\$Revision:\s*\S+\s*\$|NSS_BUILTINS_LIBRARY_VERSION\s+"[^"]+")`)

func certdataRevision(s string) string {
	if m := certdataRevisionRe.FindStringSubmatch(s); m != nil {
		return strings.TrimSpace(m[1])
	}
	if i := strings.Index(s, "NSS_BUILTINS_LIBRARY_VERSION"); i >= 0 {
		line := s[i:]
		if j := strings.IndexByte(line, '\n'); j > 0 {
			return strings.TrimSpace(line[:j])
		}
	}
	return ""
}

func parseCertdataObjects(s string) ([]certdataObject, error) {
	var objects []certdataObject
	var cur *certdataObject

	lines := strings.Split(s, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimRight(lines[i], "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		if !strings.HasPrefix(name, "CKA_") {
			continue
		}

		if name == "CKA_CLASS" {
			if cur != nil {
				objects = append(objects, *cur)
			}
			cur = &certdataObject{
				attrs:  make(map[string][]byte),
				trusts: make(map[string]string),
			}
			if len(fields) >= 3 {
				cur.class = fields[2]
			}
			continue
		}

		if cur == nil {
			continue
		}

		if fields[1] == "MULTILINE_OCTAL" {
			var buf []byte
			for i+1 < len(lines) {
				i++
				body := strings.TrimSpace(strings.TrimRight(lines[i], "\r"))
				if body == "END" {
					break
				}
				b, err := decodeOctalLine(body)
				if err != nil {
					return nil, fmt.Errorf("certdata: %w", err)
				}
				buf = append(buf, b...)
			}
			cur.attrs[name] = buf
			continue
		}

		if name == "CKA_LABEL" {
			cur.label = unquoteUTF8(trimmed)
			continue
		}

		if fields[1] == "CK_TRUST" && len(fields) >= 3 {
			cur.trusts[name] = fields[2]
		}
	}

	if cur != nil {
		objects = append(objects, *cur)
	}
	return objects, nil
}

func decodeOctalLine(line string) ([]byte, error) {
	var out []byte
	for i := 0; i < len(line); {
		if line[i] != '\\' {
			i++
			continue
		}
		if i+3 >= len(line) {
			return nil, fmt.Errorf("truncated octal escape in %q", line)
		}
		v, err := strconv.ParseUint(line[i+1:i+4], 8, 16)
		if err != nil {
			return nil, fmt.Errorf("bad octal escape %q", line[i:i+4])
		}
		out = append(out, byte(v))
		i += 4
	}
	return out, nil
}

func unquoteUTF8(line string) string {
	first := strings.Index(line, "\"")
	last := strings.LastIndex(line, "\"")
	if first < 0 || last <= first {
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			return strings.Join(fields[2:], " ")
		}
		return ""
	}
	return line[first+1 : last]
}

// --- Chrome Root Store ---

var (
	chromeAnchorRe   = regexp.MustCompile(`(?s)trust_anchors\s*\{(.*?)\n\}`)
	chromeSHA256Re   = regexp.MustCompile(`sha256_hex:\s*"([0-9a-fA-F]{64})"`)
	chromeVersionRe  = regexp.MustCompile(`(?m)^version_major:\s*(\d+)`)
	chromeConstraint = regexp.MustCompile(`constraints\s*\{`)
)

// ParseChromeRootStore pairs root_store.textproto with root_store.certs. The
// textproto is authoritative for membership: root_store.certs may hold entries
// the store does not actually include.
func ParseChromeRootStore(textproto, certsFile []byte) (*ParsedBundle, error) {
	included := make(map[string]bool)
	constrained := 0

	for _, block := range chromeAnchorRe.FindAllStringSubmatch(string(textproto), -1) {
		m := chromeSHA256Re.FindStringSubmatch(block[1])
		if m == nil {
			continue
		}
		included[strings.ToLower(m[1])] = true
		if chromeConstraint.MatchString(block[1]) {
			constrained++
		}
	}
	if len(included) == 0 {
		return nil, fmt.Errorf("root_store.textproto yielded no trust anchors")
	}

	out := &ParsedBundle{}
	if m := chromeVersionRe.FindStringSubmatch(string(textproto)); m != nil {
		out.Revision = "version_major " + m[1]
	}

	rest := certsFile
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		sum := sha256.Sum256(block.Bytes)
		fp := hex.EncodeToString(sum[:])
		if !included[fp] {
			continue
		}
		out.Trusted = append(out.Trusted, BundleCert{DER: block.Bytes})
		delete(included, fp)
	}

	if len(out.Trusted) == 0 {
		return nil, fmt.Errorf("no certificates in root_store.certs matched the textproto anchors")
	}
	if len(included) > 0 {
		out.Caveats = append(out.Caveats,
			fmt.Sprintf("%d anchors listed in root_store.textproto had no certificate in root_store.certs", len(included)))
	}
	if constrained > 0 {
		out.Caveats = append(out.Caveats,
			fmt.Sprintf("%d anchors carry constraints in root_store.textproto (SCT-not-after, validity limits) that a PEM bundle cannot express", constrained))
	}
	out.Caveats = append(out.Caveats,
		"the Chrome Root Store is scoped to public TLS server authentication; it is not an authority for client auth, code signing or S/MIME")

	return out, nil
}
