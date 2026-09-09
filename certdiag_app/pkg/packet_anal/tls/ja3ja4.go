package tls

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

const extECPointFormats uint16 = 11

// ja4Zeros is the JA4 placeholder for an empty b/c section (FoxIO spec).
const ja4Zeros = "000000000000"

// isGREASE reports whether a 2-byte value is a GREASE placeholder (RFC 8701),
// which must be excluded from JA3/JA4 fingerprints.
func isGREASE(v uint16) bool {
	return byte(v>>8) == byte(v) && v&0x0f == 0x0a
}

// JA3 returns the JA3 fingerprint (md5 hex) of a ClientHello and its raw string.
func JA3(ch *ClientHelloMsg) (fingerprint, raw string) {
	ciphers := filterGREASE(ch.CipherSuites)

	var extTypes []uint16
	var pointFormats []uint8
	for _, e := range ch.Extensions {
		if isGREASE(e.Type) {
			continue
		}
		extTypes = append(extTypes, e.Type)
		if e.Type == extECPointFormats && len(e.Data) > 0 {
			n := int(e.Data[0])
			if 1+n <= len(e.Data) {
				pointFormats = e.Data[1 : 1+n]
			}
		}
	}
	curves := filterGREASE(ch.SupportedGroups)

	raw = strings.Join([]string{
		strconv.Itoa(int(ch.Version.Code())),
		joinDec16(ciphers),
		joinDec16(extTypes),
		joinDec16(curves),
		joinDec8(pointFormats),
	}, ",")
	sum := md5.Sum([]byte(raw))
	return hex.EncodeToString(sum[:]), raw
}

// JA4 returns the JA4 fingerprint (FoxIO spec) for a ClientHello over TCP.
func JA4(ch *ClientHelloMsg) string {
	ciphers := filterGREASE(ch.CipherSuites)

	var extTypes []uint16
	for _, e := range ch.Extensions {
		if !isGREASE(e.Type) {
			extTypes = append(extTypes, e.Type)
		}
	}
	sigAlgs := filterGREASE(ch.SignatureAlgs)

	// Part a: t<ver><sni><ciphercount><extcount><alpn>
	sni := "i"
	if ch.SNI != "" {
		sni = "d"
	}
	a := "t" + ja4Version(ch) + sni + twoDigit(len(ciphers)) + twoDigit(len(extTypes)) + ja4ALPN(ch.ALPNProtocols)

	// Part b: sorted cipher suites, hashed. Per the FoxIO spec an empty section
	// is twelve zeros, not the hash of the empty string.
	b := ja4Zeros
	if len(ciphers) > 0 {
		b = sha12(joinHex4Sorted(ciphers))
	}

	// Part c: sorted extensions (minus SNI and ALPN) + "_" + signature algs (in
	// order). When there are no signature algorithms the string ends without the
	// trailing underscore; with no extensions the section is twelve zeros.
	var cExts []uint16
	for _, e := range extTypes {
		if e == ExtServerName || e == ExtALPN {
			continue
		}
		cExts = append(cExts, e)
	}
	sortU16(cExts)
	c := ja4Zeros
	if len(cExts) > 0 {
		cRaw := joinHex4(cExts)
		if len(sigAlgs) > 0 {
			cRaw += "_" + joinHex4(sigAlgs)
		}
		c = sha12(cRaw)
	}

	return a + "_" + b + "_" + c
}

func ja4Version(ch *ClientHelloMsg) string {
	v := ch.Version
	if len(ch.SupportedVersions) > 0 {
		var best uint16
		for _, sv := range ch.SupportedVersions {
			code := sv.Code()
			if isGREASE(code) {
				continue
			}
			if code > best {
				best = code
			}
		}
		if best != 0 {
			v = VersionFromCode(best)
		}
	}
	switch v {
	case VersionTLS13:
		return "13"
	case VersionTLS12:
		return "12"
	case VersionTLS11:
		return "11"
	case VersionTLS10:
		return "10"
	case VersionSSL30:
		return "s3"
	default:
		return "00"
	}
}

func ja4ALPN(alpns []string) string {
	if len(alpns) == 0 || alpns[0] == "" {
		return "00"
	}
	a := alpns[0]
	first, last := a[0], a[len(a)-1]
	// FoxIO spec: when the first or last byte is not an ASCII alphanumeric,
	// use the first and last characters of the hex-encoded ALPN instead. This
	// also avoids UTF-8-mangling a byte >= 0x80 via string(byte).
	if isASCIIAlnum(first) && isASCIIAlnum(last) {
		return string(first) + string(last)
	}
	h := hex.EncodeToString([]byte(a))
	return string(h[0]) + string(h[len(h)-1])
}

func isASCIIAlnum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func filterGREASE(vs []uint16) []uint16 {
	out := make([]uint16, 0, len(vs))
	for _, v := range vs {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func joinDec16(vs []uint16) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, "-")
}

func joinDec8(vs []uint8) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, "-")
}

func joinHex4(vs []uint16) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

func joinHex4Sorted(vs []uint16) string {
	s := append([]uint16(nil), vs...)
	sortU16(s)
	return joinHex4(s)
}

func sortU16(vs []uint16) {
	slices.Sort(vs)
}

func sha12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func twoDigit(n int) string {
	if n > 99 {
		n = 99
	}
	return fmt.Sprintf("%02d", n)
}
