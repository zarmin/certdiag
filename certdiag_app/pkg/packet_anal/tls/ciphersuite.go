package tls

import (
	"fmt"
	"strings"
)

type CipherSuite struct {
	Code uint16
	Name string
	Weak bool
}

func LookupCipherSuite(code uint16) CipherSuite {
	if name, ok := cipherSuiteNames[code]; ok {
		return CipherSuite{Code: code, Name: name, Weak: weakCipherSuite(name)}
	}
	return CipherSuite{
		Code: code,
		Name: fmt.Sprintf("Unknown(0x%04x)", code),
	}
}

func CipherSuiteName(code uint16) string {
	return LookupCipherSuite(code).Name
}

// weakCipherSuite classifies a suite by what its name says about it: no
// encryption, export grades, DES/3DES/RC4/RC2, MD5, anonymous key exchange,
// Kerberos, and static RSA key exchange (no forward secrecy). The names come
// from the IANA registry (tables_gen.go); the judgement stays here.
func weakCipherSuite(name string) bool {
	if strings.HasPrefix(name, "TLS_RSA_WITH_") || strings.HasPrefix(name, "TLS_NULL_") {
		return true
	}
	for _, marker := range []string{"_NULL_", "_NULL", "_EXPORT", "_DES_", "_DES40_", "_3DES_", "_RC4_", "_RC2_", "_MD5", "_anon_", "_KRB5_"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

func NamedGroupName(code uint16) string {
	if name, ok := namedGroups[code]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(0x%04x)", code)
}

func SignatureAlgorithmName(code uint16) string {
	if name, ok := signatureAlgorithms[code]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(0x%04x)", code)
}
