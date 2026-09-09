package certlib

import (
	"bytes"
	"encoding/pem"
	"strings"
)

type DetectedFormat int

const (
	DetectedUnknown DetectedFormat = iota
	DetectedPEM
	DetectedJKS
	DetectedASN1
)

var (
	jksMagic  = []byte{0xFE, 0xED, 0xFE, 0xED}
	pemPrefix = []byte("-----BEGIN")
)

func DetectFormat(data []byte) DetectedFormat {
	if len(data) < 4 {
		return DetectedUnknown
	}

	if bytes.HasPrefix(data, jksMagic) {
		return DetectedJKS
	}

	if bytes.HasPrefix(data, pemPrefix) {
		return DetectedPEM
	}

	block, _ := pem.Decode(data)
	if block != nil {
		return DetectedPEM
	}

	if data[0] == 0x30 {
		return DetectedASN1
	}

	return DetectedUnknown
}

func FormatFromExtension(ext string) (FileFormat, bool) {
	switch strings.ToLower(ext) {
	case ".pem", ".crt", ".cer", ".key":
		return FormatPEM, true
	case ".der":
		return FormatDER, true
	case ".p12", ".pfx":
		return FormatPKCS12, true
	case ".p7b", ".p7c", ".p7s":
		return FormatPKCS7, true
	case ".jks":
		return FormatJKS, true
	default:
		return "", false
	}
}

func ReadFileBySignature(path string, data []byte, passwords []TaggedPassword) (*CertContainer, error) {
	return readFileBySignatureCore(path, data, passwords, nil)
}

func readFileBySignatureCore(path string, data []byte, passwords []TaggedPassword, progress *ScanProgress) (*CertContainer, error) {
	detected := DetectFormat(data)
	raw := rawPasswords(passwords)

	var (
		container *CertContainer
		err       error
	)

	switch detected {
	case DetectedPEM:
		container, err = readPEM(path, data, raw, progress)

	case DetectedJKS:
		container, err = readJKS(path, data, raw, progress)

	case DetectedASN1:
		if c, e := readPKCS12(path, data, raw, progress); e == nil && len(c.Items) > 0 {
			c.UnlockSources = findSources(passwords, c.Password)
			return c, nil
		} else if e == nil && isEncryptedPKCS12(data) {
			c.UnlockSources = findSources(passwords, c.Password)
			return c, nil
		}

		if c, e := readPKCS7(path, data); e == nil && len(c.Items) > 0 {
			return c, nil
		}

		return readDER(path, data)

	default:
		return nil, ErrUnknownFormat
	}

	if err != nil {
		return nil, err
	}
	container.UnlockSources = findSources(passwords, container.Password)
	return container, nil
}
