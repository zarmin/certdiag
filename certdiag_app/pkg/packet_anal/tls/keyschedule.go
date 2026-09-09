package tls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// hkdfExpandLabel implements HKDF-Expand-Label from RFC 8446 section 7.1.
func hkdfExpandLabel(hashFn func() hash.Hash, secret []byte, label string, context []byte, length int) ([]byte, error) {
	fullLabel := "tls13 " + label
	var info []byte
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(fullLabel)))
	info = append(info, fullLabel...)
	info = append(info, byte(len(context)))
	info = append(info, context...)

	out := make([]byte, length)
	if _, err := io.ReadFull(hkdf.Expand(hashFn, secret, info), out); err != nil {
		return nil, err
	}
	return out, nil
}

// cipherSuite13 describes the AEAD and hash for a TLS 1.3 cipher suite.
type cipherSuite13 struct {
	hash   func() hash.Hash
	keyLen int
	ivLen  int
	newAEAD func(key []byte) (cipher.AEAD, error)
}

// deriveKeyIV derives the per-direction record protection key and IV from a
// traffic secret (RFC 8446 section 7.3).
func (cs *cipherSuite13) deriveKeyIV(secret []byte) (key, iv []byte, err error) {
	key, err = hkdfExpandLabel(cs.hash, secret, "key", nil, cs.keyLen)
	if err != nil {
		return nil, nil, err
	}
	iv, err = hkdfExpandLabel(cs.hash, secret, "iv", nil, cs.ivLen)
	if err != nil {
		return nil, nil, err
	}
	return key, iv, nil
}

func lookupCipherSuite13(code uint16) (*cipherSuite13, bool) {
	switch code {
	case 0x1301: // TLS_AES_128_GCM_SHA256
		return &cipherSuite13{hash: sha256.New, keyLen: 16, ivLen: 12, newAEAD: newAESGCM}, true
	case 0x1302: // TLS_AES_256_GCM_SHA384
		return &cipherSuite13{hash: sha512.New384, keyLen: 32, ivLen: 12, newAEAD: newAESGCM}, true
	case 0x1303: // TLS_CHACHA20_POLY1305_SHA256
		return &cipherSuite13{hash: sha256.New, keyLen: 32, ivLen: 12, newAEAD: func(key []byte) (cipher.AEAD, error) {
			return chacha20poly1305.New(key)
		}}, true
	}
	return nil, false
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
