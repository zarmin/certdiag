package tls

import (
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"golang.org/x/crypto/chacha20poly1305"
)

// aeadMode distinguishes the two TLS 1.2 AEAD nonce constructions we support.
type aeadMode int

const (
	aeadGCM    aeadMode = iota // 4-byte fixed IV + 8-byte explicit per-record nonce
	aeadChaCha                 // 12-byte fixed IV XOR sequence number (RFC 7905)
)

type cipherSuite12 struct {
	hash    func() hash.Hash
	keyLen  int
	ivLen   int // fixed IV length
	mode    aeadMode
	newAEAD func(key []byte) (cipher.AEAD, error)
}

func lookupCipherSuite12(code uint16) (*cipherSuite12, bool) {
	switch code {
	case 0xc02f, 0xc02b: // ECDHE_{RSA,ECDSA}_WITH_AES_128_GCM_SHA256
		return &cipherSuite12{sha256.New, 16, 4, aeadGCM, newAESGCM}, true
	case 0xc030, 0xc02c: // ECDHE_{RSA,ECDSA}_WITH_AES_256_GCM_SHA384
		return &cipherSuite12{sha512.New384, 32, 4, aeadGCM, newAESGCM}, true
	case 0xcca8, 0xcca9: // ECDHE_{RSA,ECDSA}_WITH_CHACHA20_POLY1305_SHA256
		return &cipherSuite12{sha256.New, 32, 12, aeadChaCha, func(key []byte) (cipher.AEAD, error) {
			return chacha20poly1305.New(key)
		}}, true
	}
	return nil, false
}

type tls12Keys struct {
	clientKey, serverKey []byte
	clientIV, serverIV   []byte
	suite                *cipherSuite12
}

// deriveTLS12Keys expands the master secret into per-direction AEAD keys and
// fixed IVs (RFC 5246 6.3). AEAD suites have no separate MAC keys.
func deriveTLS12Keys(master, clientRandom, serverRandom []byte, suite *cipherSuite12) *tls12Keys {
	seed := make([]byte, 0, len(serverRandom)+len(clientRandom))
	seed = append(seed, serverRandom...)
	seed = append(seed, clientRandom...)

	needed := 2*suite.keyLen + 2*suite.ivLen
	kb := prf12(suite.hash, master, []byte("key expansion"), seed, needed)

	off := 0
	ck := kb[off : off+suite.keyLen]
	off += suite.keyLen
	sk := kb[off : off+suite.keyLen]
	off += suite.keyLen
	ci := kb[off : off+suite.ivLen]
	off += suite.ivLen
	si := kb[off : off+suite.ivLen]

	return &tls12Keys{clientKey: ck, serverKey: sk, clientIV: ci, serverIV: si, suite: suite}
}

func (k *tls12Keys) decryptRecord(rec Record, fromClient bool, seq uint64) ([]byte, error) {
	key, iv := k.serverKey, k.serverIV
	if fromClient {
		key, iv = k.clientKey, k.clientIV
	}
	aead, err := k.suite.newAEAD(key)
	if err != nil {
		return nil, err
	}

	var nonce, ct []byte
	switch k.suite.mode {
	case aeadGCM:
		if len(rec.Payload) < 8 {
			return nil, errors.New("GCM record too short for explicit nonce")
		}
		nonce = append(append([]byte{}, iv...), rec.Payload[:8]...)
		ct = rec.Payload[8:]
	default: // aeadChaCha
		nonce = make([]byte, len(iv))
		copy(nonce, iv)
		var seqBytes [8]byte
		binary.BigEndian.PutUint64(seqBytes[:], seq)
		for i := 0; i < 8; i++ {
			nonce[len(nonce)-8+i] ^= seqBytes[i]
		}
		ct = rec.Payload
	}

	plainLen := len(ct) - aead.Overhead()
	if plainLen < 0 {
		return nil, errors.New("record shorter than AEAD tag")
	}

	var seqBytes [8]byte
	binary.BigEndian.PutUint64(seqBytes[:], seq)
	aad := append(seqBytes[:], byte(rec.Type), rec.Version.Major, rec.Version.Minor, byte(plainLen>>8), byte(plainLen))

	return aead.Open(nil, nonce, ct, aad)
}

func decryptTLS12Direction(records []Record, keys *tls12Keys, fromClient bool) []byte {
	var appData []byte
	var seq uint64
	afterCCS := false
	for _, rec := range records {
		if rec.Type == ContentChangeCipherSpec {
			afterCCS = true
			seq = 0
			continue
		}
		if !afterCCS {
			continue
		}
		plain, err := keys.decryptRecord(rec, fromClient, seq)
		if err != nil {
			break
		}
		seq++
		if rec.Type == ContentApplicationData {
			appData = append(appData, plain...)
		}
	}
	return appData
}

// DecryptTLS12 decrypts the application data in both directions of a TLS 1.2 flow
// using the CLIENT_RANDOM master secret from the keylog. Only AEAD suites
// (AES-GCM, ChaCha20-Poly1305) are supported; legacy CBC suites are not.
func DecryptTLS12(clientData, serverData, clientRandom, serverRandom []byte, cipherSuite uint16, kl *KeyLog) (clientApp, serverApp []byte, err error) {
	master, ok := kl.Secret(clientRandom, KeyLogClientRandom)
	if !ok {
		return nil, nil, errors.New("no CLIENT_RANDOM master secret for this session")
	}
	suite, ok := lookupCipherSuite12(cipherSuite)
	if !ok {
		return nil, nil, fmt.Errorf("unsupported TLS 1.2 cipher suite 0x%04x (only AEAD suites)", cipherSuite)
	}
	keys := deriveTLS12Keys(master, clientRandom, serverRandom, suite)

	crecs, _, _ := ParseRecords(clientData)
	srecs, _, _ := ParseRecords(serverData)
	return decryptTLS12Direction(crecs, keys, true), decryptTLS12Direction(srecs, keys, false), nil
}
