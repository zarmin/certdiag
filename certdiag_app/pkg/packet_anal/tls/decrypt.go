package tls

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
)

var ErrNoHandshakeSecret = errors.New("no SERVER_HANDSHAKE_TRAFFIC_SECRET for this session")

// decryptRecord13 decrypts one TLS 1.3 record (RFC 8446 section 5.2). It returns
// the inner content and the real inner content type, stripping the content-type
// byte and zero padding from the TLSInnerPlaintext.
func decryptRecord13(aead cipher.AEAD, iv []byte, seq uint64, rec Record) ([]byte, ContentType, error) {
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	var seqBytes [8]byte
	binary.BigEndian.PutUint64(seqBytes[:], seq)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-8+i] ^= seqBytes[i]
	}

	// Additional data is the record header exactly as on the wire.
	aad := []byte{
		byte(rec.Type), rec.Version.Major, rec.Version.Minor,
		byte(len(rec.Payload) >> 8), byte(len(rec.Payload)),
	}

	plain, err := aead.Open(nil, nonce, rec.Payload, aad)
	if err != nil {
		return nil, 0, err
	}

	// TLSInnerPlaintext = content || ContentType || zeros*
	i := len(plain) - 1
	for i >= 0 && plain[i] == 0 {
		i--
	}
	if i < 0 {
		return nil, 0, errors.New("decrypted record has no content type")
	}
	return plain[:i], ContentType(plain[i]), nil
}

// DecryptServerHandshake13 decrypts the server's encrypted TLS 1.3 handshake
// (EncryptedExtensions, Certificate, CertificateVerify, Finished) using the
// SERVER_HANDSHAKE_TRAFFIC_SECRET from the keylog, and returns the reassembled
// handshake message bytes. clientRandom is the ClientHello.Random (the keylog
// join key); cipherSuite is the negotiated suite from ServerHello.
func DecryptServerHandshake13(serverData, clientRandom []byte, cipherSuite uint16, kl *KeyLog) ([]byte, error) {
	secret, ok := kl.Secret(clientRandom, KeyLogServerHandshakeTrafficSecret)
	if !ok {
		return nil, ErrNoHandshakeSecret
	}
	suite, ok := lookupCipherSuite13(cipherSuite)
	if !ok {
		return nil, fmt.Errorf("unsupported TLS 1.3 cipher suite 0x%04x", cipherSuite)
	}

	key, iv, err := suite.deriveKeyIV(secret)
	if err != nil {
		return nil, err
	}
	aead, err := suite.newAEAD(key)
	if err != nil {
		return nil, err
	}

	records, _, _ := ParseRecords(serverData)

	var handshake []byte
	var seq uint64
	for _, rec := range records {
		if rec.Type != ContentApplicationData {
			continue
		}
		inner, innerType, derr := decryptRecord13(aead, iv, seq, rec)
		if derr != nil {
			// Past the handshake phase (application-data key) or wrong keys.
			break
		}
		seq++
		if innerType != ContentHandshake {
			break
		}
		handshake = append(handshake, inner...)
	}

	if len(handshake) == 0 {
		return nil, errors.New("no handshake records could be decrypted (wrong or missing keys)")
	}
	return handshake, nil
}
