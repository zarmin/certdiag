package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	saltLen      = 16
	nonceLen     = 12
	keyLen       = 32 // AES-256
	argonMemory  = 64 * 1024
	argonTime    = 3
	argonThreads = 4
	minPadding   = 1
	maxPadding   = 32
)

var ErrDecryptionFailed = errors.New("decryption failed: invalid master password or corrupted data")

func deriveKey(masterPassword, salt []byte) []byte {
	return argon2.IDKey(masterPassword, salt, argonTime, argonMemory, argonThreads, keyLen)
}

func Encrypt(masterPassword, plaintext []byte) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	key := deriveKey(masterPassword, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	paddingLen := minPadding
	if maxPadding > minPadding {
		padByte := make([]byte, 1)
		if _, err := io.ReadFull(rand.Reader, padByte); err != nil {
			return "", err
		}
		paddingLen = minPadding + int(padByte[0])%(maxPadding-minPadding+1)
	}
	padding := make([]byte, paddingLen)
	if _, err := io.ReadFull(rand.Reader, padding); err != nil {
		return "", err
	}

	inner := make([]byte, 4+len(plaintext)+paddingLen)
	binary.BigEndian.PutUint32(inner[:4], uint32(len(plaintext)))
	copy(inner[4:], plaintext)
	copy(inner[4+len(plaintext):], padding)

	ciphertext := gcm.Seal(nil, nonce, inner, nil)

	blob := make([]byte, 0, saltLen+nonceLen+len(ciphertext))
	blob = append(blob, salt...)
	blob = append(blob, nonce...)
	blob = append(blob, ciphertext...)

	return base64.StdEncoding.EncodeToString(blob), nil
}

func Decrypt(masterPassword []byte, encoded string) ([]byte, error) {
	blob, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	if len(blob) < saltLen+nonceLen+1 {
		return nil, ErrDecryptionFailed
	}

	salt := blob[:saltLen]
	nonce := blob[saltLen : saltLen+nonceLen]
	ciphertext := blob[saltLen+nonceLen:]

	key := deriveKey(masterPassword, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	inner, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	if len(inner) < 4 {
		return nil, ErrDecryptionFailed
	}

	length := binary.BigEndian.Uint32(inner[:4])
	if int(length) > len(inner)-4 {
		return nil, ErrDecryptionFailed
	}

	return inner[4 : 4+length], nil
}
