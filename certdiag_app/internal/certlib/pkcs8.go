package certlib

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"hash"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

var (
	oidPBES2      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidScrypt     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 4, 11}
	oidAES128CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
	oidHMACSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACSHA224 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}
	oidHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
)

type encryptedPrivateKeyInfo struct {
	Algorithm algorithmIdentifier
	Data      []byte
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue
}

type pbes2Params struct {
	KDF              algorithmIdentifier
	EncryptionScheme algorithmIdentifier
}

type pbkdf2Params struct {
	Salt       []byte
	Iterations int
	KeyLength  int                 `asn1:"optional"`
	PRF        algorithmIdentifier `asn1:"optional"`
}

type scryptParams struct {
	Salt      []byte
	CostParam int
	R         int
	P         int
	KeyLength int `asn1:"optional"`
}

func DecryptPKCS8(derBytes []byte, password []byte) ([]byte, error) {
	var epki encryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(derBytes, &epki); err != nil {
		return nil, fmt.Errorf("pkcs8: failed to parse EncryptedPrivateKeyInfo: %w", err)
	}

	if !epki.Algorithm.Algorithm.Equal(oidPBES2) {
		return nil, fmt.Errorf("pkcs8: unsupported encryption algorithm %v (only PBES2 supported)", epki.Algorithm.Algorithm)
	}

	var params pbes2Params
	if _, err := asn1.Unmarshal(epki.Algorithm.Parameters.FullBytes, &params); err != nil {
		return nil, fmt.Errorf("pkcs8: failed to parse PBES2 parameters: %w", err)
	}

	key, err := deriveKey(params.KDF, password)
	if err != nil {
		return nil, err
	}

	plaintext, err := decrypt(params.EncryptionScheme, key, epki.Data)
	if err != nil {
		return nil, err
	}

	// A wrong password yields random plaintext whose CBC/PKCS#7 padding
	// validates by chance (~1/256), returning garbage with no error. Confirm
	// the result is a well-formed PKCS#8 key so wrong passwords fail reliably.
	if _, err := x509.ParsePKCS8PrivateKey(plaintext); err != nil {
		return nil, fmt.Errorf("pkcs8: decryption failed (wrong password or corrupt data)")
	}

	return plaintext, nil
}

func deriveKey(kdf algorithmIdentifier, password []byte) ([]byte, error) {
	if kdf.Algorithm.Equal(oidPBKDF2) {
		return derivePBKDF2(kdf.Parameters, password)
	}
	if kdf.Algorithm.Equal(oidScrypt) {
		return deriveScrypt(kdf.Parameters, password)
	}
	return nil, fmt.Errorf("pkcs8: unsupported KDF %v", kdf.Algorithm)
}

func derivePBKDF2(raw asn1.RawValue, password []byte) ([]byte, error) {
	var params pbkdf2Params
	if _, err := asn1.Unmarshal(raw.FullBytes, &params); err != nil {
		return nil, fmt.Errorf("pkcs8: failed to parse PBKDF2 parameters: %w", err)
	}

	hashFunc, err := prfToHash(params.PRF)
	if err != nil {
		return nil, err
	}

	keyLen := params.KeyLength
	if keyLen == 0 {
		keyLen = 32
	}

	return pbkdf2.Key(password, params.Salt, params.Iterations, keyLen, hashFunc), nil
}

func deriveScrypt(raw asn1.RawValue, password []byte) ([]byte, error) {
	var params scryptParams
	if _, err := asn1.Unmarshal(raw.FullBytes, &params); err != nil {
		return nil, fmt.Errorf("pkcs8: failed to parse scrypt parameters: %w", err)
	}

	keyLen := params.KeyLength
	if keyLen == 0 {
		keyLen = 32
	}

	key, err := scrypt.Key(password, params.Salt, params.CostParam, params.R, params.P, keyLen)
	if err != nil {
		return nil, fmt.Errorf("pkcs8: scrypt key derivation failed: %w", err)
	}
	return key, nil
}

func prfToHash(prf algorithmIdentifier) (func() hash.Hash, error) {
	if prf.Algorithm == nil || prf.Algorithm.Equal(oidHMACSHA1) {
		return sha1.New, nil
	}
	if prf.Algorithm.Equal(oidHMACSHA224) {
		return sha256.New224, nil
	}
	if prf.Algorithm.Equal(oidHMACSHA256) {
		return sha256.New, nil
	}
	if prf.Algorithm.Equal(oidHMACSHA384) {
		return sha512.New384, nil
	}
	if prf.Algorithm.Equal(oidHMACSHA512) {
		return sha512.New, nil
	}
	return nil, fmt.Errorf("pkcs8: unsupported PBKDF2 PRF %v", prf.Algorithm)
}

func decrypt(scheme algorithmIdentifier, key []byte, ciphertext []byte) ([]byte, error) {
	var iv []byte
	if _, err := asn1.Unmarshal(scheme.Parameters.FullBytes, &iv); err != nil {
		return nil, fmt.Errorf("pkcs8: failed to parse cipher IV: %w", err)
	}

	var block cipher.Block
	var err error

	switch {
	case scheme.Algorithm.Equal(oidAES128CBC):
		if len(key) > 16 {
			key = key[:16]
		}
		block, err = aes.NewCipher(key)
	case scheme.Algorithm.Equal(oidAES192CBC):
		if len(key) > 24 {
			key = key[:24]
		}
		block, err = aes.NewCipher(key)
	case scheme.Algorithm.Equal(oidAES256CBC):
		if len(key) > 32 {
			key = key[:32]
		}
		block, err = aes.NewCipher(key)
	case scheme.Algorithm.Equal(oidDESEDE3CBC):
		if len(key) > 24 {
			key = key[:24]
		}
		block, err = des.NewTripleDESCipher(key)
	default:
		return nil, fmt.Errorf("pkcs8: unsupported cipher %v", scheme.Algorithm)
	}
	if err != nil {
		return nil, fmt.Errorf("pkcs8: cipher init failed: %w", err)
	}

	if len(ciphertext)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("pkcs8: ciphertext not a multiple of block size")
	}
	if len(iv) != block.BlockSize() {
		return nil, fmt.Errorf("pkcs8: IV length %d does not match block size %d", len(iv), block.BlockSize())
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	plaintext, err = removePKCS7Padding(plaintext, block.BlockSize())
	if err != nil {
		return nil, fmt.Errorf("pkcs8: %w", err)
	}

	return plaintext, nil
}

func removePKCS7Padding(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("invalid padding: empty data")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > blockSize || padLen > len(data) {
		return nil, fmt.Errorf("invalid padding")
	}
	for i := len(data) - padLen; i < len(data); i++ {
		if data[i] != byte(padLen) {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return data[:len(data)-padLen], nil
}

func addPKCS7Padding(data []byte, blockSize int) []byte {
	padLen := blockSize - (len(data) % blockSize)
	padding := make([]byte, padLen)
	for i := range padding {
		padding[i] = byte(padLen)
	}
	return append(data, padding...)
}

func EncryptPKCS8(derBytes []byte, password []byte) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("pkcs8: failed to generate salt: %w", err)
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("pkcs8: failed to generate IV: %w", err)
	}

	iterations := 600000
	keyLen := 32

	key := pbkdf2.Key(password, salt, iterations, keyLen, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("pkcs8: cipher init failed: %w", err)
	}

	padded := addPKCS7Padding(derBytes, block.BlockSize())
	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	ivBytes, err := asn1.Marshal(iv)
	if err != nil {
		return nil, fmt.Errorf("pkcs8: failed to marshal IV: %w", err)
	}

	prfParam := algorithmIdentifier{Algorithm: oidHMACSHA256, Parameters: asn1.RawValue{Tag: 5}}

	pbkdf2P := pbkdf2Params{
		Salt:       salt,
		Iterations: iterations,
		KeyLength:  keyLen,
		PRF:        prfParam,
	}

	pbkdf2Bytes, err := asn1.Marshal(pbkdf2P)
	if err != nil {
		return nil, fmt.Errorf("pkcs8: failed to marshal PBKDF2 params: %w", err)
	}

	p2 := pbes2Params{
		KDF: algorithmIdentifier{
			Algorithm:  oidPBKDF2,
			Parameters: asn1.RawValue{FullBytes: pbkdf2Bytes},
		},
		EncryptionScheme: algorithmIdentifier{
			Algorithm:  oidAES256CBC,
			Parameters: asn1.RawValue{FullBytes: ivBytes},
		},
	}

	p2Bytes, err := asn1.Marshal(p2)
	if err != nil {
		return nil, fmt.Errorf("pkcs8: failed to marshal PBES2 params: %w", err)
	}

	epki := encryptedPrivateKeyInfo{
		Algorithm: algorithmIdentifier{
			Algorithm:  oidPBES2,
			Parameters: asn1.RawValue{FullBytes: p2Bytes},
		},
		Data: ciphertext,
	}

	return asn1.Marshal(epki)
}
