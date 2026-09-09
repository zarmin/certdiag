package certlib

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"hash"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

func testPKCS8DER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// --- Round-trip tests for all key types ---

func TestPKCS8_RoundTrip_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := EncryptPKCS8(der, []byte("test-password-123"))
	if err != nil {
		t.Fatalf("EncryptPKCS8 failed: %v", err)
	}

	decrypted, err := DecryptPKCS8(encrypted, []byte("test-password-123"))
	if err != nil {
		t.Fatalf("DecryptPKCS8 failed: %v", err)
	}

	parsed, err := x509.ParsePKCS8PrivateKey(decrypted)
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey failed: %v", err)
	}

	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("expected RSA key")
	}
	if rsaKey.N.Cmp(key.N) != 0 {
		t.Error("RSA key N does not match")
	}
}

func TestPKCS8_RoundTrip_ECDSA_P256(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)

	encrypted, err := EncryptPKCS8(der, []byte("ec-pass"))
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptPKCS8(encrypted, []byte("ec-pass"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(decrypted)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
		t.Error("expected ECDSA key")
	}
}

func TestPKCS8_RoundTrip_ECDSA_P384(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)

	encrypted, err := EncryptPKCS8(der, []byte("p384-pass"))
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptPKCS8(encrypted, []byte("p384-pass"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(decrypted)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("expected ECDSA key")
	}
	if ecKey.Curve != elliptic.P384() {
		t.Error("expected P-384 curve")
	}
}

func TestPKCS8_RoundTrip_Ed25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := EncryptPKCS8(der, []byte("ed-pass"))
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptPKCS8(encrypted, []byte("ed-pass"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(decrypted)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed.(ed25519.PrivateKey); !ok {
		t.Error("expected Ed25519 key")
	}
}

func TestPKCS8_RoundTrip_EmptyPassword(t *testing.T) {
	der := testPKCS8DER(t)

	encrypted, err := EncryptPKCS8(der, []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptPKCS8(encrypted, []byte(""))
	if err != nil {
		t.Fatalf("DecryptPKCS8 with empty password failed: %v", err)
	}
	if _, err := x509.ParsePKCS8PrivateKey(decrypted); err != nil {
		t.Fatalf("round-tripped key invalid: %v", err)
	}
}

func TestPKCS8_RoundTrip_LongPassword(t *testing.T) {
	der := testPKCS8DER(t)
	longPw := []byte(strings.Repeat("abcdefghijklmnop", 16)) // 256 chars

	encrypted, err := EncryptPKCS8(der, longPw)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptPKCS8(encrypted, longPw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParsePKCS8PrivateKey(decrypted); err != nil {
		t.Fatalf("round-tripped key invalid: %v", err)
	}
}

func TestPKCS8_RoundTrip_UnicodePassword(t *testing.T) {
	der := testPKCS8DER(t)
	pw := []byte("paSSw0rd-mit-Umlauten-aou")

	encrypted, err := EncryptPKCS8(der, pw)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptPKCS8(encrypted, pw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParsePKCS8PrivateKey(decrypted); err != nil {
		t.Fatal(err)
	}
}

// --- Wrong password / error cases ---

func TestPKCS8_WrongPassword(t *testing.T) {
	der := testPKCS8DER(t)

	encrypted, err := EncryptPKCS8(der, []byte("correct"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptPKCS8(encrypted, []byte("wrong"))
	if err == nil {
		t.Error("expected error with wrong password")
	}
}

func TestPKCS8_InvalidDER(t *testing.T) {
	_, err := DecryptPKCS8([]byte("not valid DER"), []byte("pass"))
	if err == nil {
		t.Error("expected error for invalid DER input")
	}
}

func TestPKCS8_TruncatedCiphertext(t *testing.T) {
	der := testPKCS8DER(t)

	encrypted, err := EncryptPKCS8(der, []byte("pass"))
	if err != nil {
		t.Fatal(err)
	}

	// Truncate the DER to corrupt the ciphertext
	truncated := encrypted[:len(encrypted)/2]
	_, err = DecryptPKCS8(truncated, []byte("pass"))
	if err == nil {
		t.Error("expected error for truncated ciphertext")
	}
}

func TestPKCS8_EmptyInput(t *testing.T) {
	_, err := DecryptPKCS8([]byte{}, []byte("pass"))
	if err == nil {
		t.Error("expected error for empty input")
	}
}

func TestPKCS8_UnsupportedAlgorithm(t *testing.T) {
	// Build a fake EncryptedPrivateKeyInfo with a non-PBES2 algorithm OID
	fakeOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
	epki := encryptedPrivateKeyInfo{
		Algorithm: algorithmIdentifier{
			Algorithm:  fakeOID,
			Parameters: asn1.RawValue{Tag: 5}, // NULL
		},
		Data: []byte("fake-data"),
	}
	der, err := asn1.Marshal(epki)
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptPKCS8(der, []byte("pass"))
	if err == nil {
		t.Error("expected error for unsupported algorithm")
	}
	if !strings.Contains(err.Error(), "unsupported encryption algorithm") {
		t.Errorf("error should mention unsupported algorithm, got: %v", err)
	}
}

// --- Encrypt output validation ---

func TestPKCS8_EncryptOutputIsValidASN1(t *testing.T) {
	der := testPKCS8DER(t)

	encrypted, err := EncryptPKCS8(der, []byte("test"))
	if err != nil {
		t.Fatal(err)
	}

	var epki encryptedPrivateKeyInfo
	rest, err := asn1.Unmarshal(encrypted, &epki)
	if err != nil {
		t.Fatalf("encrypted output is not valid ASN.1: %v", err)
	}
	if len(rest) > 0 {
		t.Errorf("trailing bytes after ASN.1 parse: %d bytes", len(rest))
	}
	if !epki.Algorithm.Algorithm.Equal(oidPBES2) {
		t.Errorf("expected PBES2 OID, got %v", epki.Algorithm.Algorithm)
	}
}

func TestPKCS8_EncryptOutputIsPBES2_PBKDF2_SHA256_AES256(t *testing.T) {
	der := testPKCS8DER(t)

	encrypted, err := EncryptPKCS8(der, []byte("test"))
	if err != nil {
		t.Fatal(err)
	}

	var epki encryptedPrivateKeyInfo
	asn1.Unmarshal(encrypted, &epki)

	var params pbes2Params
	if _, err := asn1.Unmarshal(epki.Algorithm.Parameters.FullBytes, &params); err != nil {
		t.Fatalf("failed to parse PBES2 params: %v", err)
	}

	if !params.KDF.Algorithm.Equal(oidPBKDF2) {
		t.Errorf("expected PBKDF2 KDF, got %v", params.KDF.Algorithm)
	}
	if !params.EncryptionScheme.Algorithm.Equal(oidAES256CBC) {
		t.Errorf("expected AES-256-CBC, got %v", params.EncryptionScheme.Algorithm)
	}

	var kdfParams pbkdf2Params
	if _, err := asn1.Unmarshal(params.KDF.Parameters.FullBytes, &kdfParams); err != nil {
		t.Fatalf("failed to parse PBKDF2 params: %v", err)
	}
	if !kdfParams.PRF.Algorithm.Equal(oidHMACSHA256) {
		t.Errorf("expected HMAC-SHA256 PRF, got %v", kdfParams.PRF.Algorithm)
	}
	if kdfParams.Iterations < 100000 {
		t.Errorf("iterations too low: %d", kdfParams.Iterations)
	}
	if len(kdfParams.Salt) < 8 {
		t.Errorf("salt too short: %d bytes", len(kdfParams.Salt))
	}
}

func TestPKCS8_EncryptProducesDifferentOutput(t *testing.T) {
	der := testPKCS8DER(t)
	pw := []byte("same-password")

	enc1, _ := EncryptPKCS8(der, pw)
	enc2, _ := EncryptPKCS8(der, pw)

	if string(enc1) == string(enc2) {
		t.Error("two encryptions with same password should produce different output (random salt/IV)")
	}
}

// --- Decrypt with manually constructed ciphertexts (different ciphers/PRFs) ---

func buildPBES2(t *testing.T, plaintext, password []byte, cipherOID asn1.ObjectIdentifier, keyLen int, prfOID asn1.ObjectIdentifier, hashFunc func() hash.Hash) []byte {
	t.Helper()

	salt := make([]byte, 16)
	rand.Read(salt)
	iterations := 10000

	key := pbkdf2.Key(password, salt, iterations, keyLen, hashFunc)

	var block cipher.Block
	var err error
	var iv []byte

	switch {
	case cipherOID.Equal(oidAES128CBC), cipherOID.Equal(oidAES192CBC), cipherOID.Equal(oidAES256CBC):
		block, err = aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		iv = make([]byte, aes.BlockSize)
	case cipherOID.Equal(oidDESEDE3CBC):
		block, err = des.NewTripleDESCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		iv = make([]byte, des.BlockSize)
	default:
		t.Fatalf("unsupported cipher OID: %v", cipherOID)
	}
	rand.Read(iv)

	padded := addPKCS7Padding(plaintext, block.BlockSize())
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	ivBytes, _ := asn1.Marshal(iv)

	prfParam := algorithmIdentifier{Algorithm: prfOID, Parameters: asn1.RawValue{Tag: 5}}

	kdfParamsBytes, _ := asn1.Marshal(pbkdf2Params{
		Salt:       salt,
		Iterations: iterations,
		KeyLength:  keyLen,
		PRF:        prfParam,
	})

	p2Bytes, _ := asn1.Marshal(pbes2Params{
		KDF: algorithmIdentifier{
			Algorithm:  oidPBKDF2,
			Parameters: asn1.RawValue{FullBytes: kdfParamsBytes},
		},
		EncryptionScheme: algorithmIdentifier{
			Algorithm:  cipherOID,
			Parameters: asn1.RawValue{FullBytes: ivBytes},
		},
	})

	result, _ := asn1.Marshal(encryptedPrivateKeyInfo{
		Algorithm: algorithmIdentifier{
			Algorithm:  oidPBES2,
			Parameters: asn1.RawValue{FullBytes: p2Bytes},
		},
		Data: ciphertext,
	})

	return result
}

func TestPKCS8_Decrypt_PBKDF2_SHA1_AES128(t *testing.T) {
	der := testPKCS8DER(t)
	pw := []byte("sha1-aes128")

	encrypted := buildPBES2(t, der, pw, oidAES128CBC, 16, oidHMACSHA1, sha1.New)

	decrypted, err := DecryptPKCS8(encrypted, pw)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if _, err := x509.ParsePKCS8PrivateKey(decrypted); err != nil {
		t.Fatalf("decrypted key invalid: %v", err)
	}
}

func TestPKCS8_Decrypt_PBKDF2_SHA1_AES192(t *testing.T) {
	der := testPKCS8DER(t)
	pw := []byte("sha1-aes192")

	encrypted := buildPBES2(t, der, pw, oidAES192CBC, 24, oidHMACSHA1, sha1.New)

	decrypted, err := DecryptPKCS8(encrypted, pw)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if _, err := x509.ParsePKCS8PrivateKey(decrypted); err != nil {
		t.Fatalf("decrypted key invalid: %v", err)
	}
}

func TestPKCS8_Decrypt_PBKDF2_SHA1_AES256(t *testing.T) {
	der := testPKCS8DER(t)
	pw := []byte("sha1-aes256")

	encrypted := buildPBES2(t, der, pw, oidAES256CBC, 32, oidHMACSHA1, sha1.New)

	decrypted, err := DecryptPKCS8(encrypted, pw)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if _, err := x509.ParsePKCS8PrivateKey(decrypted); err != nil {
		t.Fatalf("decrypted key invalid: %v", err)
	}
}

func TestPKCS8_Decrypt_PBKDF2_SHA256_AES256(t *testing.T) {
	der := testPKCS8DER(t)
	pw := []byte("sha256-aes256")

	encrypted := buildPBES2(t, der, pw, oidAES256CBC, 32, oidHMACSHA256, sha256.New)

	decrypted, err := DecryptPKCS8(encrypted, pw)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if _, err := x509.ParsePKCS8PrivateKey(decrypted); err != nil {
		t.Fatalf("decrypted key invalid: %v", err)
	}
}

func TestPKCS8_Decrypt_PBKDF2_SHA512_AES256(t *testing.T) {
	der := testPKCS8DER(t)
	pw := []byte("sha512-aes256")

	encrypted := buildPBES2(t, der, pw, oidAES256CBC, 32, oidHMACSHA512, sha512.New)

	decrypted, err := DecryptPKCS8(encrypted, pw)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if _, err := x509.ParsePKCS8PrivateKey(decrypted); err != nil {
		t.Fatalf("decrypted key invalid: %v", err)
	}
}

func TestPKCS8_Decrypt_PBKDF2_SHA224_AES256(t *testing.T) {
	der := testPKCS8DER(t)
	pw := []byte("sha224-aes256")

	encrypted := buildPBES2(t, der, pw, oidAES256CBC, 32, oidHMACSHA224, sha256.New224)

	decrypted, err := DecryptPKCS8(encrypted, pw)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if _, err := x509.ParsePKCS8PrivateKey(decrypted); err != nil {
		t.Fatalf("decrypted key invalid: %v", err)
	}
}

func TestPKCS8_Decrypt_PBKDF2_SHA384_AES256(t *testing.T) {
	der := testPKCS8DER(t)
	pw := []byte("sha384-aes256")

	encrypted := buildPBES2(t, der, pw, oidAES256CBC, 32, oidHMACSHA384, sha512.New384)

	decrypted, err := DecryptPKCS8(encrypted, pw)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if _, err := x509.ParsePKCS8PrivateKey(decrypted); err != nil {
		t.Fatalf("decrypted key invalid: %v", err)
	}
}

func TestPKCS8_Decrypt_PBKDF2_SHA384_WrongPassword(t *testing.T) {
	der := testPKCS8DER(t)

	encrypted := buildPBES2(t, der, []byte("correct"), oidAES256CBC, 32, oidHMACSHA384, sha512.New384)

	_, err := DecryptPKCS8(encrypted, []byte("wrong"))
	if err == nil {
		t.Error("expected error with wrong password on SHA-384 key")
	}
}

func TestPKCS8_Decrypt_PBKDF2_UnknownPRF(t *testing.T) {
	der := testPKCS8DER(t)
	pw := []byte("unknown-prf")

	// Encrypt with a real hash but advertise a bogus PRF OID: decryption must
	// return an explicit unsupported-PRF error, not a silent SHA-1 fallback.
	fakePRF := asn1.ObjectIdentifier{1, 2, 3, 4, 77}
	encrypted := buildPBES2(t, der, pw, oidAES256CBC, 32, fakePRF, sha256.New)

	_, err := DecryptPKCS8(encrypted, pw)
	if err == nil {
		t.Fatal("expected error for unknown PBKDF2 PRF")
	}
	if !strings.Contains(err.Error(), "unsupported PBKDF2 PRF") {
		t.Errorf("error should mention unsupported PBKDF2 PRF, got: %v", err)
	}
}

func TestPKCS8_Decrypt_PBKDF2_SHA1_3DES(t *testing.T) {
	der := testPKCS8DER(t)
	pw := []byte("sha1-3des")

	encrypted := buildPBES2(t, der, pw, oidDESEDE3CBC, 24, oidHMACSHA1, sha1.New)

	decrypted, err := DecryptPKCS8(encrypted, pw)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if _, err := x509.ParsePKCS8PrivateKey(decrypted); err != nil {
		t.Fatalf("decrypted key invalid: %v", err)
	}
}

func TestPKCS8_Decrypt_PBKDF2_SHA256_3DES(t *testing.T) {
	der := testPKCS8DER(t)
	pw := []byte("sha256-3des")

	encrypted := buildPBES2(t, der, pw, oidDESEDE3CBC, 24, oidHMACSHA256, sha256.New)

	decrypted, err := DecryptPKCS8(encrypted, pw)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if _, err := x509.ParsePKCS8PrivateKey(decrypted); err != nil {
		t.Fatalf("decrypted key invalid: %v", err)
	}
}

func TestPKCS8_Decrypt_PBKDF2_DefaultPRF(t *testing.T) {
	// When PRF is omitted, PBKDF2 defaults to HMAC-SHA1 per RFC 8018
	der := testPKCS8DER(t)
	pw := []byte("default-prf")

	salt := make([]byte, 16)
	rand.Read(salt)
	iterations := 10000
	keyLen := 32

	key := pbkdf2.Key(pw, salt, iterations, keyLen, sha1.New)

	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)

	block, _ := aes.NewCipher(key)
	padded := addPKCS7Padding(der, block.BlockSize())
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	ivBytes, _ := asn1.Marshal(iv)

	// Omit PRF to test default SHA1 behavior
	kdfParamsBytes, _ := asn1.Marshal(struct {
		Salt       []byte
		Iterations int
		KeyLength  int
	}{salt, iterations, keyLen})

	p2Bytes, _ := asn1.Marshal(pbes2Params{
		KDF: algorithmIdentifier{
			Algorithm:  oidPBKDF2,
			Parameters: asn1.RawValue{FullBytes: kdfParamsBytes},
		},
		EncryptionScheme: algorithmIdentifier{
			Algorithm:  oidAES256CBC,
			Parameters: asn1.RawValue{FullBytes: ivBytes},
		},
	})

	encrypted, _ := asn1.Marshal(encryptedPrivateKeyInfo{
		Algorithm: algorithmIdentifier{
			Algorithm:  oidPBES2,
			Parameters: asn1.RawValue{FullBytes: p2Bytes},
		},
		Data: ciphertext,
	})

	decrypted, err := DecryptPKCS8(encrypted, pw)
	if err != nil {
		t.Fatalf("decrypt with default PRF failed: %v", err)
	}
	if _, err := x509.ParsePKCS8PrivateKey(decrypted); err != nil {
		t.Fatalf("decrypted key invalid: %v", err)
	}
}

// --- scrypt KDF ---

func TestPKCS8_Decrypt_Scrypt_AES256(t *testing.T) {
	der := testPKCS8DER(t)
	pw := []byte("scrypt-test")

	salt := make([]byte, 16)
	rand.Read(salt)
	N := 16384
	r := 8
	p := 1
	keyLen := 32

	key, err := scrypt.Key(pw, salt, N, r, p, keyLen)
	if err != nil {
		t.Fatal(err)
	}

	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)

	block, _ := aes.NewCipher(key)
	padded := addPKCS7Padding(der, block.BlockSize())
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	ivBytes, _ := asn1.Marshal(iv)

	scryptP := scryptParams{
		Salt:      salt,
		CostParam: N,
		R:         r,
		P:         p,
		KeyLength: keyLen,
	}
	scryptBytes, _ := asn1.Marshal(scryptP)

	p2Bytes, _ := asn1.Marshal(pbes2Params{
		KDF: algorithmIdentifier{
			Algorithm:  oidScrypt,
			Parameters: asn1.RawValue{FullBytes: scryptBytes},
		},
		EncryptionScheme: algorithmIdentifier{
			Algorithm:  oidAES256CBC,
			Parameters: asn1.RawValue{FullBytes: ivBytes},
		},
	})

	encrypted, _ := asn1.Marshal(encryptedPrivateKeyInfo{
		Algorithm: algorithmIdentifier{
			Algorithm:  oidPBES2,
			Parameters: asn1.RawValue{FullBytes: p2Bytes},
		},
		Data: ciphertext,
	})

	decrypted, err := DecryptPKCS8(encrypted, pw)
	if err != nil {
		t.Fatalf("decrypt scrypt failed: %v", err)
	}
	if _, err := x509.ParsePKCS8PrivateKey(decrypted); err != nil {
		t.Fatalf("decrypted key invalid: %v", err)
	}
}

// --- Padding edge cases ---

func TestPKCS8_Padding_ExactBlockSize(t *testing.T) {
	// Input exactly a multiple of block size -> full block of padding added
	data := make([]byte, 16)
	padded := addPKCS7Padding(data, 16)
	if len(padded) != 32 {
		t.Errorf("expected 32 bytes (16 data + 16 padding), got %d", len(padded))
	}
	unpadded, err := removePKCS7Padding(padded, 16)
	if err != nil {
		t.Fatal(err)
	}
	if len(unpadded) != 16 {
		t.Errorf("expected 16 bytes after unpad, got %d", len(unpadded))
	}
}

func TestPKCS8_Padding_OneBytePad(t *testing.T) {
	data := make([]byte, 15) // 15 bytes -> 1 byte pad for block size 16
	padded := addPKCS7Padding(data, 16)
	if len(padded) != 16 {
		t.Errorf("expected 16 bytes, got %d", len(padded))
	}
	if padded[15] != 1 {
		t.Errorf("expected pad byte 0x01, got 0x%02x", padded[15])
	}
}

func TestPKCS8_Padding_Invalid(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"zero pad byte", append(make([]byte, 15), 0)},
		{"pad too large", append(make([]byte, 15), 17)},
		{"inconsistent padding", append(make([]byte, 14), 1, 2)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := removePKCS7Padding(tt.data, 16)
			if err == nil {
				t.Error("expected error for invalid padding")
			}
		})
	}
}

// --- OpenSSL fixture test ---

func TestPKCS8_OpenSSLFixture(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "..", "tools", "testing", "certs", "encrypted-key.key")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Skipf("fixture not available: %v", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("no PEM block found")
	}

	decrypted, err := DecryptPKCS8(block.Bytes, []byte("keypass123"))
	if err != nil {
		t.Fatalf("DecryptPKCS8 failed: %v", err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(decrypted)
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey failed: %v", err)
	}
	if parsed == nil {
		t.Error("parsed key is nil")
	}
}

func TestPKCS8_OpenSSLFixture_WrongPassword(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "..", "tools", "testing", "certs", "encrypted-key.key")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Skipf("fixture not available: %v", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("no PEM block found")
	}

	_, err = DecryptPKCS8(block.Bytes, []byte("wrong-password"))
	if err == nil {
		t.Error("expected error with wrong password on OpenSSL fixture")
	}
}

// --- Integration: ReadFile with PKCS#8 encrypted key ---

func TestPKCS8_ReadFile_Integration(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "..", "tools", "testing", "certs", "encrypted-key.key")
	if _, err := os.Stat(fixturePath); err != nil {
		t.Skipf("fixture not available: %v", err)
	}

	c, err := ReadFile(fixturePath, []TaggedPassword{{Password: []byte("keypass123"), Source: PasswordSourceCLI}})
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if len(c.ParseErrors) > 0 {
		t.Errorf("unexpected parse errors: %v", c.ParseErrors)
	}

	found := false
	for _, item := range c.Items {
		if item.Type == ContentPrivateKey {
			found = true
			if !item.Encrypted {
				t.Error("expected Encrypted=true")
			}
			if item.PrivateKey == nil {
				t.Error("expected non-nil PrivateKey")
			}
		}
	}
	if !found {
		t.Error("expected a private key item")
	}
}

// --- Unsupported KDF error ---

func TestPKCS8_UnsupportedKDF(t *testing.T) {
	fakeKDF := asn1.ObjectIdentifier{1, 2, 3, 4, 99}

	p2Bytes, _ := asn1.Marshal(pbes2Params{
		KDF: algorithmIdentifier{
			Algorithm:  fakeKDF,
			Parameters: asn1.RawValue{Tag: 5},
		},
		EncryptionScheme: algorithmIdentifier{
			Algorithm:  oidAES256CBC,
			Parameters: asn1.RawValue{Tag: 5},
		},
	})

	encrypted, _ := asn1.Marshal(encryptedPrivateKeyInfo{
		Algorithm: algorithmIdentifier{
			Algorithm:  oidPBES2,
			Parameters: asn1.RawValue{FullBytes: p2Bytes},
		},
		Data: []byte("fake"),
	})

	_, err := DecryptPKCS8(encrypted, []byte("pass"))
	if err == nil {
		t.Error("expected error for unsupported KDF")
	}
	if !strings.Contains(err.Error(), "unsupported KDF") {
		t.Errorf("error should mention unsupported KDF, got: %v", err)
	}
}

func TestPKCS8_UnsupportedCipher(t *testing.T) {
	der := testPKCS8DER(t)
	pw := []byte("test")

	salt := make([]byte, 16)
	rand.Read(salt)

	kdfParamsBytes, _ := asn1.Marshal(pbkdf2Params{
		Salt:       salt,
		Iterations: 1000,
		KeyLength:  32,
		PRF:        algorithmIdentifier{Algorithm: oidHMACSHA256, Parameters: asn1.RawValue{Tag: 5}},
	})

	// Encode a valid OCTET STRING IV so parsing reaches the cipher dispatch
	fakeIV := make([]byte, 16)
	ivBytes, _ := asn1.Marshal(fakeIV)

	fakeCipher := asn1.ObjectIdentifier{1, 2, 3, 4, 88}
	p2Bytes, _ := asn1.Marshal(pbes2Params{
		KDF: algorithmIdentifier{
			Algorithm:  oidPBKDF2,
			Parameters: asn1.RawValue{FullBytes: kdfParamsBytes},
		},
		EncryptionScheme: algorithmIdentifier{
			Algorithm:  fakeCipher,
			Parameters: asn1.RawValue{FullBytes: ivBytes},
		},
	})

	encrypted, _ := asn1.Marshal(encryptedPrivateKeyInfo{
		Algorithm: algorithmIdentifier{
			Algorithm:  oidPBES2,
			Parameters: asn1.RawValue{FullBytes: p2Bytes},
		},
		Data: der,
	})

	_, err := DecryptPKCS8(encrypted, pw)
	if err == nil {
		t.Error("expected error for unsupported cipher")
	}
	if !strings.Contains(err.Error(), "unsupported cipher") {
		t.Errorf("error should mention unsupported cipher, got: %v", err)
	}
}

// --- OpenSSL-generated PBKDF2 PRF fixtures (SHA-224 / SHA-256 / SHA-384) ---

func opensslPKCS8Key(t *testing.T, v2prf string) []byte {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skipf("openssl not available: %v", err)
	}

	dir := t.TempDir()
	rawKey := filepath.Join(dir, "raw.pem")
	encKey := filepath.Join(dir, "enc.pem")

	gen := exec.Command("openssl", "genpkey", "-algorithm", "RSA",
		"-pkeyopt", "rsa_keygen_bits:2048", "-out", rawKey)
	if out, err := gen.CombinedOutput(); err != nil {
		t.Skipf("openssl genpkey failed: %v (%s)", err, out)
	}

	enc := exec.Command("openssl", "pkcs8", "-topk8", "-in", rawKey,
		"-v2", "aes-256-cbc", "-v2prf", v2prf, "-passout", "pass:secret", "-out", encKey)
	if out, err := enc.CombinedOutput(); err != nil {
		t.Skipf("openssl pkcs8 (%s) failed: %v (%s)", v2prf, err, out)
	}

	data, err := os.ReadFile(encKey)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("no PEM block found in openssl output")
	}
	return block.Bytes
}

func TestPKCS8_OpenSSL_PBKDF2_PRF(t *testing.T) {
	cases := []struct {
		name  string
		v2prf string
	}{
		{"sha256", "hmacWithSHA256"},
		{"sha384", "hmacWithSHA384"},
		{"sha224", "hmacWithSHA224"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			der := opensslPKCS8Key(t, tc.v2prf)

			decrypted, err := DecryptPKCS8(der, []byte("secret"))
			if err != nil {
				t.Fatalf("DecryptPKCS8 with correct password failed for %s: %v", tc.v2prf, err)
			}
			if _, err := x509.ParsePKCS8PrivateKey(decrypted); err != nil {
				t.Fatalf("decrypted key invalid for %s: %v", tc.v2prf, err)
			}

			if _, err := DecryptPKCS8(der, []byte("wrong")); err == nil {
				t.Errorf("expected error with wrong password for %s", tc.v2prf)
			}
		})
	}
}
