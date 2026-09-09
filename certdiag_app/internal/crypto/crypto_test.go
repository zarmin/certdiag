package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"normal_text", []byte("hello world")},
		{"empty", []byte("")},
		{"binary_data", []byte{0x00, 0xFF, 0x01, 0xFE, 0x80, 0x7F}},
		{"large_10KB", make([]byte, 10*1024)},
		{"single_byte", []byte{0x42}},
		{"unicode", []byte("caf\xc3\xa9 \xe2\x98\x95")},
	}

	// fill large test case with random data
	for i := range tests {
		if tests[i].name == "large_10KB" {
			rand.Read(tests[i].plaintext)
		}
	}

	pw := []byte("test-password")

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := Encrypt(pw, tc.plaintext)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}

			got, err := Decrypt(pw, encoded)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}

			if !bytes.Equal(got, tc.plaintext) {
				t.Errorf("round-trip mismatch: got %d bytes, want %d bytes", len(got), len(tc.plaintext))
			}
		})
	}
}

func TestDecrypt_WrongPassword(t *testing.T) {
	encoded, err := Encrypt([]byte("pw1"), []byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = Decrypt([]byte("pw2"), encoded)
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestDecrypt_InvalidBase64(t *testing.T) {
	_, err := Decrypt([]byte("pw"), "not-valid-base64!!!")
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestDecrypt_TruncatedBlob(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(make([]byte, 10))
	_, err := Decrypt([]byte("pw"), short)
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestDecrypt_EmptyString(t *testing.T) {
	_, err := Decrypt([]byte("pw"), "")
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestDecrypt_CorruptedCiphertext(t *testing.T) {
	encoded, err := Encrypt([]byte("pw"), []byte("data"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	blob, _ := base64.StdEncoding.DecodeString(encoded)
	// flip bytes in the ciphertext portion (after salt+nonce)
	for i := saltLen + nonceLen; i < len(blob) && i < saltLen+nonceLen+5; i++ {
		blob[i] ^= 0xFF
	}
	corrupted := base64.StdEncoding.EncodeToString(blob)

	_, err = Decrypt([]byte("pw"), corrupted)
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestDecrypt_TruncatedCiphertext(t *testing.T) {
	encoded, err := Encrypt([]byte("pw"), []byte("data"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	blob, _ := base64.StdEncoding.DecodeString(encoded)
	// chop last 5 bytes
	truncated := base64.StdEncoding.EncodeToString(blob[:len(blob)-5])

	_, err = Decrypt([]byte("pw"), truncated)
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestDeriveKey_Deterministic(t *testing.T) {
	pw := []byte("password")
	salt := []byte("0123456789abcdef")

	k1 := deriveKey(pw, salt)
	k2 := deriveKey(pw, salt)
	if !bytes.Equal(k1, k2) {
		t.Error("same password + same salt produced different keys")
	}
}

func TestDeriveKey_DifferentPassword(t *testing.T) {
	salt := []byte("0123456789abcdef")
	k1 := deriveKey([]byte("pw1"), salt)
	k2 := deriveKey([]byte("pw2"), salt)
	if bytes.Equal(k1, k2) {
		t.Error("different passwords produced same key")
	}
}

func TestDeriveKey_DifferentSalt(t *testing.T) {
	pw := []byte("password")
	k1 := deriveKey(pw, []byte("salt_aaaaaaaaaaaa"))
	k2 := deriveKey(pw, []byte("salt_bbbbbbbbbbbb"))
	if bytes.Equal(k1, k2) {
		t.Error("different salts produced same key")
	}
}

type budgetReader struct {
	budget int
}

func (r *budgetReader) Read(p []byte) (int, error) {
	if r.budget <= 0 {
		return 0, errors.New("rand exhausted")
	}
	n := len(p)
	if n > r.budget {
		n = r.budget
	}
	for i := 0; i < n; i++ {
		p[i] = 0x01
	}
	r.budget -= n
	return n, nil
}

func TestEncrypt_PaddingRandFailure(t *testing.T) {
	orig := rand.Reader
	defer func() { rand.Reader = orig }()

	// salt (16) + nonce (12) + padByte (1) succeed, padding read fails
	rand.Reader = &budgetReader{budget: saltLen + nonceLen + 1}

	_, err := Encrypt([]byte("pw"), []byte("data"))
	if err == nil {
		t.Fatal("expected error when padding rand read fails, got nil")
	}
}

func TestEncrypt_PadByteRandFailure(t *testing.T) {
	orig := rand.Reader
	defer func() { rand.Reader = orig }()

	// salt (16) + nonce (12) succeed, padByte read fails
	rand.Reader = &budgetReader{budget: saltLen + nonceLen}

	_, err := Encrypt([]byte("pw"), []byte("data"))
	if err == nil {
		t.Fatal("expected error when padByte rand read fails, got nil")
	}
}

func TestEncrypt_NonDeterministic(t *testing.T) {
	pw := []byte("password")
	plaintext := []byte("same data")

	e1, err := Encrypt(pw, plaintext)
	if err != nil {
		t.Fatalf("Encrypt 1: %v", err)
	}
	e2, err := Encrypt(pw, plaintext)
	if err != nil {
		t.Fatalf("Encrypt 2: %v", err)
	}

	if e1 == e2 {
		t.Error("two encryptions of same data produced identical ciphertext")
	}
}
