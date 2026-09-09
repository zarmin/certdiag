package certlib

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	tests := []struct {
		name      string
		opts      KeyGenOptions
		wantType  string
		wantBits  int
		wantCurve elliptic.Curve
		wantErr   bool
	}{
		{
			name:     "RSA/2048",
			opts:     KeyGenOptions{Algorithm: "rsa", KeySize: 2048},
			wantType: "rsa",
			wantBits: 2048,
		},
		{
			name:     "RSA/3072",
			opts:     KeyGenOptions{Algorithm: "rsa", KeySize: 3072},
			wantType: "rsa",
			wantBits: 3072,
		},
		{
			name:     "RSA/4096",
			opts:     KeyGenOptions{Algorithm: "rsa", KeySize: 4096},
			wantType: "rsa",
			wantBits: 4096,
		},
		{
			name:      "ECDSA/P256",
			opts:      KeyGenOptions{Algorithm: "ecdsa", Curve: "p256"},
			wantType:  "ecdsa",
			wantCurve: elliptic.P256(),
		},
		{
			name:      "ECDSA/P384",
			opts:      KeyGenOptions{Algorithm: "ecdsa", Curve: "p384"},
			wantType:  "ecdsa",
			wantCurve: elliptic.P384(),
		},
		{
			name:      "ECDSA/P521",
			opts:      KeyGenOptions{Algorithm: "ecdsa", Curve: "p521"},
			wantType:  "ecdsa",
			wantCurve: elliptic.P521(),
		},
		{
			name:     "Ed25519",
			opts:     KeyGenOptions{Algorithm: "ed25519"},
			wantType: "ed25519",
		},
		{
			name:     "CaseInsensitive",
			opts:     KeyGenOptions{Algorithm: "RSA", KeySize: 2048},
			wantType: "rsa",
			wantBits: 2048,
		},
		{
			name:    "Error/InvalidAlgorithm",
			opts:    KeyGenOptions{Algorithm: "blowfish"},
			wantErr: true,
		},
		{
			name:    "Error/InvalidCurve",
			opts:    KeyGenOptions{Algorithm: "ecdsa", Curve: "p999"},
			wantErr: true,
		},
		{
			name:    "Error/RSASize1024",
			opts:    KeyGenOptions{Algorithm: "rsa", KeySize: 1024},
			wantErr: true,
		},
		{
			name:    "Error/RSASize0",
			opts:    KeyGenOptions{Algorithm: "rsa", KeySize: 0},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := GenerateKey(tc.opts)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			switch tc.wantType {
			case "rsa":
				rsaKey, ok := key.(*rsa.PrivateKey)
				if !ok {
					t.Fatalf("expected *rsa.PrivateKey, got %T", key)
				}
				if rsaKey.N.BitLen() != tc.wantBits {
					t.Errorf("RSA bits = %d, want %d", rsaKey.N.BitLen(), tc.wantBits)
				}
			case "ecdsa":
				ecKey, ok := key.(*ecdsa.PrivateKey)
				if !ok {
					t.Fatalf("expected *ecdsa.PrivateKey, got %T", key)
				}
				if ecKey.Curve != tc.wantCurve {
					t.Errorf("ECDSA curve = %v, want %v", ecKey.Curve, tc.wantCurve)
				}
			case "ed25519":
				if _, ok := key.(ed25519.PrivateKey); !ok {
					t.Fatalf("expected ed25519.PrivateKey, got %T", key)
				}
			}
		})
	}
}
