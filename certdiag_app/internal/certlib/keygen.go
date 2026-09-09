package certlib

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"
)

func GenerateKey(opts KeyGenOptions) (crypto.PrivateKey, error) {
	switch strings.ToLower(opts.Algorithm) {
	case "rsa":
		switch opts.KeySize {
		case 2048, 3072, 4096:
		default:
			return nil, fmt.Errorf("unsupported RSA key size %d (valid: 2048, 3072, 4096)", opts.KeySize)
		}
		return rsa.GenerateKey(rand.Reader, opts.KeySize)

	case "ecdsa":
		var curve elliptic.Curve
		switch strings.ToLower(opts.Curve) {
		case "p256":
			curve = elliptic.P256()
		case "p384":
			curve = elliptic.P384()
		case "p521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported ECDSA curve %q (valid: p256, p384, p521)", opts.Curve)
		}
		return ecdsa.GenerateKey(curve, rand.Reader)

	case "ed25519":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err

	default:
		return nil, fmt.Errorf("unsupported algorithm %q (valid: rsa, ecdsa, ed25519)", opts.Algorithm)
	}
}
