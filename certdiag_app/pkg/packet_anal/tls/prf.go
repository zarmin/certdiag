package tls

import (
	"crypto/hmac"
	"hash"
)

// prf12 is the TLS 1.2 pseudorandom function (RFC 5246 section 5): P_hash over
// HMAC with the cipher suite's hash.
func prf12(hashFn func() hash.Hash, secret, label, seed []byte, length int) []byte {
	labelSeed := make([]byte, 0, len(label)+len(seed))
	labelSeed = append(labelSeed, label...)
	labelSeed = append(labelSeed, seed...)

	out := make([]byte, 0, length)
	a := labelSeed // A(0)
	for len(out) < length {
		// A(i) = HMAC(secret, A(i-1))
		am := hmac.New(hashFn, secret)
		am.Write(a)
		a = am.Sum(nil)

		// block = HMAC(secret, A(i) || labelSeed)
		bm := hmac.New(hashFn, secret)
		bm.Write(a)
		bm.Write(labelSeed)
		out = append(out, bm.Sum(nil)...)
	}
	return out[:length]
}
