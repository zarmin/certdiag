package tls

import "crypto/cipher"

// TLS13Decrypted holds the recovered pieces of a decrypted TLS 1.3 flow.
type TLS13Decrypted struct {
	ServerHandshake []byte // reassembled server handshake (EncExt, Certificate, ...)
	ClientApp       []byte // decrypted client application data
	ServerApp       []byte // decrypted server application data
}

// DecryptTLS13 decrypts a TLS 1.3 flow: the server's encrypted handshake (for the
// certificate) and both directions' application data, using the handshake and
// application traffic secrets from the keylog.
func DecryptTLS13(clientData, serverData, clientRandom []byte, cipherSuite uint16, kl *KeyLog) (*TLS13Decrypted, error) {
	suite, ok := lookupCipherSuite13(cipherSuite)
	if !ok {
		return nil, ErrNoHandshakeSecret
	}
	out := &TLS13Decrypted{}

	sHS, ok := kl.Secret(clientRandom, KeyLogServerHandshakeTrafficSecret)
	if !ok {
		return nil, ErrNoHandshakeSecret
	}
	hsAEAD, hsIV, err := deriveAEAD(suite, sHS)
	if err != nil {
		return nil, err
	}
	appAEAD, appIV := optionalAEAD(suite, kl, clientRandom, KeyLogServerTrafficSecret0)
	srecs, _, _ := ParseRecords(serverData)
	out.ServerHandshake, out.ServerApp = decryptTLS13Records(srecs, hsAEAD, hsIV, appAEAD, appIV)

	if cHS, ok := kl.Secret(clientRandom, KeyLogClientHandshakeTrafficSecret); ok {
		cHsAEAD, cHsIV, err := deriveAEAD(suite, cHS)
		if err == nil {
			cAppAEAD, cAppIV := optionalAEAD(suite, kl, clientRandom, KeyLogClientTrafficSecret0)
			crecs, _, _ := ParseRecords(clientData)
			_, out.ClientApp = decryptTLS13Records(crecs, cHsAEAD, cHsIV, cAppAEAD, cAppIV)
		}
	}
	return out, nil
}

func deriveAEAD(suite *cipherSuite13, secret []byte) (cipher.AEAD, []byte, error) {
	key, iv, err := suite.deriveKeyIV(secret)
	if err != nil {
		return nil, nil, err
	}
	aead, err := suite.newAEAD(key)
	if err != nil {
		return nil, nil, err
	}
	return aead, iv, nil
}

func optionalAEAD(suite *cipherSuite13, kl *KeyLog, clientRandom []byte, label string) (cipher.AEAD, []byte) {
	secret, ok := kl.Secret(clientRandom, label)
	if !ok {
		return nil, nil
	}
	aead, iv, err := deriveAEAD(suite, secret)
	if err != nil {
		return nil, nil
	}
	return aead, iv
}

// decryptTLS13Records walks the application-data records of one direction,
// decrypting the encrypted handshake with the handshake key, then (once that key
// stops working, i.e. after Finished) switching to the application key. Returns
// the handshake bytes and the application-data bytes.
func decryptTLS13Records(records []Record, hsAEAD cipher.AEAD, hsIV []byte, appAEAD cipher.AEAD, appIV []byte) (hsBytes, appBytes []byte) {
	inHandshake := true
	var seq uint64

	for _, rec := range records {
		if rec.Type != ContentApplicationData {
			continue
		}

		if inHandshake {
			inner, itype, err := decryptRecord13(hsAEAD, hsIV, seq, rec)
			if err == nil {
				seq++
				if itype == ContentHandshake {
					hsBytes = append(hsBytes, inner...)
				}
				continue
			}
			// Handshake key no longer decrypts: switch to the application key.
			if appAEAD == nil {
				break
			}
			inHandshake = false
			seq = 0
		}

		inner, itype, err := decryptRecord13(appAEAD, appIV, seq, rec)
		if err != nil {
			break
		}
		seq++
		if itype == ContentApplicationData {
			appBytes = append(appBytes, inner...)
		}
	}
	return hsBytes, appBytes
}
