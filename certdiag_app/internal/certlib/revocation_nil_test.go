package certlib

import (
	"testing"
)

// The revocation entry points must tolerate a nil certificate (undetermined,
// not panic): callers resolve the cert and issuer independently and either can
// legitimately be missing.

func TestResolveRevocationNilCert(t *testing.T) {
	res := ResolveRevocation(nil, nil, nil, RevocationOptions{})
	if res.Status != RevocationUndetermined {
		t.Errorf("status = %s, want undetermined", res.Status)
	}
	if len(res.Attempts) != 1 || res.Attempts[0].Err != "no certificate" {
		t.Errorf("attempts = %+v, want one 'no certificate' attempt", res.Attempts)
	}
}

func TestCheckCRLNilCert(t *testing.T) {
	res := CheckCRL([]byte("not a crl"), nil, nil)
	if res.Status != RevocationUndetermined {
		t.Errorf("status = %s, want undetermined", res.Status)
	}
	if len(res.Attempts) != 1 || res.Attempts[0].Err != "no certificate" {
		t.Errorf("attempts = %+v, want one 'no certificate' attempt", res.Attempts)
	}
}

func TestQueryOCSPNilLeaf(t *testing.T) {
	res := QueryOCSP(nil, nil, []string{"http://ocsp.example"}, RevocationOptions{})
	if res.Status != RevocationUndetermined {
		t.Errorf("status = %s, want undetermined", res.Status)
	}
	if len(res.Attempts) != 1 || res.Attempts[0].Err != "no certificate" {
		t.Errorf("attempts = %+v, want one 'no certificate' attempt", res.Attempts)
	}
}
