package certlib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// --- fixtures -------------------------------------------------------------

type testPKI struct {
	caCert   *x509.Certificate
	caKey    *ecdsa.PrivateKey
	wrongCA  *x509.Certificate
	wrongKey *ecdsa.PrivateKey
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	ca, caKey := makeCA(t, "Test Root CA")
	wrong, wrongKey := makeCA(t, "Wrong CA")
	return &testPKI{caCert: ca, caKey: caKey, wrongCA: wrong, wrongKey: wrongKey}
}

func makeCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func makeLeaf(t *testing.T, pki *testPKI, serial int64, ocspURLs, crlURLs []string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		OCSPServer:            ocspURLs,
		CRLDistributionPoints: crlURLs,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, pki.caCert, &key.PublicKey, pki.caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// makeDelegatedResponder returns a responder cert signed by the CA, with or
// without the OCSPSigning EKU.
func makeDelegatedResponder(t *testing.T, pki *testPKI, withEKU bool) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(999),
		Subject:      pkix.Name{CommonName: "delegated responder"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	if withEKU {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, pki.caCert, &key.PublicKey, pki.caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func makeOCSPResponse(t *testing.T, pki *testPKI, leaf *x509.Certificate, status, reason int, responderCert *x509.Certificate, responderKey *ecdsa.PrivateKey) []byte {
	t.Helper()
	now := time.Now()
	tmpl := ocsp.Response{
		Status:       status,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   now.Add(-time.Minute),
		NextUpdate:   now.Add(time.Hour),
	}
	if status == ocsp.Revoked {
		tmpl.RevokedAt = now.Add(-time.Minute)
		tmpl.RevocationReason = reason
	}
	// A delegated responder must embed its cert so the parser can chain it to
	// the issuer; CreateResponse only embeds when template.Certificate is set.
	if responderCert != pki.caCert {
		tmpl.Certificate = responderCert
	}
	der, err := ocsp.CreateResponse(pki.caCert, responderCert, tmpl, responderKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func makeCRL(t *testing.T, cert *x509.Certificate, key *ecdsa.PrivateKey, revoked map[int64]int, nextUpdate time.Time) []byte {
	t.Helper()
	var entries []x509.RevocationListEntry
	for serial, reason := range revoked {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   big.NewInt(serial),
			RevocationTime: time.Now().Add(-time.Minute),
			ReasonCode:     reason,
		})
	}
	tmpl := &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                nextUpdate.Add(-time.Hour),
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// makeScopedCRL builds a same-issuer CRL carrying a scope-limiting extension
// (issuing distribution point or delta CRL indicator) so its "not listed"
// result cannot be read as a complete "good".
func makeScopedCRL(t *testing.T, pki *testPKI, revoked map[int64]int, nextUpdate time.Time, scopeOID asn1.ObjectIdentifier) []byte {
	t.Helper()
	var entries []x509.RevocationListEntry
	for serial, reason := range revoked {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   big.NewInt(serial),
			RevocationTime: time.Now().Add(-time.Minute),
			ReasonCode:     reason,
		})
	}
	tmpl := &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                nextUpdate.Add(-time.Hour),
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
		ExtraExtensions:           []pkix.Extension{{Id: scopeOID, Value: []byte{0x30, 0x00}}},
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, pki.caCert, pki.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// --- CheckOCSPStaple ------------------------------------------------------

func TestCheckOCSPStaple(t *testing.T) {
	pki := newTestPKI(t)
	leaf := makeLeaf(t, pki, 100, nil, nil)

	t.Run("empty returns nil", func(t *testing.T) {
		if CheckOCSPStaple(nil, leaf, pki.caCert) != nil {
			t.Fatal("expected nil for empty staple")
		}
	})

	t.Run("good issuer-signed verified", func(t *testing.T) {
		der := makeOCSPResponse(t, pki, leaf, ocsp.Good, 0, pki.caCert, pki.caKey)
		res := CheckOCSPStaple(der, leaf, pki.caCert)
		if res.Status != RevocationGood || !res.Verified {
			t.Fatalf("got status=%s verified=%v", res.Status, res.Verified)
		}
	})

	t.Run("revoked carries reason and time", func(t *testing.T) {
		der := makeOCSPResponse(t, pki, leaf, ocsp.Revoked, ocsp.KeyCompromise, pki.caCert, pki.caKey)
		res := CheckOCSPStaple(der, leaf, pki.caCert)
		if res.Status != RevocationRevoked {
			t.Fatalf("got status=%s", res.Status)
		}
		if res.Reason != reasonKeyCompromise {
			t.Fatalf("got reason=%s", res.Reason)
		}
		if res.RevokedAt.IsZero() {
			t.Fatal("expected RevokedAt set")
		}
	})

	t.Run("garbage bytes undetermined", func(t *testing.T) {
		res := CheckOCSPStaple([]byte("not an ocsp response"), leaf, pki.caCert)
		if res.Status != RevocationUndetermined {
			t.Fatalf("got status=%s", res.Status)
		}
		if len(res.Attempts) == 0 || res.Attempts[0].Err == "" {
			t.Fatal("expected an attempt error")
		}
	})

	t.Run("delegated with EKU verified", func(t *testing.T) {
		rc, rk := makeDelegatedResponder(t, pki, true)
		der := makeOCSPResponse(t, pki, leaf, ocsp.Good, 0, rc, rk)
		res := CheckOCSPStaple(der, leaf, pki.caCert)
		if res.Status != RevocationGood || !res.Verified {
			t.Fatalf("got status=%s verified=%v", res.Status, res.Verified)
		}
	})

	t.Run("delegated without EKU not verified", func(t *testing.T) {
		rc, rk := makeDelegatedResponder(t, pki, false)
		der := makeOCSPResponse(t, pki, leaf, ocsp.Good, 0, rc, rk)
		res := CheckOCSPStaple(der, leaf, pki.caCert)
		if res.Verified {
			t.Fatal("delegated responder without OCSPSigning EKU must not verify")
		}
	})

	t.Run("stale good staple cannot prove good", func(t *testing.T) {
		der := makeStaleOCSPResponse(t, pki, leaf, ocsp.Good)
		res := CheckOCSPStaple(der, leaf, pki.caCert)
		if res.Status != RevocationUndetermined {
			t.Fatalf("stale good staple must not be determinate, got status=%s", res.Status)
		}
		if len(res.Attempts) == 0 || res.Attempts[0].Err == "" {
			t.Fatal("expected freshness note in attempt")
		}
	})

	t.Run("stale revoked staple stays revoked", func(t *testing.T) {
		der := makeStaleOCSPResponse(t, pki, leaf, ocsp.Revoked)
		res := CheckOCSPStaple(der, leaf, pki.caCert)
		if res.Status != RevocationRevoked {
			t.Fatalf("stale revoked staple must stay revoked, got status=%s", res.Status)
		}
	})

	t.Run("staple for a different cert rejected (nil issuer)", func(t *testing.T) {
		other := makeLeaf(t, pki, 12345, nil, nil)
		der := makeOCSPResponse(t, pki, other, ocsp.Good, 0, pki.caCert, pki.caKey)
		// nil issuer takes the ParseResponse path that skips serial matching.
		res := CheckOCSPStaple(der, leaf, nil)
		if res.Status != RevocationUndetermined {
			t.Fatalf("staple for a different serial must be undetermined, got status=%s", res.Status)
		}
		if len(res.Attempts) == 0 || res.Attempts[0].Err == "" {
			t.Fatal("expected a serial-mismatch attempt error")
		}
	})
}

// makeStaleOCSPResponse builds an issuer-signed OCSP response whose nextUpdate
// lies in the past.
func makeStaleOCSPResponse(t *testing.T, pki *testPKI, leaf *x509.Certificate, status int) []byte {
	t.Helper()
	now := time.Now()
	tmpl := ocsp.Response{
		Status:       status,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   now.Add(-2 * time.Hour),
		NextUpdate:   now.Add(-time.Hour),
	}
	if status == ocsp.Revoked {
		tmpl.RevokedAt = now.Add(-2 * time.Hour)
		tmpl.RevocationReason = ocsp.KeyCompromise
	}
	der, err := ocsp.CreateResponse(pki.caCert, pki.caCert, tmpl, pki.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestResolveRevocationStaleStaple asserts a stale "good" staple no longer
// short-circuits resolution: the fresh revoked CRL must win.
func TestResolveRevocationStaleStaple(t *testing.T) {
	pki := newTestPKI(t)
	leaf := makeLeaf(t, pki, 400, nil, nil)
	staple := makeStaleOCSPResponse(t, pki, leaf, ocsp.Good)

	crl := makeCRL(t, pki.caCert, pki.caKey, map[int64]int{400: 1}, time.Now().Add(time.Hour))
	crlPath := filepath.Join(t.TempDir(), "fresh.crl")
	if err := os.WriteFile(crlPath, crl, 0o600); err != nil {
		t.Fatal(err)
	}

	res := ResolveRevocation(leaf, pki.caCert, staple, RevocationOptions{CRLFile: crlPath})
	if res.Status != RevocationRevoked {
		t.Fatalf("fresh revoked CRL must override stale good staple, got status=%s", res.Status)
	}
}

// --- CheckCRL -------------------------------------------------------------

func TestCheckCRL(t *testing.T) {
	pki := newTestPKI(t)
	leaf := makeLeaf(t, pki, 200, nil, nil)
	future := time.Now().Add(time.Hour)

	t.Run("serial listed revoked", func(t *testing.T) {
		crl := makeCRL(t, pki.caCert, pki.caKey, map[int64]int{200: 1}, future)
		res := CheckCRL(crl, leaf, pki.caCert)
		if res.Status != RevocationRevoked || res.Reason != reasonKeyCompromise {
			t.Fatalf("got status=%s reason=%s", res.Status, res.Reason)
		}
		if !res.Verified {
			t.Fatal("expected verified against issuer")
		}
	})

	t.Run("serial not listed good", func(t *testing.T) {
		crl := makeCRL(t, pki.caCert, pki.caKey, map[int64]int{999: 1}, future)
		res := CheckCRL(crl, leaf, pki.caCert)
		if res.Status != RevocationGood {
			t.Fatalf("got status=%s", res.Status)
		}
	})

	t.Run("wrong issuer CRL is out of scope", func(t *testing.T) {
		// A CRL from a different CA proves nothing about this cert; a serial
		// match there is coincidental and must not be reported as revoked.
		crl := makeCRL(t, pki.wrongCA, pki.wrongKey, map[int64]int{200: 1}, future)
		res := CheckCRL(crl, leaf, pki.caCert)
		if res.Status != RevocationUndetermined {
			t.Fatalf("wrong-issuer CRL must be undetermined, got status=%s", res.Status)
		}
		if res.Verified {
			t.Fatal("must not verify against a different issuer")
		}
	})

	t.Run("wrong issuer not-listed is not good", func(t *testing.T) {
		crl := makeCRL(t, pki.wrongCA, pki.wrongKey, map[int64]int{999: 1}, future)
		res := CheckCRL(crl, leaf, pki.caCert)
		if res.Status != RevocationUndetermined {
			t.Fatalf("wrong-issuer CRL must not yield good, got status=%s", res.Status)
		}
	})

	t.Run("partitioned CRL not-listed is undetermined", func(t *testing.T) {
		crl := makeScopedCRL(t, pki, map[int64]int{999: 1}, future, oidIssuingDistributionPoint)
		res := CheckCRL(crl, leaf, pki.caCert)
		if res.Status != RevocationUndetermined {
			t.Fatalf("partitioned CRL absence must be undetermined, got status=%s", res.Status)
		}
	})

	t.Run("partitioned CRL listed is still revoked", func(t *testing.T) {
		crl := makeScopedCRL(t, pki, map[int64]int{200: 1}, future, oidIssuingDistributionPoint)
		res := CheckCRL(crl, leaf, pki.caCert)
		if res.Status != RevocationRevoked {
			t.Fatalf("being listed in a same-issuer partition is authoritative, got status=%s", res.Status)
		}
	})

	t.Run("delta CRL not-listed is undetermined", func(t *testing.T) {
		crl := makeScopedCRL(t, pki, map[int64]int{999: 1}, future, oidDeltaCRLIndicator)
		res := CheckCRL(crl, leaf, pki.caCert)
		if res.Status != RevocationUndetermined {
			t.Fatalf("delta CRL absence must be undetermined, got status=%s", res.Status)
		}
	})

	t.Run("forged CRL (same issuer DN, bad signature) is undetermined", func(t *testing.T) {
		// A CRL with the correct issuer DN but signed by a different key must not
		// yield a verdict when we can check the signature - it is forged/corrupt.
		forger, forgerKey := makeCA(t, "Test Root CA") // same CN, different key
		crl := makeCRL(t, forger, forgerKey, map[int64]int{200: 1}, future)
		res := CheckCRL(crl, leaf, pki.caCert)
		if res.Status != RevocationUndetermined {
			t.Fatalf("forged CRL listing the serial must be undetermined, not revoked, got status=%s", res.Status)
		}
		if res.Verified {
			t.Fatal("forged CRL must not verify")
		}
	})

	t.Run("nil issuer lookup only", func(t *testing.T) {
		crl := makeCRL(t, pki.caCert, pki.caKey, map[int64]int{200: 1}, future)
		res := CheckCRL(crl, leaf, nil)
		if res.Status != RevocationRevoked || res.Verified {
			t.Fatalf("got status=%s verified=%v", res.Status, res.Verified)
		}
	})

	t.Run("expired crl cannot prove good", func(t *testing.T) {
		crl := makeCRL(t, pki.caCert, pki.caKey, map[int64]int{999: 1}, time.Now().Add(-time.Hour))
		res := CheckCRL(crl, leaf, pki.caCert)
		if res.Status != RevocationUndetermined {
			t.Fatalf("stale CRL must not yield good, got status=%s", res.Status)
		}
		if len(res.Attempts) == 0 || res.Attempts[0].Err == "" {
			t.Fatal("expected freshness note in attempt")
		}
	})

	t.Run("expired crl still proves revoked", func(t *testing.T) {
		crl := makeCRL(t, pki.caCert, pki.caKey, map[int64]int{200: 1}, time.Now().Add(-time.Hour))
		res := CheckCRL(crl, leaf, pki.caCert)
		if res.Status != RevocationRevoked {
			t.Fatalf("stale revoked listing must stay revoked, got status=%s", res.Status)
		}
		if len(res.Attempts) == 0 || res.Attempts[0].Err == "" {
			t.Fatal("expected freshness note in attempt")
		}
	})

	t.Run("malformed undetermined", func(t *testing.T) {
		res := CheckCRL([]byte("garbage"), leaf, pki.caCert)
		if res.Status != RevocationUndetermined {
			t.Fatalf("got status=%s", res.Status)
		}
	})
}

// --- QueryOCSP / FetchCRL over httptest -----------------------------------

func TestQueryOCSPHTTP(t *testing.T) {
	pki := newTestPKI(t)
	leaf := makeLeaf(t, pki, 300, nil, nil)

	newOCSPServer := func(status int) *httptest.Server {
		body := makeOCSPResponse(t, pki, leaf, status, ocsp.KeyCompromise, pki.caCert, pki.caKey)
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", ocspResponseContentType)
			w.Write(body)
		}))
	}

	t.Run("good", func(t *testing.T) {
		srv := newOCSPServer(ocsp.Good)
		defer srv.Close()
		res := QueryOCSP(leaf, pki.caCert, []string{srv.URL}, RevocationOptions{HTTPClient: srv.Client()})
		if res.Status != RevocationGood {
			t.Fatalf("got %s", res.Status)
		}
	})

	t.Run("revoked", func(t *testing.T) {
		srv := newOCSPServer(ocsp.Revoked)
		defer srv.Close()
		res := QueryOCSP(leaf, pki.caCert, []string{srv.URL}, RevocationOptions{HTTPClient: srv.Client()})
		if res.Status != RevocationRevoked {
			t.Fatalf("got %s", res.Status)
		}
	})

	t.Run("non-200 records attempt error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()
		res := QueryOCSP(leaf, pki.caCert, []string{srv.URL}, RevocationOptions{HTTPClient: srv.Client()})
		if res.Status != RevocationUndetermined || len(res.Attempts) == 0 || res.Attempts[0].Err == "" {
			t.Fatalf("expected undetermined with error, got %+v", res)
		}
	})

	t.Run("nil issuer undetermined", func(t *testing.T) {
		res := QueryOCSP(leaf, nil, []string{"http://x"}, RevocationOptions{})
		if res.Status != RevocationUndetermined {
			t.Fatalf("got %s", res.Status)
		}
	})

	t.Run("second url succeeds after first fails", func(t *testing.T) {
		bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		}))
		defer bad.Close()
		good := newOCSPServer(ocsp.Good)
		defer good.Close()
		res := QueryOCSP(leaf, pki.caCert, []string{bad.URL, good.URL}, RevocationOptions{HTTPClient: good.Client()})
		if res.Status != RevocationGood {
			t.Fatalf("got %s (attempts=%d)", res.Status, len(res.Attempts))
		}
	})

	t.Run("unknown then failure leaves no stale state and explains itself", func(t *testing.T) {
		unknown := newOCSPServer(ocsp.Unknown)
		defer unknown.Close()
		bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		}))
		defer bad.Close()

		res := QueryOCSP(leaf, pki.caCert, []string{unknown.URL, bad.URL}, RevocationOptions{HTTPClient: unknown.Client()})
		if res.Status != RevocationUndetermined {
			t.Fatalf("got %s, want undetermined", res.Status)
		}
		if res.Verified {
			t.Error("the unknown response's verified flag leaked into the final result")
		}
		if !res.NextUpdate.IsZero() || !res.ThisUpdate.IsZero() {
			t.Error("the unknown response's timestamps leaked into the final result")
		}
		if s := attemptSummary(res); s == "" {
			t.Error("undetermined result must carry an explanation (unknown status)")
		}
	})
}

func TestFetchCRLLimitsAndScheme(t *testing.T) {
	t.Run("rejects non-http scheme", func(t *testing.T) {
		if _, err := FetchCRL("ldap://example.com/crl", RevocationOptions{}); err == nil {
			t.Fatal("expected scheme rejection")
		}
	})

	t.Run("rejects oversize body", func(t *testing.T) {
		big := make([]byte, crlMaxResponseSize+10)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(big)
		}))
		defer srv.Close()
		if _, err := FetchCRL(srv.URL, RevocationOptions{HTTPClient: srv.Client()}); err == nil {
			t.Fatal("expected oversize rejection")
		}
	})
}

// --- ResolveRevocation ----------------------------------------------------

func TestResolveRevocation(t *testing.T) {
	pki := newTestPKI(t)

	t.Run("staple wins in auto", func(t *testing.T) {
		leaf := makeLeaf(t, pki, 400, nil, nil)
		staple := makeOCSPResponse(t, pki, leaf, ocsp.Good, 0, pki.caCert, pki.caKey)
		res := ResolveRevocation(leaf, pki.caCert, staple, RevocationOptions{Method: RevocationMethodAuto})
		if res.Status != RevocationGood || res.Method != RevocationMethodStapledOCSP {
			t.Fatalf("got status=%s method=%s", res.Status, res.Method)
		}
	})

	t.Run("method=crl skips ocsp entirely", func(t *testing.T) {
		var ocspHits int
		ocspSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ocspHits++
			w.Write([]byte("x"))
		}))
		defer ocspSrv.Close()

		leaf := makeLeaf(t, pki, 401, []string{ocspSrv.URL}, nil)
		crl := makeCRL(t, pki.caCert, pki.caKey, map[int64]int{401: 1}, time.Now().Add(time.Hour))
		crlPath := filepath.Join(t.TempDir(), "test.crl")
		if err := os.WriteFile(crlPath, crl, 0644); err != nil {
			t.Fatal(err)
		}
		res := ResolveRevocation(leaf, pki.caCert, nil, RevocationOptions{Method: RevocationMethodCRL, CRLFile: crlPath})
		if res.Status != RevocationRevoked || res.Method != RevocationMethodCRLFile {
			t.Fatalf("got status=%s method=%s", res.Status, res.Method)
		}
		if ocspHits != 0 {
			t.Fatalf("OCSP endpoint hit %d times under method=crl", ocspHits)
		}
	})

	t.Run("all fail undetermined with attempts", func(t *testing.T) {
		leaf := makeLeaf(t, pki, 402, nil, nil)
		res := ResolveRevocation(leaf, pki.caCert, nil, RevocationOptions{Method: RevocationMethodAuto})
		if res.Status != RevocationUndetermined {
			t.Fatalf("got %s", res.Status)
		}
	})

	t.Run("crl file path no network", func(t *testing.T) {
		leaf := makeLeaf(t, pki, 403, nil, nil)
		crl := makeCRL(t, pki.caCert, pki.caKey, map[int64]int{403: 5}, time.Now().Add(time.Hour))
		crlPath := filepath.Join(t.TempDir(), "test.crl")
		if err := os.WriteFile(crlPath, crl, 0644); err != nil {
			t.Fatal(err)
		}
		res := ResolveRevocation(leaf, pki.caCert, nil, RevocationOptions{Method: RevocationMethodAuto, CRLFile: crlPath})
		if res.Status != RevocationRevoked || res.Reason != reasonCessationOfOperation {
			t.Fatalf("got status=%s reason=%s", res.Status, res.Reason)
		}
	})
}

func TestRevocationReasonString(t *testing.T) {
	cases := map[int]string{
		0: reasonUnspecified, 1: reasonKeyCompromise, 2: reasonCACompromise,
		3: reasonAffiliationChanged, 4: reasonSuperseded, 5: reasonCessationOfOperation,
		6: reasonCertificateHold, 8: reasonRemoveFromCRL, 9: reasonPrivilegeWithdrawn,
		10: reasonAACompromise,
	}
	for code, want := range cases {
		if got := RevocationReasonString(code); got != want {
			t.Errorf("RevocationReasonString(%d) = %q, want %q", code, got, want)
		}
	}
	if got := RevocationReasonString(99); got != "reason(99)" {
		t.Errorf("unknown code = %q", got)
	}
}
