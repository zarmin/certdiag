package certlib

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"
)

func mustCreateCAWithPathLen(t *testing.T, pathLen int) *x509.Certificate {
	t.Helper()
	key := mustGenerateECKey(t)
	cert, _, err := CreateSelfSignedCert(key, CertGenOptions{
		Subject:    pkix.Name{CommonName: "PathLen CA"},
		Days:       365,
		IsCA:       true,
		KeyUsage:   x509.KeyUsageCertSign,
		PathLength: pathLen,
	})
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func pathLengthField(t *testing.T, left, right *x509.Certificate) DiffField {
	t.Helper()
	result := CompareCertificates(left, right, true)
	for _, f := range result.Fields {
		if f.Name == "Path Length" {
			return f
		}
	}
	t.Fatal("Path Length field not found in diff")
	return DiffField{}
}

func TestFormatPathLength_Unlimited(t *testing.T) {
	unlimited := mustCreateCAWithPathLen(t, -1)
	constrained := mustCreateCAWithPathLen(t, 2)

	f := pathLengthField(t, unlimited, constrained)
	if f.Left != "unlimited" {
		t.Errorf("expected left path length %q, got %q", "unlimited", f.Left)
	}
	if f.Right != "2" {
		t.Errorf("expected right path length %q, got %q", "2", f.Right)
	}
}

func TestFormatPathLength_Zero(t *testing.T) {
	zero := mustCreateCAWithPathLen(t, 0)
	unlimited := mustCreateCAWithPathLen(t, -1)

	f := pathLengthField(t, zero, unlimited)
	if f.Left != "0" {
		t.Errorf("expected left path length %q, got %q", "0", f.Left)
	}
	if f.Right != "unlimited" {
		t.Errorf("expected right path length %q, got %q", "unlimited", f.Right)
	}
}

func TestCompareTime_NonUTCConvertedToUTC(t *testing.T) {
	est := time.FixedZone("EST", -5*3600)
	left := time.Date(2020, 1, 1, 10, 0, 0, 0, est)
	right := time.Date(2020, 1, 1, 15, 0, 0, 0, time.UTC)

	f := compareTime("Test Time", "validity", left, right)
	const want = "2020-01-01 15:00:00 UTC"
	if f.Left != want {
		t.Errorf("expected left %q, got %q", want, f.Left)
	}
	if f.Right != want {
		t.Errorf("expected right %q, got %q", want, f.Right)
	}
	if f.Status != DiffSame {
		t.Errorf("expected same status for equal instants, got %q", f.Status)
	}
}
