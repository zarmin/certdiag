package certlib

import (
	"crypto/x509"
	"testing"
)

// TestHostnameMismatch_FiresOnce (M31 WP12): with --hostname the SNI and the
// expected name are the same string; one mismatch is one finding.
func TestHostnameMismatch_FiresOnce(t *testing.T) {
	leaf := makeRemoteTestCert(t, "correct.com", []string{"correct.com"}, false)
	ctx := RemoteCheckContext{
		Target:       RemoteTarget{Host: "correct.com", Port: 443},
		TLSInfo:      TLSConnectionInfo{ServerName: "other.test"},
		Certificates: []*x509.Certificate{leaf},
	}
	issues := append(checkHostnameMismatch(ctx, CheckOptions{}), checkSNIMismatch(ctx, CheckOptions{})...)
	if len(issues) != 1 || issues[0].CheckID != "remote_hostname_mismatch" {
		t.Errorf("want exactly one remote_hostname_mismatch, got %+v", issues)
	}
	ctx.TLSInfo.ServerName = ""
	ctx.Target.Host = "other.test"
	issues = append(checkHostnameMismatch(ctx, CheckOptions{}), checkSNIMismatch(ctx, CheckOptions{})...)
	if len(issues) != 1 {
		t.Errorf("without SNI the hostname check alone fires, got %+v", issues)
	}
}
