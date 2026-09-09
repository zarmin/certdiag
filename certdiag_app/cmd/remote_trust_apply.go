package cmd

import (
	"crypto/x509"
	"net"

	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
)

// remoteCertsOf extracts the parsed certificates of one target result.
func remoteCertsOf(infos []certops.RemoteCertInfo) []*x509.Certificate {
	var certs []*x509.Certificate
	for _, ci := range infos {
		if ci.Cert != nil && ci.Cert.Certificate != nil {
			certs = append(certs, ci.Cert.Certificate)
		}
	}
	return certs
}

// remoteVerifyHostname is the name a chain must be valid for: the SNI that was
// actually sent, else the target's host part.
func remoteVerifyHostname(target string, conn *certops.RemoteConnectionInfo) string {
	hostname := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		hostname = h
	}
	if conn != nil && conn.SNI != "" {
		hostname = conn.SNI
	}
	return hostname
}

// applyRemoteCheckTrust fills each target's per-store verdicts (decision D2).
// The stores are read once for all targets.
func applyRemoteCheckTrust(result *certops.CheckRemoteResult, sel certops.RemoteTrustSelection) {
	loaded, err := certops.LoadStoresForSelection(sel, certops.StoreLoadAllOptions{})
	if err != nil {
		warnf("Warning: %v", err)
		return
	}
	for i := range result.TargetResults {
		tr := &result.TargetResults[i]
		if tr.Error != "" {
			continue
		}
		certs := remoteCertsOf(tr.Certs)
		if len(certs) == 0 {
			continue
		}
		rows, _ := certops.VerifyRemoteAgainstStores(certs, remoteVerifyHostname(tr.Target, tr.Connection), sel, loaded.Stores)
		tr.StoreVerdicts = rows
	}
}
