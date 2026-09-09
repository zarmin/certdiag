//go:build dockertest

package certops

import (
	"crypto/tls"
	"fmt"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func TestDockerMTLS_WithoutClientCert(t *testing.T) {
	requireDockerAvailable(t)
	requireServiceAvailable(t, portMTLS)

	// Verify mTLS enforcement via HTTP: without client cert, server returns 400
	httpResult, err := HTTPRemote(HTTPRemoteOptions{
		Target:  fmt.Sprintf("https://localhost:%d/", portMTLS),
		Timeout: dockerTestTimeout,
	})
	if err != nil {
		t.Fatalf("HTTPRemote error: %v", err)
	}
	if httpResult.Error != "" {
		t.Fatalf("HTTP error: %s", httpResult.Error)
	}
	if httpResult.Response.StatusCode != 400 {
		t.Errorf("expected HTTP 400 without client cert, got %d", httpResult.Response.StatusCode)
	}
}

func TestDockerMTLS_WithClientCert(t *testing.T) {
	requireDockerAvailable(t)
	requireServiceAvailable(t, portMTLS)

	certPath := testCertPath("client.crt")
	keyPath := testCertPath("client.key")
	requireFileExists(t, certPath)
	requireFileExists(t, keyPath)

	clientCert, err := certlib.LoadClientCert(certlib.ClientCertOptions{
		CertPath: certPath,
		KeyPath:  keyPath,
	})
	if err != nil {
		t.Fatalf("LoadClientCert error: %v", err)
	}

	result, err := FetchRemoteCert(FetchRemoteCertOptions{
		Targets:     []string{dockerTarget(portMTLS)},
		Timeout:     dockerTestTimeout,
		ClientCerts: []tls.Certificate{clientCert},
	})
	if err != nil {
		t.Fatalf("FetchRemoteCert error: %v", err)
	}

	tr := result.TargetResults[0]
	if tr.Error != "" {
		t.Fatalf("expected success with valid client cert, got error: %s", tr.Error)
	}
	if len(tr.Certs) == 0 {
		t.Fatal("expected at least one server cert")
	}
}

func TestDockerMTLS_WrongClientCert(t *testing.T) {
	requireDockerAvailable(t)
	requireServiceAvailable(t, portMTLS)

	certPath := testCertPath("wrongclient.crt")
	keyPath := testCertPath("wrongclient.key")
	requireFileExists(t, certPath)
	requireFileExists(t, keyPath)

	clientCert, err := certlib.LoadClientCert(certlib.ClientCertOptions{
		CertPath: certPath,
		KeyPath:  keyPath,
	})
	if err != nil {
		t.Fatalf("LoadClientCert error: %v", err)
	}

	// Verify mTLS enforcement via HTTP: wrong client cert gets 400
	httpResult, err := HTTPRemote(HTTPRemoteOptions{
		Target:      fmt.Sprintf("https://localhost:%d/", portMTLS),
		Timeout:     dockerTestTimeout,
		ClientCerts: []tls.Certificate{clientCert},
	})
	if err != nil {
		t.Fatalf("HTTPRemote error: %v", err)
	}
	if httpResult.Error != "" {
		// TLS-level rejection is also acceptable
		return
	}
	if httpResult.Response.StatusCode != 400 {
		t.Errorf("expected HTTP 400 with wrong client cert, got %d", httpResult.Response.StatusCode)
	}
}
