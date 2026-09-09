//go:build dockertest

package certops

import (
	"bufio"
	"fmt"
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func TestDockerPipe_Connect(t *testing.T) {
	requireDockerAvailable(t)

	target, err := certlib.ParseTarget(dockerTarget(portModernTLS))
	if err != nil {
		t.Fatalf("ParseTarget error: %v", err)
	}

	conn, tlsInfo, err := certlib.PipeConnection(target, certlib.TLSDialOptions{
		Timeout: dockerTestTimeout,
	})
	if err != nil {
		t.Fatalf("PipeConnection error: %v", err)
	}
	defer conn.Close()

	if tlsInfo == nil {
		t.Fatal("TLS info is nil")
	}
	if !tlsInfo.HandshakeComplete {
		t.Error("handshake should be complete")
	}

	// Send an HTTP/1.1 GET request over the TLS pipe
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: localhost:%d\r\nConnection: close\r\n\r\n", portModernTLS)
	_, err = conn.Write([]byte(req))
	if err != nil {
		t.Fatalf("write error: %v", err)
	}

	// Read the response
	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		t.Fatal("no response from server")
	}
	statusLine := scanner.Text()
	if !strings.Contains(statusLine, "200") {
		t.Errorf("expected HTTP 200 in status line, got %q", statusLine)
	}
}

func TestDockerPipe_STARTTLS(t *testing.T) {
	requireDockerAvailable(t)
	requireSMTPReady(t, portSMTP)

	target, err := certlib.ParseTarget(dockerTarget(portSMTP))
	if err != nil {
		t.Fatalf("ParseTarget error: %v", err)
	}

	conn, tlsInfo, err := certlib.PipeConnection(target, certlib.TLSDialOptions{
		Timeout:  dockerTestTimeout,
		Starttls: certlib.StarttlsSMTP,
	})
	if err != nil {
		t.Fatalf("PipeConnection with SMTP STARTTLS error: %v", err)
	}
	defer conn.Close()

	if tlsInfo == nil {
		t.Fatal("TLS info is nil")
	}
	if !tlsInfo.HandshakeComplete {
		t.Error("TLS handshake should be complete after STARTTLS")
	}
	if tlsInfo.VersionName == "" {
		t.Error("expected TLS version after STARTTLS")
	}
}
