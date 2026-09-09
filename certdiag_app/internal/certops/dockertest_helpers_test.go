//go:build dockertest

package certops

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

const (
	portModernTLS     = 14430
	portLegacyTLS     = 14431
	portSSLv3         = 14432
	portExpired       = 14433
	portSelfSigned    = 14434
	portWrongHost     = 14435
	portIncomplete    = 14436
	portMTLS          = 14437
	portRedirect      = 14438
	portEcho          = 14439
	portSMTP          = 14587
	portIMAP          = 14143
	portPOP3          = 14110
	portLDAP          = 14389
	portPostgreSQL    = 14532
	portMySQL         = 14306
	dockerTestTimeout = 10 * time.Second
)

func dockerTarget(port int) string {
	return fmt.Sprintf("localhost:%d", port)
}

func requireDockerAvailable(t *testing.T) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", dockerTarget(portModernTLS), 2*time.Second)
	if err != nil {
		t.Fatalf("docker test infrastructure not available (port %d): %v", portModernTLS, err)
	}
	conn.Close()
}

func requireServiceAvailable(t *testing.T, port int) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", dockerTarget(port), 2*time.Second)
	if err != nil {
		t.Fatalf("service on port %d not available: %v", port, err)
	}
	conn.Close()
}

func requireServiceResponds(t *testing.T, port int) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", dockerTarget(port), 2*time.Second)
	if err != nil {
		t.Skipf("service on port %d not available: %v", port, err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		t.Skipf("service on port %d not responding: %v", port, err)
	}
}

func requireSMTPReady(t *testing.T, port int) {
	t.Helper()
	for i := 0; i < 15; i++ {
		conn, err := net.DialTimeout("tcp", dockerTarget(port), 2*time.Second)
		if err != nil {
			time.Sleep(4 * time.Second)
			continue
		}
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 4)
		n, err := conn.Read(buf)
		conn.Close()
		if err == nil && n >= 3 && string(buf[:3]) == "220" {
			return
		}
		time.Sleep(4 * time.Second)
	}
	t.Fatalf("SMTP service on port %d not ready after retries", port)
}

func testCertsDir() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "tools", "testinfra", "certs")
}

func testCertPath(name string) string {
	return filepath.Join(testCertsDir(), name)
}

func requireFileExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("required file missing: %s: %v", path, err)
	}
}
