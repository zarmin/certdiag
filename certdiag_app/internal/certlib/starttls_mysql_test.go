package certlib

import (
	"net"
	"testing"
	"time"
)

// TestStarttlsMySQL_ZeroLengthPayloadNoPanic verifies the fix: a peer-supplied
// zero-length MySQL initial packet must yield a clean error, not an
// index-out-of-range panic.
func TestStarttlsMySQL_ZeroLengthPayloadNoPanic(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		server.Write([]byte{0x00, 0x00, 0x00, 0x00}) // length=0, seq=0
		time.Sleep(50 * time.Millisecond)
		server.Close()
	}()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("starttlsMySQL panicked on zero-length payload: %v", r)
		}
	}()

	err := starttlsMySQL(client)
	if err == nil {
		t.Fatal("expected an error for a zero-length MySQL handshake, got nil")
	}
	t.Logf("clean error (no panic): %v", err)
}

// TestStarttlsMySQL_WrongVersionStillReports keeps the version-mismatch path
// working (non-empty payload, wrong protocol version byte).
func TestStarttlsMySQL_WrongVersionStillReports(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		// payload length 1, one byte = 9 (not 10)
		server.Write([]byte{0x01, 0x00, 0x00, 0x00, 0x09})
		time.Sleep(50 * time.Millisecond)
		server.Close()
	}()

	err := starttlsMySQL(client)
	if err == nil {
		t.Fatal("expected a protocol-version error, got nil")
	}
	t.Logf("version-mismatch error: %v", err)
}
