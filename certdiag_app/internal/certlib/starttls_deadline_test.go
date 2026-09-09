package certlib

import (
	"bufio"
	"net"
	"testing"
	"time"
)

type recordConn struct {
	net.Conn
	lastDeadline time.Time
	deadlineSet  bool
}

func (c *recordConn) SetDeadline(t time.Time) error {
	c.lastDeadline = t
	c.deadlineSet = true
	return c.Conn.SetDeadline(t)
}

// TestPerformStarttls_AppliesCallerDeadline verifies the fix: PerformStarttls
// applies exactly the caller's deadline (not a fixed 10s) and, because it is
// absolute, that deadline is still in effect after the exchange for the caller's
// TLS handshake. This is what makes a probe honor --timeout (#5) and, once an
// interactive caller clears it, lets a pipe session outlive the exchange (#1).
func TestPerformStarttls_AppliesCallerDeadline(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		r := bufio.NewReader(server)
		server.Write([]byte("220 mail.example.com ESMTP\r\n"))
		r.ReadString('\n') // EHLO
		server.Write([]byte("250-mail.example.com\r\n250 STARTTLS\r\n"))
		r.ReadString('\n') // STARTTLS
		server.Write([]byte("220 go ahead\r\n"))
		select {} // stall (never send ServerHello)
	}()

	want := time.Now().Add(37 * time.Second) // a distinctive, non-default value
	rc := &recordConn{Conn: client}
	if err := PerformStarttls(rc, StarttlsSMTP, "", want); err != nil {
		t.Fatalf("PerformStarttls: %v", err)
	}

	if !rc.deadlineSet {
		t.Fatal("no deadline was set")
	}
	// The connection must carry exactly the caller's deadline after the exchange,
	// proving the fixed-10s override is gone and the handshake will use the
	// caller's timeout.
	if !rc.lastDeadline.Equal(want) {
		t.Fatalf("deadline = %v, want the caller's %v (fixed override must be gone)", rc.lastDeadline, want)
	}
}

// TestPerformStarttls_ZeroDeadlineExchangeUnbounded documents that a zero
// deadline means "no deadline": callers that want a long-lived session must
// still pass a bounded deadline for the exchange and clear it afterwards (as
// PipeConnection does), rather than passing the zero value here.
func TestPerformStarttls_ZeroDeadlineIsNoDeadline(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		r := bufio.NewReader(server)
		server.Write([]byte("220 mail.example.com ESMTP\r\n"))
		r.ReadString('\n')
		server.Write([]byte("250-mail.example.com\r\n250 STARTTLS\r\n"))
		r.ReadString('\n')
		server.Write([]byte("220 go ahead\r\n"))
		select {}
	}()

	rc := &recordConn{Conn: client}
	if err := PerformStarttls(rc, StarttlsSMTP, "", time.Time{}); err != nil {
		t.Fatalf("PerformStarttls: %v", err)
	}
	if !rc.lastDeadline.IsZero() {
		t.Fatalf("expected the zero deadline to be applied verbatim, got %v", rc.lastDeadline)
	}
}
