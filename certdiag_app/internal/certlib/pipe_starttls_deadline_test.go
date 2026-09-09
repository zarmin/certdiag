package certlib

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func selfSignedTLSCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestPipeConnection_ClearsDeadlineAfterStarttls is the end-to-end regression
// for the pipe-session bug: PipeConnection sets a bounded deadline for the
// STARTTLS exchange (via PerformStarttls) but must clear it after the handshake,
// otherwise the interactive session dies ~timeout seconds after connecting. The
// server here sends a line only AFTER the client's timeout window, so the read
// succeeds only if the deadline was cleared.
func TestPipeConnection_ClearsDeadlineAfterStarttls(t *testing.T) {
	srvCert := selfSignedTLSCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const clientTimeout = 400 * time.Millisecond
	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		// SMTP STARTTLS preamble.
		conn.Write([]byte("220 test ESMTP\r\n"))
		r.ReadString('\n') // EHLO
		conn.Write([]byte("250-test\r\n250 STARTTLS\r\n"))
		r.ReadString('\n') // STARTTLS
		conn.Write([]byte("220 go ahead\r\n"))
		// Real TLS handshake as the server.
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{srvCert}})
		if err := tlsConn.Handshake(); err != nil {
			serverDone <- err
			return
		}
		// Send a line only well after the client's STARTTLS-exchange deadline.
		time.Sleep(2 * clientTimeout)
		tlsConn.Write([]byte("hello-after-timeout\n"))
		time.Sleep(50 * time.Millisecond)
		serverDone <- nil
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	target := RemoteTarget{Host: host, Port: port, SNI: host, IsIP: true}
	opts := TLSDialOptions{Starttls: StarttlsSMTP, Timeout: clientTimeout}

	conn, _, err := PipeConnection(target, opts)
	if err != nil {
		t.Fatalf("PipeConnection: %v", err)
	}
	defer conn.Close()

	// Read the delayed line. If the STARTTLS deadline was not cleared, this read
	// fails with i/o timeout ~clientTimeout after connect, before the server
	// sends at 2*clientTimeout.
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read after STARTTLS failed - deadline not cleared: %v", err)
	}
	if !strings.Contains(string(buf[:n]), "hello-after-timeout") {
		t.Fatalf("unexpected data: %q", buf[:n])
	}
	if serr := <-serverDone; serr != nil {
		t.Fatalf("server error: %v", serr)
	}
}
