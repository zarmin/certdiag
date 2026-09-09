package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"os/exec"
	"time"

	"testing"
)

func selfSignedTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  key,
		}},
	}
}

func TestRemotePipeExitsWhenServerCloses(t *testing.T) {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", selfSignedTLSConfig(t))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		if hs, ok := conn.(*tls.Conn); ok {
			_ = hs.Handshake()
		}
		conn.Write([]byte("hello\n"))
		conn.Close()
	}()

	// A real pipe whose write end we keep open: the child's stdin never sees
	// EOF, reproducing the "user has not closed stdin" condition.
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer stdinR.Close()
	defer stdinW.Close()

	cmd := exec.Command(remoteTestBinary, "remote", "pipe", ln.Addr().String())
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "CERTDIAG_CONFIG=")
	cmd.Stdin = stdinR

	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-done:
		// Exited promptly after the server closed the connection.
	case <-time.After(5 * time.Second):
		cmd.Process.Kill()
		<-done
		t.Fatal("remote pipe hung after server closed connection (stdin still open)")
	}
}
