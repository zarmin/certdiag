package certlib

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"testing"
	"time"
)

func startProbeTLSListener(t *testing.T, addr string, cfg *tls.Config) net.Listener {
	t.Helper()
	l, err := tls.Listen("tcp", addr, cfg)
	if err != nil {
		t.Skipf("cannot listen on %s: %v", addr, err)
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				tc, ok := c.(*tls.Conn)
				if ok {
					tc.SetDeadline(time.Now().Add(2 * time.Second))
					tc.Handshake()
				}
				c.Close()
			}(conn)
		}
	}()
	return l
}

func TestProbeServerHonorsIPFamily(t *testing.T) {
	key := mustGenerateRSAKey(t)
	_, der := mustCreateSelfSignedCA(t, key)
	tlsCert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	cfg := &tls.Config{Certificates: []tls.Certificate{tlsCert}}

	l4 := startProbeTLSListener(t, "127.0.0.1:0", cfg)
	defer l4.Close()
	port := l4.Addr().(*net.TCPAddr).Port

	l6 := startProbeTLSListener(t, fmt.Sprintf("[::1]:%d", port), cfg)
	defer l6.Close()

	tests := []struct {
		name         string
		ipv4Only     bool
		ipv6Only     bool
		wantResolved string
	}{
		{"ipv4 only", true, false, "127.0.0.1"},
		{"ipv6 only", false, true, "::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := RemoteTarget{Host: "localhost", Port: port, SNI: "localhost"}
			result, err := ProbeServer(context.Background(), target, StarttlsNone, 2*time.Second, tt.ipv4Only, tt.ipv6Only)
			if err != nil {
				t.Fatalf("ProbeServer error: %v", err)
			}
			if result.ResolvedAddr != tt.wantResolved {
				t.Errorf("ResolvedAddr = %q, want %q", result.ResolvedAddr, tt.wantResolved)
			}
		})
	}
}
