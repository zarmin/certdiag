package certlib

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type socks5Capture struct {
	atyp byte
	addr string
	port int
}

func startSOCKS5CaptureStub(t *testing.T) (string, <-chan socks5Capture) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan socks5Capture, 1)
	go func() {
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		hdr := make([]byte, 2)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		if _, err := io.ReadFull(conn, make([]byte, int(hdr[1]))); err != nil {
			return
		}
		conn.Write([]byte{0x05, 0x00})

		req := make([]byte, 4)
		if _, err := io.ReadFull(conn, req); err != nil {
			return
		}
		cap := socks5Capture{atyp: req[3]}
		switch req[3] {
		case 0x01:
			b := make([]byte, 4)
			io.ReadFull(conn, b)
			cap.addr = net.IP(b).String()
		case 0x04:
			b := make([]byte, 16)
			io.ReadFull(conn, b)
			cap.addr = net.IP(b).String()
		case 0x03:
			l := make([]byte, 1)
			io.ReadFull(conn, l)
			b := make([]byte, int(l[0]))
			io.ReadFull(conn, b)
			cap.addr = string(b)
		}
		p := make([]byte, 2)
		io.ReadFull(conn, p)
		cap.port = int(p[0])<<8 | int(p[1])
		ch <- cap

		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}()
	return ln.Addr().String(), ch
}

func TestProxySOCKS5SendsHostnameAsDomainATYP(t *testing.T) {
	proxyAddr, ch := startSOCKS5CaptureStub(t)

	target, err := ParseTarget("example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	opts := TLSDialOptions{ProxyURL: "socks5://" + proxyAddr, Timeout: 2 * time.Second}
	DialTLS(target, opts)

	select {
	case cap := <-ch:
		if cap.atyp != 0x03 {
			t.Fatalf("expected DOMAIN ATYP (0x03), got 0x%02x", cap.atyp)
		}
		if cap.addr != "example.com" {
			t.Fatalf("expected hostname example.com, got %q", cap.addr)
		}
		if cap.port != 443 {
			t.Fatalf("expected port 443, got %d", cap.port)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("proxy stub did not receive connect request")
	}
}

func TestProxySOCKS5SendsLiteralIPv4ATYP(t *testing.T) {
	proxyAddr, ch := startSOCKS5CaptureStub(t)

	target, err := ParseTarget("127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	opts := TLSDialOptions{ProxyURL: "socks5://" + proxyAddr, Timeout: 2 * time.Second}
	DialTLS(target, opts)

	select {
	case cap := <-ch:
		if cap.atyp != 0x01 {
			t.Fatalf("expected IPv4 ATYP (0x01), got 0x%02x", cap.atyp)
		}
		if cap.addr != "127.0.0.1" {
			t.Fatalf("expected 127.0.0.1, got %q", cap.addr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("proxy stub did not receive connect request")
	}
}

func TestProxySOCKS5SendsLiteralIPv6ATYP(t *testing.T) {
	proxyAddr, ch := startSOCKS5CaptureStub(t)

	target, err := ParseTarget("[::1]:443")
	if err != nil {
		t.Fatal(err)
	}
	opts := TLSDialOptions{ProxyURL: "socks5://" + proxyAddr, Timeout: 2 * time.Second}
	DialTLS(target, opts)

	select {
	case cap := <-ch:
		if cap.atyp != 0x04 {
			t.Fatalf("expected IPv6 ATYP (0x04), got 0x%02x", cap.atyp)
		}
		if cap.addr != "::1" {
			t.Fatalf("expected ::1, got %q", cap.addr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("proxy stub did not receive connect request")
	}
}

func startHTTPConnectCaptureStub(t *testing.T) (string, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan string, 1)
	go func() {
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		ch <- strings.TrimRight(line, "\r\n")
		for {
			h, err := br.ReadString('\n')
			if err != nil || strings.TrimRight(h, "\r\n") == "" {
				break
			}
		}
		conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	}()
	return ln.Addr().String(), ch
}

func TestProxyHTTPConnectSendsHostname(t *testing.T) {
	proxyAddr, ch := startHTTPConnectCaptureStub(t)

	target, err := ParseTarget("example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	opts := TLSDialOptions{ProxyURL: "http://" + proxyAddr, Timeout: 2 * time.Second}
	DialTLS(target, opts)

	select {
	case line := <-ch:
		if !strings.Contains(line, "example.com:443") {
			t.Fatalf("expected CONNECT request line to contain example.com:443, got %q", line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("proxy stub did not receive CONNECT request")
	}
}
