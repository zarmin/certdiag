package certlib

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestDialHTTPConnect407WithContentLengthRejected(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		readCONNECTHeaders(br)
		conn.Write([]byte("HTTP/1.1 407 Proxy Auth Required\r\nContent-Length: 1200\r\n\r\n"))
		io.Copy(io.Discard, conn)
	}()

	u, _ := url.Parse("http://" + ln.Addr().String())
	ctx := context.Background()
	conn, err := dialHTTPConnect(ctx, u, "example.com:443", 2*time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("expected 407 response to be rejected, got success")
	}
	if !strings.Contains(err.Error(), "407") {
		t.Fatalf("expected 407 in error, got %v", err)
	}
}

func TestDialHTTPConnect200Success(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		readCONNECTHeaders(br)
		conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		io.Copy(io.Discard, conn)
	}()

	u, _ := url.Parse("http://" + ln.Addr().String())
	ctx := context.Background()
	conn, err := dialHTTPConnect(ctx, u, "example.com:443", 2*time.Second)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	conn.Close()
}

func TestDialHTTPConnectSendsProxyAuthorization(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	authCh := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		headers := readCONNECTHeaders(br)
		authCh <- headers["Proxy-Authorization"]
		conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		io.Copy(io.Discard, conn)
	}()

	u, _ := url.Parse("http://alice:s3cret@" + ln.Addr().String())
	ctx := context.Background()
	conn, err := dialHTTPConnect(ctx, u, "example.com:443", 2*time.Second)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	conn.Close()

	got := <-authCh
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:s3cret"))
	if got != want {
		t.Fatalf("Proxy-Authorization mismatch: got %q want %q", got, want)
	}
}

func TestDialHTTPConnectDeadlineOnStalledProxy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Accept and never reply.
		time.Sleep(3 * time.Second)
	}()

	u, _ := url.Parse("http://" + ln.Addr().String())
	ctx := context.Background()
	start := time.Now()
	conn, err := dialHTTPConnect(ctx, u, "example.com:443", 300*time.Millisecond)
	elapsed := time.Since(start)
	if err == nil {
		conn.Close()
		t.Fatal("expected timeout error, got success")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("dial did not honor deadline, took %v", elapsed)
	}
}

func TestDialSOCKS5FragmentedReplies(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Method selection request: 0x05 0x01 0x00
		io.ReadFull(conn, make([]byte, 3))
		// Reply split across two writes: version, then method.
		conn.Write([]byte{0x05})
		time.Sleep(20 * time.Millisecond)
		conn.Write([]byte{0x00})

		// Connect request: ver, cmd, rsv, atyp, addr, port.
		header := make([]byte, 4)
		io.ReadFull(conn, header)
		switch header[3] {
		case 0x01:
			io.ReadFull(conn, make([]byte, 4+2))
		case 0x04:
			io.ReadFull(conn, make([]byte, 16+2))
		case 0x03:
			l := make([]byte, 1)
			io.ReadFull(conn, l)
			io.ReadFull(conn, make([]byte, int(l[0])+2))
		}

		// Connect reply split across two writes, plus fragmented bind addr.
		conn.Write([]byte{0x05, 0x00})
		time.Sleep(20 * time.Millisecond)
		conn.Write([]byte{0x00, 0x01}) // rsv + atyp IPv4
		conn.Write([]byte{127, 0, 0})  // partial bind IP
		time.Sleep(20 * time.Millisecond)
		conn.Write([]byte{1, 0x1f, 0x90}) // last IP byte + port
		io.Copy(io.Discard, conn)
	}()

	u, _ := url.Parse("socks5://" + ln.Addr().String())
	ctx := context.Background()
	conn, err := dialSOCKS5(ctx, u, "example.com:443", 2*time.Second)
	if err != nil {
		t.Fatalf("expected success with fragmented replies, got %v", err)
	}
	conn.Close()
}

func TestDialSOCKS5DeadlineOnStalledProxy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(3 * time.Second)
	}()

	u, _ := url.Parse("socks5://" + ln.Addr().String())
	ctx := context.Background()
	start := time.Now()
	conn, err := dialSOCKS5(ctx, u, "example.com:443", 300*time.Millisecond)
	elapsed := time.Since(start)
	if err == nil {
		conn.Close()
		t.Fatal("expected timeout error, got success")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("dial did not honor deadline, took %v", elapsed)
	}
}

func readCONNECTHeaders(br *bufio.Reader) map[string]string {
	headers := map[string]string{}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return headers
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return headers
		}
		if k, v, ok := strings.Cut(line, ":"); ok {
			headers[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
}
