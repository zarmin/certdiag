package proxy

import (
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/tcp"
)

// startEchoServer listens on a random port and echoes back whatever it receives.
func startEchoServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String(), func() { ln.Close(); wg.Wait() }
}

func TestNew(t *testing.T) {
	p := New("127.0.0.1:0", "127.0.0.1:443")
	if p == nil {
		t.Fatal("New() returned nil")
	}
	if p.listenAddr != "127.0.0.1:0" {
		t.Errorf("listenAddr = %q, want 127.0.0.1:0", p.listenAddr)
	}
}

func TestStartStop_NoConnections(t *testing.T) {
	echoAddr, stopEcho := startEchoServer(t)
	defer stopEcho()

	p := New("127.0.0.1:0", echoAddr)
	if err := p.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	conns := p.Stop()
	if len(conns) != 0 {
		t.Errorf("Stop() returned %d connections, want 0", len(conns))
	}
	if p.ConnCount() != 0 {
		t.Errorf("ConnCount() = %d, want 0", p.ConnCount())
	}
}

func TestProxy_SingleConnection(t *testing.T) {
	echoAddr, stopEcho := startEchoServer(t)
	defer stopEcho()

	p := New("127.0.0.1:0", echoAddr)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}

	proxyAddr := p.listener.Addr().String()

	// Connect through the proxy
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("hello proxy")
	conn.Write(msg)

	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := io.ReadFull(conn, buf)
	if err != nil {
		t.Fatalf("read echoed data: %v", err)
	}
	if string(buf[:n]) != "hello proxy" {
		t.Errorf("echoed = %q, want %q", buf[:n], "hello proxy")
	}
	conn.Close()
	time.Sleep(200 * time.Millisecond) // let proxy finish

	conns := p.Stop()
	if len(conns) != 1 {
		t.Fatalf("Stop() returned %d connections, want 1", len(conns))
	}

	c := conns[0]
	if string(c.ClientData) != "hello proxy" {
		t.Errorf("ClientData = %q, want %q", c.ClientData, "hello proxy")
	}
	if string(c.ServerData) != "hello proxy" { // echo
		t.Errorf("ServerData = %q, want %q (echoed)", c.ServerData, "hello proxy")
	}

	if p.ConnCount() != 1 {
		t.Errorf("ConnCount() = %d, want 1", p.ConnCount())
	}
	if p.IngressBytes() != int64(len(msg)) {
		t.Errorf("IngressBytes() = %d, want %d", p.IngressBytes(), len(msg))
	}
	if p.EgressBytes() != int64(len(msg)) {
		t.Errorf("EgressBytes() = %d, want %d", p.EgressBytes(), len(msg))
	}
	if p.ByteCount() != int64(len(msg)*2) {
		t.Errorf("ByteCount() = %d, want %d", p.ByteCount(), len(msg)*2)
	}
}

func TestProxy_MultipleConnections(t *testing.T) {
	echoAddr, stopEcho := startEchoServer(t)
	defer stopEcho()

	p := New("127.0.0.1:0", echoAddr)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}

	proxyAddr := p.listener.Addr().String()
	numConns := 5

	var wg sync.WaitGroup
	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			conn, err := net.Dial("tcp", proxyAddr)
			if err != nil {
				return
			}
			msg := fmt.Sprintf("msg-%d", idx)
			conn.Write([]byte(msg))
			buf := make([]byte, len(msg))
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			io.ReadFull(conn, buf)
			conn.Close()
		}(i)
	}
	wg.Wait()
	time.Sleep(300 * time.Millisecond)

	conns := p.Stop()
	if len(conns) != numConns {
		t.Errorf("Stop() returned %d connections, want %d", len(conns), numConns)
	}
	if p.ConnCount() != int64(numConns) {
		t.Errorf("ConnCount() = %d, want %d", p.ConnCount(), numConns)
	}
}

func TestProxy_OnConnectionCallback(t *testing.T) {
	echoAddr, stopEcho := startEchoServer(t)
	defer stopEcho()

	p := New("127.0.0.1:0", echoAddr)

	callbackCount := 0
	var mu sync.Mutex
	p.OnConnection = func(c *tcp.Connection) {
		mu.Lock()
		callbackCount++
		mu.Unlock()
	}

	if err := p.Start(); err != nil {
		t.Fatal(err)
	}

	conn, _ := net.Dial("tcp", p.listener.Addr().String())
	conn.Write([]byte("test"))
	buf := make([]byte, 4)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	io.ReadFull(conn, buf)
	conn.Close()
	time.Sleep(200 * time.Millisecond)

	p.Stop()

	mu.Lock()
	if callbackCount != 1 {
		t.Errorf("OnConnection called %d times, want 1", callbackCount)
	}
	mu.Unlock()
}

func TestProxy_TargetUnreachable(t *testing.T) {
	// Target on a port that nothing listens on
	p := New("127.0.0.1:0", "127.0.0.1:1") // port 1 is almost certainly closed
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}

	conn, err := net.Dial("tcp", p.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	// Connection to proxy succeeds, but proxy can't reach target.
	// The proxy should close the client connection without crashing.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("expected read error when target is unreachable")
	}
	conn.Close()

	conns := p.Stop()
	// No completed connections since target was unreachable
	if len(conns) != 0 {
		t.Errorf("expected 0 connections, got %d", len(conns))
	}
}
