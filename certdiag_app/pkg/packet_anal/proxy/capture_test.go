package proxy

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/tcp"
)

// TestProxy_CaptureIsBounded guards M31 M11: a 1 MB stream is forwarded in
// full and counted, but only a bounded prefix is kept.
func TestProxy_CaptureIsBounded(t *testing.T) {
	echoAddr, stopEcho := startEchoServer(t)
	defer stopEcho()
	p := New("127.0.0.1:0", echoAddr)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", p.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("x"), 1<<20)
	go func() {
		conn.Write(payload)
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	got, err := io.ReadAll(conn)
	if err != nil || len(got) != len(payload) {
		t.Fatalf("echo returned %d bytes, err %v", len(got), err)
	}
	conn.Close()
	time.Sleep(200 * time.Millisecond)

	conns := p.Stop()
	if len(conns) != 1 {
		t.Fatalf("got %d connections, want 1", len(conns))
	}
	c := conns[0]
	if len(c.ClientData) > captureAppDataLimit || len(c.ServerData) > captureAppDataLimit {
		t.Errorf("capture not bounded: client=%d server=%d, limit %d", len(c.ClientData), len(c.ServerData), captureAppDataLimit)
	}
	if p.ByteCount() != int64(2*len(payload)) {
		t.Errorf("ByteCount = %d, want %d (every byte forwarded is counted)", p.ByteCount(), 2*len(payload))
	}
}

// TestProxy_EmitsOnceApplicationDataFlows guards M31 M11: a session is
// reported when both sides carry ApplicationData, not when it closes.
func TestProxy_EmitsOnceApplicationDataFlows(t *testing.T) {
	echoAddr, stopEcho := startEchoServer(t)
	defer stopEcho()
	p := New("127.0.0.1:0", echoAddr)
	emitted := make(chan *tcp.Connection, 1)
	p.OnConnection = func(c *tcp.Connection) { emitted <- c }
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", p.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	handshake := []byte{0x16, 0x03, 0x01, 0x00, 0x03, 0x01, 0x02, 0x03}
	appData := []byte{0x17, 0x03, 0x03, 0x00, 0x03, 0x41, 0x42, 0x43}
	conn.Write(append(append([]byte{}, handshake...), appData...))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, len(handshake)+len(appData))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("echo: %v", err)
	}

	select {
	case c := <-emitted:
		if c.ClientFIN || c.ServerFIN {
			t.Error("an early-emitted session must not claim the connection closed")
		}
		if !bytes.HasPrefix(c.ClientData, handshake) {
			t.Errorf("handshake bytes missing from the capture: %x", c.ClientData)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("session not emitted while the connection is still open")
	}
	conn.Close()
	time.Sleep(200 * time.Millisecond)
	if n := len(p.Stop()); n != 1 {
		t.Errorf("connection reported %d times, want once", n)
	}
}

// TestCaptureWriter_KeepsHandshakeCapsAppData checks the record-level cap.
func TestCaptureWriter_KeepsHandshakeCapsAppData(t *testing.T) {
	w := newCaptureWriter()
	big := bytes.Repeat([]byte("h"), 40000)
	hs := append([]byte{0x16, 0x03, 0x03, byte(len(big) >> 8), byte(len(big))}, big...)
	w.Write(hs[:7]) // split across writes on purpose
	w.Write(hs[7:])
	app := bytes.Repeat([]byte("a"), 30000)
	rec := append([]byte{0x17, 0x03, 0x03, byte(len(app) >> 8), byte(len(app))}, app...)
	w.Write(rec)
	got := w.captured()
	if !bytes.Equal(got[:len(hs)], hs) {
		t.Error("the handshake record must be kept in full regardless of size")
	}
	if kept := len(got) - len(hs) - 5; kept != captureAppDataLimit {
		t.Errorf("kept %d ApplicationData bytes, want %d", kept, captureAppDataLimit)
	}
	if w.total() != int64(len(hs)+len(rec)) {
		t.Errorf("total = %d, want %d", w.total(), len(hs)+len(rec))
	}
}
