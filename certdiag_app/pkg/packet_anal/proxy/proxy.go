package proxy

import (
	"bytes"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/tcp"
)

type Proxy struct {
	listenAddr   string
	targetAddr   string
	mu           sync.Mutex
	conns        []*tcp.Connection
	listener     net.Listener
	OnConnection func(c *tcp.Connection)
	connCount    atomic.Int64
	byteCount    atomic.Int64
	ingressBytes atomic.Int64
	egressBytes  atomic.Int64
}

func New(listen, target string) *Proxy {
	return &Proxy{
		listenAddr: listen,
		targetAddr: target,
	}
}

func (p *Proxy) Start() error {
	ln, err := net.Listen("tcp", p.listenAddr)
	if err != nil {
		return err
	}
	p.listener = ln
	go p.acceptLoop()
	return nil
}

func (p *Proxy) Stop() []*tcp.Connection {
	p.listener.Close()
	time.Sleep(100 * time.Millisecond)
	p.mu.Lock()
	defer p.mu.Unlock()
	result := p.conns
	p.conns = nil
	return result
}

func (p *Proxy) ConnCount() int64    { return p.connCount.Load() }
func (p *Proxy) ByteCount() int64    { return p.byteCount.Load() }
func (p *Proxy) IngressBytes() int64 { return p.ingressBytes.Load() }
func (p *Proxy) EgressBytes() int64  { return p.egressBytes.Load() }

func (p *Proxy) acceptLoop() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		go p.handleConn(conn)
	}
}

func (p *Proxy) handleConn(clientConn net.Conn) {
	start := time.Now()
	defer clientConn.Close()

	serverConn, err := net.Dial("tcp", p.targetAddr)
	if err != nil {
		return
	}
	defer serverConn.Close()

	clientCap, serverCap := newCaptureWriter(), newCaptureWriter()
	var emitOnce sync.Once
	emit := func(closed bool) {
		emitOnce.Do(func() {
			c := &tcp.Connection{
				ClientAddr: clientConn.RemoteAddr().String(),
				ServerAddr: p.targetAddr,
				ClientData: clientCap.captured(),
				ServerData: serverCap.captured(),
				StartTime:  start,
				EndTime:    time.Now(),
				ClientFIN:  closed,
				ServerFIN:  closed,
			}
			p.connCount.Add(1)
			p.mu.Lock()
			p.conns = append(p.conns, c)
			p.mu.Unlock()
			if p.OnConnection != nil {
				p.OnConnection(c)
			}
		})
	}
	// Once both sides carry ApplicationData the handshake is over and the
	// session can be reported; waiting for the close would hide a long-lived
	// connection until it ends (M31 M11).
	bothSeen := func() {
		if clientCap.appDataSeen() && serverCap.appDataSeen() {
			emit(false)
		}
	}
	clientCap.onAppData = bothSeen
	serverCap.onAppData = bothSeen

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(io.MultiWriter(serverConn, clientCap), clientConn)
		if tc, ok := serverConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		io.Copy(io.MultiWriter(clientConn, serverCap), serverConn)
		if tc, ok := clientConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	wg.Wait()

	in, out := clientCap.total(), serverCap.total()
	p.byteCount.Add(in + out)
	p.ingressBytes.Add(in)
	p.egressBytes.Add(out)
	emit(true)
}

// captureAppDataLimit bounds what is kept per direction once the TLS
// handshake is over. The handshake is what the diagnostics need; a websocket
// or database connection must not grow the capture with its traffic.
const captureAppDataLimit = 16 * 1024

// captureWriter forwards nothing and keeps a bounded copy of a stream: every
// TLS record that is not ApplicationData is kept in full, ApplicationData up
// to captureAppDataLimit. A stream that is not TLS at all counts as
// ApplicationData from its first byte.
type captureWriter struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	seen      int64
	appBytes  int
	appSeen   bool
	onAppData func()

	hdr     []byte // partial record header
	remain  int    // bytes left in the current record
	recType byte
	notTLS  bool
}

func newCaptureWriter() *captureWriter { return &captureWriter{} }

func (w *captureWriter) Write(p []byte) (int, error) {
	written := len(p)
	w.mu.Lock()
	w.seen += int64(written)
	var fire bool
	for len(p) > 0 {
		if w.notTLS {
			fire = w.consume(p, true) || fire
			break
		}
		if w.remain == 0 {
			need := 5 - len(w.hdr)
			if need > len(p) {
				w.hdr = append(w.hdr, p...)
				break
			}
			w.hdr = append(w.hdr, p[:need]...)
			p = p[need:]
			if w.hdr[0] < 20 || w.hdr[0] > 24 || w.hdr[1] != 3 {
				w.notTLS = true
				fire = w.consume(w.hdr, true) || fire
				w.hdr = nil
				continue
			}
			w.recType = w.hdr[0]
			w.remain = int(w.hdr[3])<<8 | int(w.hdr[4])
			w.buf.Write(w.hdr)
			w.hdr = nil
			continue
		}
		n := w.remain
		if n > len(p) {
			n = len(p)
		}
		fire = w.consume(p[:n], w.recType == 23) || fire
		w.remain -= n
		p = p[n:]
	}
	cb := w.onAppData
	w.mu.Unlock()
	if fire && cb != nil {
		cb()
	}
	return written, nil
}

// consume stores a chunk, subject to the ApplicationData cap, and reports
// whether this chunk was the first ApplicationData.
func (w *captureWriter) consume(chunk []byte, appData bool) bool {
	if !appData {
		w.buf.Write(chunk)
		return false
	}
	first := !w.appSeen
	w.appSeen = true
	room := captureAppDataLimit - w.appBytes
	w.appBytes += len(chunk)
	if room > 0 {
		if room < len(chunk) {
			chunk = chunk[:room]
		}
		w.buf.Write(chunk)
	}
	return first
}

func (w *captureWriter) captured() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.buf.Bytes()...)
}

func (w *captureWriter) appDataSeen() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.appSeen
}

func (w *captureWriter) total() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.seen
}
