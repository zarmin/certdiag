package tcp

import (
	"fmt"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/tcpassembly"
)

// Connection represents a bidirectional TCP connection with reassembled data.
// Exported fields are free of gopacket types so downstream packages (tls/, session/)
// can consume them without importing gopacket.
type Connection struct {
	ClientAddr string // "ip:port"
	ServerAddr string // "ip:port"
	ClientData []byte // reassembled client -> server bytes
	ServerData []byte // reassembled server -> client bytes
	StartTime  time.Time
	EndTime    time.Time
	ClientRST  bool // client sent RST
	ServerRST  bool // server sent RST
	ClientFIN  bool
	ServerFIN  bool
}

// connKey identifies a bidirectional connection regardless of direction.
type connKey struct {
	addr1, addr2 string // sorted so addr1 < addr2
}

func makeConnKey(netFlow, tcpFlow gopacket.Flow) connKey {
	a := fmt.Sprintf("%s:%s", netFlow.Src(), tcpFlow.Src())
	b := fmt.Sprintf("%s:%s", netFlow.Dst(), tcpFlow.Dst())
	if a > b {
		a, b = b, a
	}
	return connKey{addr1: a, addr2: b}
}

// streamDir identifies which direction this half-stream represents.
type streamDir struct {
	srcAddr string
	dstAddr string
}

// Reassembler reassembles TCP streams from packets and collects completed connections.
type Reassembler struct {
	mu          sync.Mutex
	connections map[connKey]*connState
	completed   []*Connection
	pool        *tcpassembly.StreamPool
	assembler   *tcpassembly.Assembler
}

type connState struct {
	conn       Connection
	clientAddr string // the first stream seen, until a ClientHello says otherwise
	assigned   bool   // true once we know which side is the client
	roleFixed  bool   // set once a ClientHello has settled who the client is
}

func NewReassembler() *Reassembler {
	r := &Reassembler{
		connections: make(map[connKey]*connState),
	}
	factory := &streamFactory{reassembler: r}
	r.pool = tcpassembly.NewStreamPool(factory)
	r.assembler = tcpassembly.NewAssembler(r.pool)
	return r
}

// ProcessPacket feeds a decoded packet into the reassembler.
func (r *Reassembler) ProcessPacket(packet gopacket.Packet) {
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return
	}
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp := tcpLayer.(*layers.TCP)

	r.assembler.AssembleWithTimestamp(
		netLayer.NetworkFlow(),
		tcp,
		packet.Metadata().Timestamp,
	)
}

// Flush flushes all remaining streams and returns all completed connections.
func (r *Reassembler) Flush() []*Connection {
	r.assembler.FlushAll()

	r.mu.Lock()
	defer r.mu.Unlock()

	// Move any remaining open connections to completed
	for _, cs := range r.connections {
		r.completed = append(r.completed, &cs.conn)
	}
	r.connections = make(map[connKey]*connState)

	result := r.completed
	r.completed = nil
	return result
}

// getOrCreate returns the connection state for this stream, creating it if needed.
func (r *Reassembler) getOrCreate(netFlow, tcpFlow gopacket.Flow) (*connState, streamDir) {
	key := makeConnKey(netFlow, tcpFlow)
	srcAddr := fmt.Sprintf("%s:%s", netFlow.Src(), tcpFlow.Src())
	dstAddr := fmt.Sprintf("%s:%s", netFlow.Dst(), tcpFlow.Dst())

	r.mu.Lock()
	defer r.mu.Unlock()

	cs, ok := r.connections[key]
	if !ok {
		cs = &connState{
			clientAddr: srcAddr, // first stream seen is assumed to be client
			assigned:   true,
		}
		cs.conn.ClientAddr = srcAddr
		cs.conn.ServerAddr = dstAddr
		r.connections[key] = cs
	}
	return cs, streamDir{srcAddr: srcAddr, dstAddr: dstAddr}
}

// streamFactory creates half-streams for tcpassembly.
type streamFactory struct {
	reassembler *Reassembler
}

func (f *streamFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	cs, dir := f.reassembler.getOrCreate(netFlow, tcpFlow)
	return &halfStream{
		reassembler: f.reassembler,
		connState:   cs,
		dir:         dir,
		netFlow:     netFlow,
		tcpFlow:     tcpFlow,
	}
}

// halfStream receives reassembled bytes for one direction of a TCP connection.
type halfStream struct {
	reassembler *Reassembler
	connState   *connState
	dir         streamDir
	netFlow     gopacket.Flow
	tcpFlow     gopacket.Flow
}

func (s *halfStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	s.reassembler.mu.Lock()
	defer s.reassembler.mu.Unlock()

	isClient := s.dir.srcAddr == s.connState.clientAddr

	for _, r := range reassemblies {
		if len(r.Bytes) == 0 {
			continue
		}

		// The first stream seen was called the client, which a capture that
		// starts mid-stream or a STARTTLS banner gets wrong. The ClientHello
		// is the authority: when it shows up on the "server" side, swap
		// (M31 M12).
		if !s.connState.roleFixed && !isClient && len(s.connState.conn.ServerData) == 0 &&
			looksLikeClientHello(r.Bytes) && !looksLikeClientHello(s.connState.conn.ClientData) {
			s.connState.swapRoles(s.dir.srcAddr)
			isClient = true
		}
		if looksLikeClientHello(r.Bytes) {
			s.connState.roleFixed = true
		}

		if isClient {
			s.connState.conn.ClientData = append(s.connState.conn.ClientData, r.Bytes...)
		} else {
			s.connState.conn.ServerData = append(s.connState.conn.ServerData, r.Bytes...)
		}

		if s.connState.conn.StartTime.IsZero() || r.Seen.Before(s.connState.conn.StartTime) {
			s.connState.conn.StartTime = r.Seen
		}
		if r.Seen.After(s.connState.conn.EndTime) {
			s.connState.conn.EndTime = r.Seen
		}

		if r.End {
			if isClient {
				s.connState.conn.ClientFIN = true
			} else {
				s.connState.conn.ServerFIN = true
			}
		}
	}
}

func (s *halfStream) ReassemblyComplete() {
	// Don't finalize here -- we wait for Flush() to collect all connections,
	// since both half-streams complete independently.
}

// swapRoles makes the given address the client and moves what was collected
// so far to the other side.
func (cs *connState) swapRoles(clientAddr string) {
	cs.clientAddr = clientAddr
	c := &cs.conn
	c.ClientAddr, c.ServerAddr = c.ServerAddr, c.ClientAddr
	c.ClientData, c.ServerData = c.ServerData, c.ClientData
	c.ClientFIN, c.ServerFIN = c.ServerFIN, c.ClientFIN
	c.ClientRST, c.ServerRST = c.ServerRST, c.ClientRST
}

// looksLikeClientHello reports whether b starts with a TLS handshake record
// carrying a ClientHello.
func looksLikeClientHello(b []byte) bool {
	return len(b) >= 6 && b[0] == 0x16 && b[1] == 0x03 && b[5] == 0x01
}
