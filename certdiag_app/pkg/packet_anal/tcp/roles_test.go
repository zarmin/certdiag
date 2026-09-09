package tcp

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func tcpPacket(t *testing.T, src, dst string, sport, dport uint16, seq uint32, payload []byte) gopacket.Packet {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: net.ParseIP(src).To4(), DstIP: net.ParseIP(dst).To4()}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(sport), DstPort: layers.TCPPort(dport),
		Seq: seq, Ack: 1, ACK: true, PSH: len(payload) > 0, Window: 65535}
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	pkt.Metadata().Timestamp = time.Now()
	return pkt
}

// TestReassembly_ServerSpeaksFirst guards M31 M12: with a STARTTLS banner (or a
// capture that starts mid-stream) the first stream seen is the server; the
// ClientHello decides who the client is.
func TestReassembly_ServerSpeaksFirst(t *testing.T) {
	banner := []byte("220 mail.test ESMTP\r\n")
	clientHello := []byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00}
	serverHello := []byte{0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00}

	r := NewReassembler()
	r.ProcessPacket(tcpPacket(t, "10.0.0.2", "10.0.0.1", 25, 40000, 1000, banner))
	r.ProcessPacket(tcpPacket(t, "10.0.0.1", "10.0.0.2", 40000, 25, 5000, clientHello))
	r.ProcessPacket(tcpPacket(t, "10.0.0.2", "10.0.0.1", 25, 40000, 1000+uint32(len(banner)), serverHello))
	conns := r.Flush()
	if len(conns) != 1 {
		t.Fatalf("got %d connections, want 1", len(conns))
	}
	c := conns[0]
	if c.ClientAddr != "10.0.0.1:40000" || c.ServerAddr != "10.0.0.2:25" {
		t.Errorf("roles: client=%s server=%s, want the ClientHello sender as client", c.ClientAddr, c.ServerAddr)
	}
	if !bytes.Equal(c.ClientData, clientHello) {
		t.Errorf("ClientData = %x, want the ClientHello", c.ClientData)
	}
	if !bytes.HasPrefix(c.ServerData, banner) || !bytes.HasSuffix(c.ServerData, serverHello) {
		t.Errorf("ServerData = %q, want banner then ServerHello", c.ServerData)
	}
}
