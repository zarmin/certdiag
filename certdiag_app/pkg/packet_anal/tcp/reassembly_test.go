package tcp

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestNewReassembler(t *testing.T) {
	r := NewReassembler()
	if r == nil {
		t.Fatal("NewReassembler() returned nil")
	}
	if r.assembler == nil {
		t.Error("assembler is nil")
	}
	if r.pool == nil {
		t.Error("pool is nil")
	}
}

func TestFlush_Empty(t *testing.T) {
	r := NewReassembler()
	conns := r.Flush()
	if len(conns) != 0 {
		t.Errorf("Flush() on empty reassembler returned %d connections, want 0", len(conns))
	}
}

func TestProcessPacket_NilLayers(t *testing.T) {
	r := NewReassembler()
	// Create a packet with no network/TCP layers — should not panic
	packet := gopacket.NewPacket([]byte{0x00}, layers.LayerTypeEthernet, gopacket.NoCopy)
	r.ProcessPacket(packet)
	conns := r.Flush()
	if len(conns) != 0 {
		t.Errorf("expected 0 connections from garbage packet, got %d", len(conns))
	}
}

// Integration test: read real pcap, reassemble TCP, verify connections
func TestReassembly_RealCapture(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	pcapPath := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..", "tools", "testing", "testdata", "tls_handshake.pcap")

	if _, err := os.Stat(pcapPath); err != nil {
		t.Skipf("real capture not found: %s", pcapPath)
	}

	f, err := os.Open(pcapPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	pr, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}

	r := NewReassembler()
	packetSource := gopacket.NewPacketSource(pr, pr.LinkType())
	packetCount := 0
	for packet := range packetSource.Packets() {
		r.ProcessPacket(packet)
		packetCount++
	}

	conns := r.Flush()
	t.Logf("processed %d packets, got %d connections", packetCount, len(conns))

	if len(conns) == 0 {
		t.Fatal("expected at least 1 TCP connection from TLS capture")
	}

	// Verify the first connection has data on both sides
	c := conns[0]
	if c.ClientAddr == "" || c.ServerAddr == "" {
		t.Error("connection missing address info")
	}
	if len(c.ClientData) == 0 {
		t.Error("no client data in connection")
	}
	if len(c.ServerData) == 0 {
		t.Error("no server data in connection")
	}
	t.Logf("connection: %s -> %s, client=%d bytes, server=%d bytes",
		c.ClientAddr, c.ServerAddr, len(c.ClientData), len(c.ServerData))
}

func TestConnection_Fields(t *testing.T) {
	c := &Connection{
		ClientAddr: "192.168.1.1:12345",
		ServerAddr: "93.184.216.34:443",
		ClientData: []byte("client hello"),
		ServerData: []byte("server hello"),
		ClientFIN:  true,
		ServerFIN:  true,
	}
	if c.ClientAddr != "192.168.1.1:12345" {
		t.Error("ClientAddr mismatch")
	}
	if c.ServerAddr != "93.184.216.34:443" {
		t.Error("ServerAddr mismatch")
	}
	if !c.ClientFIN || !c.ServerFIN {
		t.Error("FIN flags not set")
	}
}
