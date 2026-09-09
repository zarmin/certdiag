package pcap

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// nonSeekable exposes only Read, simulating a pipe (stdin), so tests exercise
// the peek-based, seek-free open path.
type nonSeekable struct{ r io.Reader }

func (n nonSeekable) Read(p []byte) (int, error) { return n.r.Read(p) }

func TestNewReaderFromStream(t *testing.T) {
	dir := t.TempDir()
	data, err := os.ReadFile(writeTestPcap(t, dir, fakePacket, fakePacket))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("raw stream", func(t *testing.T) {
		r, err := newReader(nonSeekable{bytes.NewReader(data)}, nil)
		if err != nil {
			t.Fatalf("newReader from stream: %v", err)
		}
		if _, _, err := r.ReadPacket(); err != nil {
			t.Fatalf("ReadPacket from stream: %v", err)
		}
	})

	t.Run("gzip stream", func(t *testing.T) {
		var gzBuf bytes.Buffer
		gw := gzip.NewWriter(&gzBuf)
		gw.Write(data)
		gw.Close()
		r, err := newReader(nonSeekable{bytes.NewReader(gzBuf.Bytes())}, nil)
		if err != nil {
			t.Fatalf("newReader from gzip stream: %v", err)
		}
		if _, _, err := r.ReadPacket(); err != nil {
			t.Fatalf("ReadPacket from gzip stream: %v", err)
		}
	})

	t.Run("garbage stream errors", func(t *testing.T) {
		if _, err := newReader(nonSeekable{bytes.NewReader([]byte("not a pcap"))}, nil); err == nil {
			t.Fatal("expected error for non-pcap stream")
		}
	})
}

func writeTestPcap(t *testing.T, dir string, packets ...[]byte) string {
	t.Helper()
	path := filepath.Join(dir, "test.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	for _, pkt := range packets {
		ci := gopacketCaptureInfo(len(pkt))
		if err := w.WritePacket(ci, pkt); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func gopacketCaptureInfo(length int) gopacket.CaptureInfo {
	return gopacket.CaptureInfo{
		CaptureLength: length,
		Length:        length,
	}
}

// minimal fake Ethernet + IP + TCP frame (just enough bytes for gopacket to accept)
var fakePacket = []byte{
	// Ethernet header (14 bytes): dst(6) + src(6) + type(2)=0x0800 (IPv4)
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	0x08, 0x00,
	// IPv4 header (20 bytes): minimal valid
	0x45, 0x00, 0x00, 0x28, // version+IHL, DSCP, total length=40
	0x00, 0x01, 0x00, 0x00, // identification, flags+fragoffset
	0x40, 0x06, 0x00, 0x00, // TTL=64, protocol=TCP, checksum
	0x7f, 0x00, 0x00, 0x01, // src IP
	0x7f, 0x00, 0x00, 0x02, // dst IP
	// TCP header (20 bytes): minimal
	0x00, 0x50, 0x01, 0xbb, // src port=80, dst port=443
	0x00, 0x00, 0x00, 0x01, // seq
	0x00, 0x00, 0x00, 0x00, // ack
	0x50, 0x02, 0xff, 0xff, // data offset=5, SYN, window
	0x00, 0x00, 0x00, 0x00, // checksum, urgent
}

func TestOpen_ValidPcap(t *testing.T) {
	dir := t.TempDir()
	path := writeTestPcap(t, dir, fakePacket)

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error: %v", err)
	}
	defer r.Close()

	if r.LinkType() != layers.LinkTypeEthernet {
		t.Errorf("LinkType() = %v, want Ethernet", r.LinkType())
	}
}

func TestOpen_ReadPackets(t *testing.T) {
	dir := t.TempDir()
	path := writeTestPcap(t, dir, fakePacket, fakePacket)

	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	count := 0
	for {
		_, _, err := r.ReadPacket()
		if err != nil {
			break
		}
		count++
	}
	if count != 2 {
		t.Errorf("read %d packets, want 2", count)
	}
}

func TestOpen_GzippedPcap(t *testing.T) {
	dir := t.TempDir()

	// Write a normal pcap first
	pcapPath := writeTestPcap(t, dir, fakePacket)

	// Gzip it
	gzPath := filepath.Join(dir, "test.pcap.gz")
	raw, err := os.ReadFile(pcapPath)
	if err != nil {
		t.Fatal(err)
	}
	gzFile, err := os.Create(gzPath)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(gzFile)
	gz.Write(raw)
	gz.Close()
	gzFile.Close()

	r, err := Open(gzPath)
	if err != nil {
		t.Fatalf("Open(gzip) error: %v", err)
	}
	defer r.Close()

	if r.LinkType() != layers.LinkTypeEthernet {
		t.Errorf("LinkType() = %v, want Ethernet", r.LinkType())
	}

	_, _, err = r.ReadPacket()
	if err != nil {
		t.Errorf("ReadPacket() from gzip error: %v", err)
	}
}

func TestOpen_NonExistentFile(t *testing.T) {
	_, err := Open("/nonexistent/path/file.pcap")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

func TestOpen_NotPcap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "garbage.pcap")
	os.WriteFile(path, []byte("this is not a pcap file at all"), 0644)

	_, err := Open(path)
	if err == nil {
		t.Fatal("expected error for non-pcap file")
	}
}

func TestOpen_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.pcap")
	os.WriteFile(path, []byte{}, 0644)

	_, err := Open(path)
	if err == nil {
		t.Fatal("expected error for empty file")
	}
}

func TestOpen_TooShort(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "short.pcap")
	os.WriteFile(path, []byte{0xd4, 0xc3}, 0644)

	_, err := Open(path)
	if err == nil {
		t.Fatal("expected error for too-short file")
	}
}

func TestClose_NilCloser(t *testing.T) {
	r := &Reader{}
	if err := r.Close(); err != nil {
		t.Errorf("Close() on nil closer: %v", err)
	}
}

// Integration: read the real tcpdump capture
func TestOpen_RealCapture(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	pcapPath := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..", "tools", "testing", "testdata", "tls_handshake.pcap")

	if _, err := os.Stat(pcapPath); err != nil {
		t.Skipf("real capture not found: %s", pcapPath)
	}

	r, err := Open(pcapPath)
	if err != nil {
		t.Fatalf("Open(real capture) error: %v", err)
	}
	defer r.Close()

	if r.LinkType() != layers.LinkTypeEthernet {
		t.Errorf("LinkType() = %v, want Ethernet", r.LinkType())
	}

	count := 0
	for {
		_, _, err := r.ReadPacket()
		if err != nil {
			break
		}
		count++
	}
	if count == 0 {
		t.Error("expected at least 1 packet from real capture")
	}
	t.Logf("read %d packets from real capture", count)
}
