package pcap

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

type Reader struct {
	source   gopacket.PacketDataSource
	linkType layers.LinkType
	closer   io.Closer
}

// Open opens a pcap/pcapng file, or reads a stream from stdin when path is "-"
// (e.g. `tcpdump -w - | certdiag pcap -`). Both raw and gzip-compressed input
// are supported. Stdin is non-seekable, so detection is peek-based.
func Open(path string) (*Reader, error) {
	if path == "-" {
		r, err := newReader(os.Stdin, nil)
		if err != nil {
			return nil, fmt.Errorf("read pcap from stdin: %w", err)
		}
		return r, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	r, err := newReader(f, f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return r, nil
}

// newReader builds a Reader from any (possibly non-seekable) stream. closer, if
// non-nil, is closed by Reader.Close.
func newReader(raw io.Reader, closer io.Closer) (*Reader, error) {
	br := bufio.NewReader(raw)

	// Peek (not seek) so this works on a pipe: detect gzip by magic bytes.
	var rd io.Reader = br
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		rd = gz
	}

	r, linkType, err := tryOpen(rd)
	if err != nil {
		return nil, err
	}
	return &Reader{source: r, linkType: linkType, closer: closer}, nil
}

func tryOpen(r io.Reader) (gopacket.PacketDataSource, layers.LinkType, error) {
	// We need to peek at the magic bytes to determine the format.
	// pcap magic: 0xd4c3b2a1 or 0xa1b2c3d4 (or nanosecond variants)
	// pcapng magic: 0x0a0d0d0a (Section Header Block)
	magic := make([]byte, 4)
	n, err := io.ReadFull(r, magic)
	if err != nil {
		return nil, 0, fmt.Errorf("read magic: %w", err)
	}
	if n < 4 {
		return nil, 0, errors.New("file too short")
	}

	// Reconstruct a reader with the magic bytes prepended
	combined := io.MultiReader(bytesReader(magic), r)

	if isPcapNg(magic) {
		ngr, err := pcapgo.NewNgReader(combined, pcapgo.NgReaderOptions{})
		if err != nil {
			return nil, 0, fmt.Errorf("pcapng: %w", err)
		}
		return ngr, ngr.LinkType(), nil
	}

	if isPcap(magic) {
		pr, err := pcapgo.NewReader(combined)
		if err != nil {
			return nil, 0, fmt.Errorf("pcap: %w", err)
		}
		return pr, pr.LinkType(), nil
	}

	return nil, 0, errors.New("unknown file format (not pcap or pcapng)")
}

func isPcapNg(magic []byte) bool {
	// pcapng Section Header Block magic: 0x0a0d0d0a
	return magic[0] == 0x0a && magic[1] == 0x0d && magic[2] == 0x0d && magic[3] == 0x0a
}

func isPcap(magic []byte) bool {
	// pcap little-endian: d4 c3 b2 a1
	if magic[0] == 0xd4 && magic[1] == 0xc3 && magic[2] == 0xb2 && magic[3] == 0xa1 {
		return true
	}
	// pcap big-endian: a1 b2 c3 d4
	if magic[0] == 0xa1 && magic[1] == 0xb2 && magic[2] == 0xc3 && magic[3] == 0xd4 {
		return true
	}
	// nanosecond pcap little-endian: 4d 3c b2 a1
	if magic[0] == 0x4d && magic[1] == 0x3c && magic[2] == 0xb2 && magic[3] == 0xa1 {
		return true
	}
	// nanosecond pcap big-endian: a1 b2 3c 4d
	if magic[0] == 0xa1 && magic[1] == 0xb2 && magic[2] == 0x3c && magic[3] == 0x4d {
		return true
	}
	return false
}

func bytesReader(b []byte) io.Reader {
	return &fixedReader{data: b}
}

type fixedReader struct {
	data []byte
	pos  int
}

func (r *fixedReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func (r *Reader) ReadPacket() ([]byte, gopacket.CaptureInfo, error) {
	return r.source.ReadPacketData()
}

func (r *Reader) LinkType() layers.LinkType {
	return r.linkType
}

func (r *Reader) Close() error {
	if r.closer != nil {
		return r.closer.Close()
	}
	return nil
}
