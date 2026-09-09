package pcapint

import (
	"io"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/pcap"
	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/tls"
)

const (
	fixturePcap   = "../../../tools/testing/testdata/tls13_keylog.pcap"
	fixtureKeylog = "../../../tools/testing/testdata/tls13.keylog"
)

// mockSource replays captured packets then reports EOF, standing in for a live
// AF_PACKET handle so the live-analysis loop is testable off Linux.
type mockSource struct {
	packets [][]byte
	i       int
}

func (m *mockSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	if m.i >= len(m.packets) {
		return nil, gopacket.CaptureInfo{}, io.EOF
	}
	p := m.packets[m.i]
	m.i++
	return p, gopacket.CaptureInfo{CaptureLength: len(p), Length: len(p), Timestamp: time.Now()}, nil
}

func fixturePackets(t *testing.T) ([][]byte, layers.LinkType) {
	t.Helper()
	r, err := pcap.Open(fixturePcap)
	if err != nil {
		t.Skipf("fixture pcap unavailable: %v", err)
	}
	defer r.Close()
	lt := r.LinkType()
	var pkts [][]byte
	for {
		data, _, err := r.ReadPacket()
		if err != nil {
			break
		}
		pkts = append(pkts, append([]byte(nil), data...))
	}
	return pkts, lt
}

func TestAnalyzeLive(t *testing.T) {
	pkts, lt := fixturePackets(t)
	if len(pkts) == 0 {
		t.Fatal("no fixture packets")
	}
	kl, err := tls.ParseKeyLogFile(fixtureKeylog)
	if err != nil {
		t.Fatal(err)
	}

	res, err := AnalyzeLive(LiveOptions{Source: &mockSource{packets: pkts}, LinkType: lt, KeyLog: kl})
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 1 {
		t.Fatalf("expected 1 session from live source, got %d", res.Total)
	}
	s := res.Sessions[0]
	if !s.CertsDecrypted || s.Certificates == nil {
		t.Fatalf("expected decrypted cert from live source; encrypted=%v err=%q", s.TLS13CertEncrypted, s.DecryptError)
	}
}

func TestAnalyzeLiveMaxPackets(t *testing.T) {
	pkts, lt := fixturePackets(t)
	res, err := AnalyzeLive(LiveOptions{Source: &mockSource{packets: pkts}, LinkType: lt, MaxPackets: 1})
	if err != nil {
		t.Fatal(err)
	}
	if res.Packets != 1 {
		t.Fatalf("MaxPackets=1 but processed %d packets", res.Packets)
	}
}

func TestAnalyzeLiveNoSource(t *testing.T) {
	if _, err := AnalyzeLive(LiveOptions{}); err == nil {
		t.Fatal("expected error with nil source")
	}
}
