package pcapint

import (
	"fmt"
	"io"

	"github.com/gopacket/gopacket"
	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/pcap"
	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/session"
	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/tcp"
	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/tls"
)

type AnalyzeOptions struct {
	Path       string
	Aggressive bool
	KeyLog     *tls.KeyLog // optional SSLKEYLOGFILE for TLS 1.3 decryption
}

type AnalyzeResult struct {
	Sessions    []*session.Session
	AllSessions []*session.Session
	Total       int
	Packets     int
	Connections int
	TotalBytes  int64
	PcapFile    string
}

func Analyze(opts AnalyzeOptions) (*AnalyzeResult, error) {
	r, err := pcap.Open(opts.Path)
	if err != nil {
		return nil, fmt.Errorf("open pcap: %w", err)
	}
	defer r.Close()

	reassembler := tcp.NewReassembler()
	packetCount := 0

	for {
		data, ci, err := r.ReadPacket()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read packet: %w", err)
		}
		packetCount++

		packet := gopacket.NewPacket(data, r.LinkType(), gopacket.NoCopy)
		packet.Metadata().Timestamp = ci.Timestamp
		packet.Metadata().CaptureLength = ci.CaptureLength
		packet.Metadata().Length = ci.Length
		reassembler.ProcessPacket(packet)
	}

	connections := reassembler.Flush()

	var totalBytes int64
	for _, c := range connections {
		totalBytes += int64(len(c.ClientData) + len(c.ServerData))
	}

	tracker := &session.Tracker{Aggressive: opts.Aggressive, KeyLog: opts.KeyLog}
	allSessions := tracker.ProcessConnections(connections)
	total := len(allSessions)

	return &AnalyzeResult{
		Sessions:    allSessions,
		AllSessions: allSessions,
		Total:       total,
		Packets:     packetCount,
		Connections: len(connections),
		TotalBytes:  totalBytes,
		PcapFile:    opts.Path,
	}, nil
}
