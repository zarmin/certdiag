package pcapint

import (
	"errors"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/session"
	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/tcp"
	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/tls"
)

// LiveOptions controls a live capture analysis. Source is any packet source
// (a real AF_PACKET handle on Linux, or a mock in tests).
type LiveOptions struct {
	Source     gopacket.PacketDataSource
	LinkType   layers.LinkType
	Aggressive bool
	KeyLog     *tls.KeyLog
	MaxPackets int           // stop after N packets (0 = unlimited)
	Duration   time.Duration // stop after this long (0 = unlimited)
	Stop       <-chan struct{}
	Close      func() error // called on stop to unblock a blocking Source
}

// CloseOnce wraps a close function so repeated or concurrent calls run it only
// once; later calls return the first call's error. AnalyzeLive's stop watcher
// and the caller's own defer may both close the same capture handle.
func CloseOnce(fn func() error) func() error {
	var once sync.Once
	var err error
	return func() error {
		once.Do(func() { err = fn() })
		return err
	}
}

// AnalyzeLive reads packets from a live source until a stop condition, then
// reassembles and analyzes them exactly like a captured file. It reuses the same
// TCP reassembly and TLS session pipeline, so keylog decryption works here too.
func AnalyzeLive(opts LiveOptions) (*AnalyzeResult, error) {
	if opts.Source == nil {
		return nil, errors.New("no capture source")
	}

	// A blocking real source is unblocked by closing it; this watcher fires the
	// close on duration/stop. Mock sources return EOF on their own, so no watcher.
	if (opts.Duration > 0 || opts.Stop != nil) && opts.Close != nil {
		done := make(chan struct{})
		defer close(done)
		go func() {
			var timer <-chan time.Time
			if opts.Duration > 0 {
				tm := time.NewTimer(opts.Duration)
				defer tm.Stop()
				timer = tm.C
			}
			select {
			case <-timer:
			case <-opts.Stop:
			case <-done:
				return
			}
			opts.Close()
		}()
	}

	reassembler := tcp.NewReassembler()
	packetCount := 0
	for {
		if opts.MaxPackets > 0 && packetCount >= opts.MaxPackets {
			break
		}
		data, ci, err := opts.Source.ReadPacketData()
		if err != nil {
			break // EOF, closed handle, or fatal read error -> stop
		}
		packetCount++
		// NoCopy requires the source to hand over buffer ownership: both the
		// pcap file reader and pcapgo's EthernetHandle.ReadPacketData return a
		// fresh slice per packet (the zero-copy variant is not used here).
		packet := gopacket.NewPacket(data, opts.LinkType, gopacket.NoCopy)
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

	return &AnalyzeResult{
		Sessions:    allSessions,
		AllSessions: allSessions,
		Total:       len(allSessions),
		Packets:     packetCount,
		Connections: len(connections),
		TotalBytes:  totalBytes,
		PcapFile:    "live",
	}, nil
}
