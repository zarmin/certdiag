//go:build !linux

package pcap

import (
	"fmt"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// OpenLive is unsupported off Linux (AF_PACKET is Linux-only). The stdin pipe is
// the portable alternative.
func OpenLive(iface string) (gopacket.PacketDataSource, layers.LinkType, func() error, error) {
	return nil, 0, nil, fmt.Errorf(
		"live capture is only supported on Linux; use a capture tool instead: tcpdump -i %s -w - | certdiag pcap -", iface)
}
