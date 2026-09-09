//go:build linux

package pcap

import (
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// OpenLive opens a live AF_PACKET capture on the named interface (Linux only,
// pure Go, no libpcap/cgo). Requires CAP_NET_RAW or root. Returns a packet
// source, its link type, and a close function.
func OpenLive(iface string) (gopacket.PacketDataSource, layers.LinkType, func() error, error) {
	h, err := pcapgo.NewEthernetHandle(iface)
	if err != nil {
		return nil, 0, nil, err
	}
	return h, layers.LinkTypeEthernet, h.Close, nil
}
