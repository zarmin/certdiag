package pcap

import "testing"

// TestOpenLive covers both build variants: on non-Linux it must return the
// portable-alternative error; on Linux a bogus interface name must fail (no
// privileged capture actually started).
func TestOpenLive(t *testing.T) {
	_, _, closeFn, err := OpenLive("certdiag-nonexistent-iface-zzz")
	if err == nil {
		if closeFn != nil {
			closeFn()
		}
		t.Fatal("expected an error opening a nonexistent/unsupported live interface")
	}
}
