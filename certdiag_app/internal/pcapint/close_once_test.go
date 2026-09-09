package pcapint

import (
	"errors"
	"io"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// TestCloseOnce verifies repeated calls run the wrapped close only once and
// return the first call's error.
func TestCloseOnce(t *testing.T) {
	calls := 0
	sentinel := errors.New("close failed")
	fn := CloseOnce(func() error {
		calls++
		return sentinel
	})

	if err := fn(); err != sentinel {
		t.Errorf("first call err = %v, want sentinel", err)
	}
	if err := fn(); err != sentinel {
		t.Errorf("second call err = %v, want sentinel", err)
	}
	if calls != 1 {
		t.Errorf("close ran %d times, want 1", calls)
	}
}

// blockingSource blocks in ReadPacketData until closed, like a real AF_PACKET
// handle with no traffic.
type blockingSource struct {
	closed chan struct{}
}

func (b *blockingSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	<-b.closed
	return nil, gopacket.CaptureInfo{}, io.EOF
}

// TestAnalyzeLiveDoubleClose exercises the real double-close path: the stop
// watcher inside AnalyzeLive closes the handle to unblock the read, then the
// caller's deferred close fires again. The underlying close must run once.
func TestAnalyzeLiveDoubleClose(t *testing.T) {
	src := &blockingSource{closed: make(chan struct{})}
	calls := 0
	closeFn := CloseOnce(func() error {
		calls++
		close(src.closed)
		return nil
	})

	stop := make(chan struct{})
	close(stop)
	_, err := AnalyzeLive(LiveOptions{
		Source:   src,
		LinkType: layers.LinkTypeEthernet,
		Stop:     stop,
		Close:    closeFn,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := closeFn(); err != nil {
		t.Fatalf("deferred close returned %v", err)
	}
	if calls != 1 {
		t.Errorf("close ran %d times, want 1", calls)
	}
}
