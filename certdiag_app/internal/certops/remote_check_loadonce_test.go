package certops

import (
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

// TestCheckRemoteReadsTheStoresOnce guards M9: however many targets a run
// has, and however parallel it is, the OS trust store is read exactly once.
func TestCheckRemoteReadsTheStoresOnce(t *testing.T) {
	listener, serverCert, port := startTestTLSServer(t)
	defer listener.Close()

	var reads int32
	readers := StoreReaders{
		OS: func() ([]truststore.StoreContents, error) {
			atomic.AddInt32(&reads, 1)
			return []truststore.StoreContents{storeFixture("Stub OS Store", truststore.StoreTypeOS, "/os", serverCert)}, nil
		},
	}
	target := fmt.Sprintf("127.0.0.1:%d", port)
	result, err := CheckRemote(CheckRemoteOptions{
		Targets:   []string{target, target, target},
		Parallel:  3,
		NoAIA:     true,
		StoreLoad: hermeticOpts(readers),
	})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if got := atomic.LoadInt32(&reads); got != 1 {
		t.Errorf("OS store read %d times for 3 targets, want 1", got)
	}
	if result.Summary.Total != 3 {
		t.Errorf("summary total %d, want 3", result.Summary.Total)
	}
}
