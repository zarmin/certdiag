package certlib

import (
	"context"
	"testing"
	"time"
)

func TestProbeServerHonorsCancelledContext(t *testing.T) {
	// 203.0.113.1 is in TEST-NET-3 (RFC 5737): a black-hole address that never
	// completes a connection. With a large per-probe timeout, the only way this
	// returns quickly is if ProbeServer honors the cancelled context.
	target := RemoteTarget{Host: "203.0.113.1", Port: 443, IsIP: true}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, err := ProbeServer(ctx, target, StarttlsNone, 30*time.Second, false, false)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error when the context is cancelled")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("ProbeServer blocked for %v despite a cancelled context", elapsed)
	}
}
