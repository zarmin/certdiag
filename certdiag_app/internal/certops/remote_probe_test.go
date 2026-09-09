package certops

import (
	"testing"
)

func TestProbeRemoteTLS_NoTarget(t *testing.T) {
	_, err := ProbeRemoteTLS(ProbeRemoteOptions{})
	if err == nil {
		t.Fatal("expected error for empty target")
	}
}

func TestProbeRemoteTLS_InvalidTarget(t *testing.T) {
	_, err := ProbeRemoteTLS(ProbeRemoteOptions{
		Target: "://invalid",
	})
	if err == nil {
		t.Fatal("expected error for invalid target")
	}
}

func TestProbeRemoteTLS_InvalidStarttls(t *testing.T) {
	_, err := ProbeRemoteTLS(ProbeRemoteOptions{
		Target:   "example.com",
		Starttls: "invalid",
	})
	if err == nil {
		t.Fatal("expected error for invalid STARTTLS protocol")
	}
}
