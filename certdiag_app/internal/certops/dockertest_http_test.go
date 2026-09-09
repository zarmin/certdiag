//go:build dockertest

package certops

import (
	"fmt"
	"strings"
	"testing"
)

func TestDockerHTTP_BasicGET(t *testing.T) {
	requireDockerAvailable(t)

	result, err := HTTPRemote(HTTPRemoteOptions{
		Target:  fmt.Sprintf("https://localhost:%d/", portModernTLS),
		Timeout: dockerTestTimeout,
	})
	if err != nil {
		t.Fatalf("HTTPRemote error: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("HTTP error: %s", result.Error)
	}
	if result.Response == nil {
		t.Fatal("response is nil")
	}
	if result.Response.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", result.Response.StatusCode)
	}
}

func TestDockerHTTP_CustomHeaders(t *testing.T) {
	requireDockerAvailable(t)
	requireServiceAvailable(t, portEcho)

	result, err := HTTPRemote(HTTPRemoteOptions{
		Target:        fmt.Sprintf("https://localhost:%d/", portEcho),
		Timeout:       dockerTestTimeout,
		CustomHeaders: []string{"X-Test: hello-certdiag"},
	})
	if err != nil {
		t.Fatalf("HTTPRemote error: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("HTTP error: %s", result.Error)
	}
	if result.Response.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", result.Response.StatusCode)
	}
	// Verify the request headers were set
	if v, ok := result.RequestHeaders["X-Test"]; !ok || v != "hello-certdiag" {
		t.Errorf("expected X-Test header in request, got %v", result.RequestHeaders)
	}
}

func TestDockerHTTP_RedirectNoFollow(t *testing.T) {
	requireDockerAvailable(t)
	requireServiceAvailable(t, portRedirect)

	result, err := HTTPRemote(HTTPRemoteOptions{
		Target:          fmt.Sprintf("https://localhost:%d/", portRedirect),
		Timeout:         dockerTestTimeout,
		FollowRedirects: false,
	})
	if err != nil {
		t.Fatalf("HTTPRemote error: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("HTTP error: %s", result.Error)
	}
	if result.Response.StatusCode != 301 {
		t.Errorf("expected status 301, got %d", result.Response.StatusCode)
	}
	loc := result.Response.Headers.Get("Location")
	if loc == "" {
		t.Error("expected Location header in 301 response")
	}
	if !strings.Contains(loc, "14430") {
		t.Errorf("expected Location to point to port 14430, got %q", loc)
	}
}

func TestDockerHTTP_RedirectFollow(t *testing.T) {
	requireDockerAvailable(t)
	requireServiceAvailable(t, portRedirect)

	result, err := HTTPRemote(HTTPRemoteOptions{
		Target:          fmt.Sprintf("https://localhost:%d/", portRedirect),
		Timeout:         dockerTestTimeout,
		FollowRedirects: true,
	})
	if err != nil {
		t.Fatalf("HTTPRemote error: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("HTTP error: %s", result.Error)
	}
	if result.Response.StatusCode != 200 {
		t.Errorf("expected final status 200 after redirect, got %d", result.Response.StatusCode)
	}
}
