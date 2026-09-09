package session

import (
	"strings"
	"testing"
)

func TestSummarizeAppData(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		want    string
		wantSub bool // want is a substring
	}{
		{"http request", "GET /path HTTP/1.1\r\nHost: x\r\n\r\n", "GET /path HTTP/1.1", false},
		{"http response", "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc", "HTTP/1.1 200 OK", false},
		{"post request", "POST /api HTTP/1.1\r\n\r\nbody", "POST /api HTTP/1.1", false},
		{"non-http", "\x00\x01\x02random binary\xff", "non-HTTP or binary", true},
		{"empty", "", "", false},
		{"method without http token is non-http", "GET-something-else\r\n", "non-HTTP", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SummarizeAppData([]byte(tt.data))
			if tt.wantSub {
				if !strings.Contains(got, tt.want) {
					t.Errorf("SummarizeAppData = %q, want substring %q", got, tt.want)
				}
			} else if got != tt.want {
				t.Errorf("SummarizeAppData = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSummarizeAppDataTruncates(t *testing.T) {
	long := "GET /" + strings.Repeat("a", 100) + " HTTP/1.1"
	got := SummarizeAppData([]byte(long))
	if len(got) > 90 || !strings.HasSuffix(got, "...") {
		t.Errorf("expected truncated HTTP line, got %q (len %d)", got, len(got))
	}
}
