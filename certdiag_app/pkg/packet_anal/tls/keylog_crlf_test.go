package tls

import (
	"encoding/hex"
	"strings"
	"testing"
)

// TestParseKeyLog_CRLFAndMixedLabels: a keylog written on Windows, with
// comments and mixed TLS 1.2 / 1.3 labels, parses whole.
func TestParseKeyLog_CRLFAndMixedLabels(t *testing.T) {
	cr := strings.Repeat("aa", 32)
	text := "# SSL/TLS secrets log file\r\n" +
		"CLIENT_RANDOM " + cr + " " + strings.Repeat("11", 48) + "\r\n" +
		"\r\n" +
		"SERVER_HANDSHAKE_TRAFFIC_SECRET " + cr + " " + strings.Repeat("22", 32) + "\r\n" +
		"CLIENT_TRAFFIC_SECRET_0 " + cr + " " + strings.Repeat("33", 32) + "\r\n"
	kl, err := ParseKeyLog(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	if kl.Len() != 1 {
		t.Errorf("Len counts client randoms: got %d, want 1", kl.Len())
	}
	random, _ := hex.DecodeString(cr)
	for _, label := range []string{"CLIENT_RANDOM", "SERVER_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0"} {
		if _, ok := kl.Secret(random, label); !ok {
			t.Errorf("%s not found", label)
		}
	}
}
