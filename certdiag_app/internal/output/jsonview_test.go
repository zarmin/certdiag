package output

import (
	"encoding/json"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func TestFormatJSONView(t *testing.T) {
	t.Run("single cert", func(t *testing.T) {
		rsaKey := mustGenRSAKey(t)
		cert := mustSelfSignedCert(t, rsaKey)
		container := makeContainer("/tmp/cert.pem", certlib.FormatPEM, makeCertItem(cert))

		got := FormatJSONView([]*certlib.CertContainer{container}, OutputOptions{})
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(got), &parsed); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		files, ok := parsed["files"].([]interface{})
		if !ok || len(files) != 1 {
			t.Error("expected 1 file in JSON output")
		}
	})

	t.Run("empty", func(t *testing.T) {
		got := FormatJSONView(nil, OutputOptions{})
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(got), &parsed); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
	})
}
