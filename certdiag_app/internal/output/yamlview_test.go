package output

import (
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"gopkg.in/yaml.v3"
)

func TestFormatYAMLView(t *testing.T) {
	t.Run("single cert", func(t *testing.T) {
		rsaKey := mustGenRSAKey(t)
		cert := mustSelfSignedCert(t, rsaKey)
		container := makeContainer("/tmp/cert.pem", certlib.FormatPEM, makeCertItem(cert))

		got := FormatYAMLView([]*certlib.CertContainer{container}, OutputOptions{})
		var parsed interface{}
		if err := yaml.Unmarshal([]byte(got), &parsed); err != nil {
			t.Fatalf("invalid YAML: %v", err)
		}
	})

	t.Run("empty", func(t *testing.T) {
		got := FormatYAMLView(nil, OutputOptions{})
		var parsed interface{}
		if err := yaml.Unmarshal([]byte(got), &parsed); err != nil {
			t.Fatalf("invalid YAML: %v", err)
		}
	})
}
