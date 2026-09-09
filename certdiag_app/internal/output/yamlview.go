package output

import (
	"fmt"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"gopkg.in/yaml.v3"
)

func FormatYAMLView(containers []*certlib.CertContainer, opts OutputOptions) string {
	data := BuildStructuredOutput(containers, opts)
	b, err := yaml.Marshal(data)
	if err != nil {
		return fmt.Sprintf("error: %v\n", err)
	}
	return string(b)
}
