package output

import (
	"encoding/json"
	"fmt"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func FormatJSONView(containers []*certlib.CertContainer, opts OutputOptions) string {
	data := BuildStructuredOutput(containers, opts)
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Sprintf("{\"error\": %q}\n", err.Error())
	}
	return string(b) + "\n"
}
