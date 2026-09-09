package output

import (
	"encoding/json"

	"github.com/invopop/jsonschema"
)

func GenerateJSONSchema() (string, error) {
	return schemaFor(&StructuredOutput{})
}

// GenerateRemoteJSONSchema describes the structured output of remote inspection
// (remote fetch, and `certdiag <host>` autodetection with -o json/yaml).
func GenerateRemoteJSONSchema() (string, error) {
	return schemaFor(&RemoteStructuredOutput{})
}

func schemaFor(v any) (string, error) {
	r := &jsonschema.Reflector{
		ExpandedStruct: true,
	}
	schema := r.Reflect(v)

	data, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
