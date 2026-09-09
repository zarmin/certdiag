package config

import (
	"encoding/json"

	"github.com/invopop/jsonschema"
)

// GenerateJSONSchema returns a JSON Schema (Draft 2020-12) describing the
// certdiag config file format. Field names come from the yaml tags so the schema
// matches the on-disk YAML keys.
func GenerateJSONSchema() (string, error) {
	r := &jsonschema.Reflector{
		ExpandedStruct: true,
		FieldNameTag:   "yaml",
		// Without this, invopop marks every field lacking ,omitempty as required,
		// which rejects valid configs (including certdiag's own generated example).
		// The config has no mandatory fields - all have defaults - so required is
		// opt-in via jsonschema:"required" tags, of which there are none.
		RequiredFromJSONSchemaTags: true,
	}
	schema := r.Reflect(&ConfigFile{})

	data, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
