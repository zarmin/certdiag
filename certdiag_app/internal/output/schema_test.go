package output

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGenerateJSONSchema(t *testing.T) {
	got, err := GenerateJSONSchema()
	if err != nil {
		t.Fatalf("GenerateJSONSchema() error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if !strings.Contains(got, "title") {
		t.Error("schema should contain 'title'")
	}
	if !strings.Contains(got, "properties") {
		t.Error("schema should contain 'properties'")
	}
}

// TestGenerateRemoteJSONSchema is the LOW addition: the remote inspection output
// shape has its own schema (now first-class via `certdiag <host>` autodetection).
func TestGenerateRemoteJSONSchema(t *testing.T) {
	got, err := GenerateRemoteJSONSchema()
	if err != nil {
		t.Fatalf("GenerateRemoteJSONSchema() error: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	props, _ := parsed["properties"].(map[string]any)
	if _, ok := props["targets"]; !ok {
		t.Errorf("remote schema should describe the targets field: %v", parsed["properties"])
	}
}
