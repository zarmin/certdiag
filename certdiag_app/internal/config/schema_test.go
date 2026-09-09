package config

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestGenerateJSONSchema(t *testing.T) {
	s, err := GenerateJSONSchema()
	if err != nil {
		t.Fatalf("GenerateJSONSchema: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal([]byte(s), &doc); err != nil {
		t.Fatalf("schema is not valid json: %v", err)
	}

	// Field names must come from yaml tags, not Go field names.
	for _, key := range []string{"kind", "passwords", "expiry_warn_days", "rsa_key_size", "disabled_checks"} {
		if !strings.Contains(s, key) {
			t.Errorf("schema missing yaml key %q", key)
		}
	}
	if strings.Contains(s, "ExpiryWarnDays") {
		t.Error("schema leaked Go field name ExpiryWarnDays; yaml tag naming not applied")
	}

	// M15: the config has no mandatory fields, so the schema must not mark any
	// field required - otherwise valid configs (including certdiag's own example)
	// fail validation. Walk the whole schema for a non-empty "required".
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch node := v.(type) {
		case map[string]any:
			if req, ok := node["required"].([]any); ok && len(req) > 0 {
				t.Errorf("schema marks fields required at %s: %v", path, req)
			}
			for k, child := range node {
				walk(path+"/"+k, child)
			}
		case []any:
			for i, child := range node {
				walk(fmt.Sprintf("%s[%d]", path, i), child)
			}
		}
	}
	walk("", doc)
}
