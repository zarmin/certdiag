package cmdutil

import "testing"

const sampleJSON = `{
  "files": [
    {"filename": "a.pem", "file_size": 100, "items": [
      {"type": "certificate", "certificate": {"subject": "CA", "is_ca": true}}
    ]},
    {"filename": "b.pem", "file_size": 200, "items": []}
  ]
}`

func TestEvalJSONPath(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		want    string
		wantErr bool
	}{
		{"scalar_string", "$.files[0].filename", "a.pem", false},
		{"leading_dot_shorthand", ".files[0].filename", "a.pem", false},
		{"brace_kubectl_style", "{.files[0].filename}", "a.pem", false},
		{"array_wildcard_newline_joined", "$.files[*].filename", "a.pem\nb.pem", false},
		{"number_no_decimal", "$.files[0].file_size", "100", false},
		{"bool", "$.files[0].items[0].certificate.is_ca", "true", false},
		{"nested_object_compact_json", "$.files[0].items[0].certificate", `{"is_ca":true,"subject":"CA"}`, false},
		{"empty_expr", "", "", true},
		{"whitespace_only_expr", "   ", "", true},
		{"missing_key", "$.files[0].nope", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EvalJSONPath([]byte(sampleJSON), tt.expr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("EvalJSONPath(%q) err = %v, wantErr %v", tt.expr, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got != tt.want {
				t.Errorf("EvalJSONPath(%q) = %q, want %q", tt.expr, got, tt.want)
			}
		})
	}
}

func TestEvalJSONPathInvalidJSON(t *testing.T) {
	if _, err := EvalJSONPath([]byte("{not json"), "$.x"); err == nil {
		t.Error("expected error for invalid json input")
	}
}
