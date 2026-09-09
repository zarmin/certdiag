package cmdutil

import (
	"io"
	"os"
	"testing"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = orig
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestEmitStructured(t *testing.T) {
	human := func() string { return "HUMAN" }
	json := func() string { return "JSON" }
	yaml := func() string { return "YAML" }

	cases := map[string]string{
		OutputJSON:      "JSON",
		OutputYAML:      "YAML",
		OutputHuman:     "HUMAN",
		"anything-else": "HUMAN",
	}
	for format, want := range cases {
		got := captureStdout(t, func() {
			EmitStructured(format, human, json, yaml)
		})
		if got != want {
			t.Errorf("format %q: got %q, want %q", format, got, want)
		}
	}
}

func TestEmitStructuredLazy(t *testing.T) {
	called := map[string]bool{}
	human := func() string { called["human"] = true; return "" }
	json := func() string { called["json"] = true; return "" }
	yaml := func() string { called["yaml"] = true; return "" }

	captureStdout(t, func() { EmitStructured(OutputJSON, human, json, yaml) })
	if !called["json"] || called["human"] || called["yaml"] {
		t.Errorf("only json producer should run, got %v", called)
	}
}
