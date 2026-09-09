package output

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"gopkg.in/yaml.v3"
)

func TestFormatDiffSourceLabel(t *testing.T) {
	disableColors(t)

	t.Run("simple path", func(t *testing.T) {
		src := certlib.DiffSource{FilePath: "/tmp/cert.pem"}
		got := formatDiffSourceLabel(src)
		if got != "cert.pem" {
			t.Errorf("got %q, want %q", got, "cert.pem")
		}
	})

	t.Run("with item index", func(t *testing.T) {
		src := certlib.DiffSource{FilePath: "/tmp/bundle.pem", ItemIndex: 1}
		got := formatDiffSourceLabel(src)
		if !strings.Contains(got, "#2") {
			t.Errorf("got %q, expected to contain '#2'", got)
		}
	})

	t.Run("with alias", func(t *testing.T) {
		src := certlib.DiffSource{FilePath: "/tmp/store.jks", ItemIndex: 0, Alias: "mykey"}
		got := formatDiffSourceLabel(src)
		// ItemIndex=0 but Alias!="" triggers the block
		if !strings.Contains(got, "mykey") {
			t.Errorf("got %q, expected to contain alias", got)
		}
	})
}

func TestFormatDiffHuman_Identical(t *testing.T) {
	disableColors(t)

	result := certlib.DiffResult{
		Left:  certlib.DiffSource{FilePath: "/tmp/a.pem"},
		Right: certlib.DiffSource{FilePath: "/tmp/b.pem"},
		Fields: []certlib.DiffField{
			{Name: "Subject", Status: certlib.DiffSame, Left: "CN=test"},
		},
		Summary: certlib.DiffSummary{Same: 1},
	}
	got := FormatDiffHuman(result, DiffOutputOptions{})
	if !strings.Contains(got, "All fields are identical.") {
		t.Errorf("expected identical message, got %q", got)
	}
}

func TestFormatDiffHuman_Changes(t *testing.T) {
	disableColors(t)

	result := certlib.DiffResult{
		Left:  certlib.DiffSource{FilePath: "/tmp/a.pem"},
		Right: certlib.DiffSource{FilePath: "/tmp/b.pem"},
		Fields: []certlib.DiffField{
			{Name: "Subject", Status: certlib.DiffChanged, Left: "CN=old", Right: "CN=new"},
			{Name: "Issuer", Status: certlib.DiffSame, Left: "CN=ca"},
			{Name: "Extra", Status: certlib.DiffAdded, Right: "value"},
			{Name: "Old", Status: certlib.DiffRemoved, Left: "gone"},
		},
		Summary: certlib.DiffSummary{Changed: 1, Same: 1, Added: 1, Removed: 1},
	}
	got := FormatDiffHuman(result, DiffOutputOptions{})
	if !strings.Contains(got, "->") {
		t.Error("should contain '->' for changed fields")
	}
	if !strings.Contains(got, "(added)") {
		t.Error("should contain '(added)'")
	}
	if !strings.Contains(got, "(removed)") {
		t.Error("should contain '(removed)'")
	}
	if !strings.Contains(got, "(same)") {
		t.Error("should contain '(same)'")
	}
	if !strings.Contains(got, "Summary:") {
		t.Error("should contain summary")
	}
}

func TestFormatDiffHuman_OnlyChanges(t *testing.T) {
	disableColors(t)

	result := certlib.DiffResult{
		Left:  certlib.DiffSource{FilePath: "/tmp/a.pem"},
		Right: certlib.DiffSource{FilePath: "/tmp/b.pem"},
		Fields: []certlib.DiffField{
			{Name: "Subject", Status: certlib.DiffChanged, Left: "CN=old", Right: "CN=new"},
			{Name: "Issuer", Status: certlib.DiffSame, Left: "CN=ca"},
		},
		Summary: certlib.DiffSummary{Changed: 1, Same: 1},
	}
	got := FormatDiffHuman(result, DiffOutputOptions{OnlyChanges: true})
	if strings.Contains(got, "(same)") {
		t.Error("OnlyChanges should exclude (same) fields")
	}
	if !strings.Contains(got, "->") {
		t.Error("should still contain changed fields")
	}
}

func TestFormatDiffHuman_Children(t *testing.T) {
	disableColors(t)

	result := certlib.DiffResult{
		Left:  certlib.DiffSource{FilePath: "/tmp/a.pem"},
		Right: certlib.DiffSource{FilePath: "/tmp/b.pem"},
		Fields: []certlib.DiffField{
			{
				Name:   "SANs",
				Status: certlib.DiffChanged,
				Children: []certlib.DiffField{
					{Name: "DNS:common.example.com", Status: certlib.DiffSame},
					{Name: "DNS:new.example.com", Status: certlib.DiffAdded},
					{Name: "DNS:old.example.com", Status: certlib.DiffRemoved},
				},
			},
		},
		Summary: certlib.DiffSummary{Changed: 1},
	}
	got := FormatDiffHuman(result, DiffOutputOptions{})
	if !strings.Contains(got, "+ DNS:new.example.com") {
		t.Error("should contain '+ ' prefix for added children")
	}
	if !strings.Contains(got, "- DNS:old.example.com") {
		t.Error("should contain '- ' prefix for removed children")
	}
}

func TestFormatDiffJSON(t *testing.T) {
	disableColors(t)

	result := certlib.DiffResult{
		Left:  certlib.DiffSource{FilePath: "/tmp/a.pem"},
		Right: certlib.DiffSource{FilePath: "/tmp/b.pem"},
		Fields: []certlib.DiffField{
			{Name: "Subject", Status: certlib.DiffChanged, Left: "CN=old", Right: "CN=new"},
		},
		Summary: certlib.DiffSummary{Changed: 1},
	}
	got := FormatDiffJSON(result, DiffOutputOptions{})
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for _, key := range []string{"left", "right", "fields", "summary", "identical"} {
		if _, ok := parsed[key]; !ok {
			t.Errorf("missing key %q", key)
		}
	}
}

func TestFormatDiffYAML(t *testing.T) {
	result := certlib.DiffResult{
		Left:  certlib.DiffSource{FilePath: "/tmp/a.pem"},
		Right: certlib.DiffSource{FilePath: "/tmp/b.pem"},
		Fields: []certlib.DiffField{
			{Name: "Subject", Status: certlib.DiffSame, Left: "CN=test"},
		},
		Summary: certlib.DiffSummary{Same: 1},
	}
	got := FormatDiffYAML(result, DiffOutputOptions{})
	var parsed interface{}
	if err := yaml.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("invalid YAML: %v", err)
	}
}

func TestBuildDiffOutputJSON_OnlyChanges(t *testing.T) {
	result := certlib.DiffResult{
		Left:  certlib.DiffSource{FilePath: "/tmp/a.pem"},
		Right: certlib.DiffSource{FilePath: "/tmp/b.pem"},
		Fields: []certlib.DiffField{
			{Name: "Subject", Status: certlib.DiffChanged, Left: "CN=old", Right: "CN=new"},
			{Name: "Issuer", Status: certlib.DiffSame, Left: "CN=ca"},
		},
		Summary: certlib.DiffSummary{Changed: 1, Same: 1},
	}
	out := buildDiffOutputJSON(result, DiffOutputOptions{OnlyChanges: true})
	for _, f := range out.Fields {
		if f.Status == certlib.DiffSame {
			t.Errorf("OnlyChanges should filter 'same' fields, found %q", f.Name)
		}
	}
	if out.Summary.Same != 1 {
		t.Errorf("summary should retain same count, got %d", out.Summary.Same)
	}
}
