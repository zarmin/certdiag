package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

// Fast submit exists because the forms are long and the field that matters is
// usually the first one: the remote fetch form has thirteen fields and a normal
// use fills in one.

func keyF2() tea.KeyMsg       { return tea.KeyMsg{Type: tea.KeyF2} }
func keyAltEnter() tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyEnter, Alt: true} }

func TestFastSubmit_FromTheFirstField(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  tea.KeyMsg
	}{
		{"F2", keyF2()},
		{"Alt+Enter", keyAltEnter()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			initStyles()
			initFormStyles()
			f := buildRemoteForm()
			f.fieldByName(fieldKeyTarget).SetValue("example.com:443")
			f.setFocus(0)

			submitted, _ := f.update(tc.key)
			if !submitted {
				t.Error("a valid form must submit from the field the user is on")
			}
		})
	}
}

// TestFastSubmit_RefusalSaysWhere: a refused submit that just refuses is a dead
// end; validateAll moves the cursor to the field at fault.
func TestFastSubmit_RefusalSaysWhere(t *testing.T) {
	initStyles()
	initFormStyles()
	f := buildRemoteForm()
	f.fieldByName(fieldKeyTarget).SetValue("") // required
	f.setFocus(len(f.fields) - 1)              // sitting on the submit button

	submitted, _ := f.update(keyF2())
	if submitted {
		t.Fatal("a form missing a required field must not submit")
	}
	if len(f.errors) == 0 {
		t.Error("the refusal must record what was wrong")
	}
	if f.fieldNames[f.focusIdx] != fieldKeyTarget {
		t.Errorf("the cursor must land on the offending field, got %q", f.fieldNames[f.focusIdx])
	}
}

// TestFastSubmit_EveryForm: the shortcut lives in the shared update path, so it
// applies to all of them. A form that stopped reaching that path would be a
// silent regression.
func TestFastSubmit_EveryForm(t *testing.T) {
	initStyles()
	initFormStyles()

	forms := map[string]*formModel{
		"remote":      buildRemoteForm(),
		"create key":  buildCreateKeyForm("/tmp", certlib.KeyGenOptions{}),
		"pcap":        buildPcapForm("/tmp", false),
		"proxy":       buildProxyForm("127.0.0.1:8080", "example.com:443", false),
		"create cert": buildCreateCertForm("/tmp", nil, "", "", certlib.KeyGenOptions{}, 0, 0),
		"create csr":  buildCreateCSRForm("/tmp", nil, "", "", certlib.KeyGenOptions{}),
	}

	for name, f := range forms {
		if f == nil {
			t.Errorf("%s: no form", name)
			continue
		}
		// Not asserting that each submits - most need fields filled in - only
		// that the key reaches validation rather than being typed into a field.
		before := f.focusIdx
		submitted, _ := f.update(keyF2())
		if !submitted && len(f.errors) == 0 && f.focusIdx == before {
			t.Errorf("%s: F2 did nothing; the form is not on the shared submit path", name)
		}
	}
}

func TestFastSubmit_AdvertisedInTheFooter(t *testing.T) {
	initStyles()
	initFormStyles()
	f := buildRemoteForm()
	f.width = 400 // wide enough that nothing is elided

	bar, _ := f.footerHints()
	if !strings.Contains(bar, "F2") || !strings.Contains(bar, "Alt+Enter") {
		t.Errorf("both keys must be advertised, got:\n%s", bar)
	}
}

// TestFastSubmit_PlainEnterUnchanged guards the distinction: Enter still means
// what it meant in each field, and only the submit button submits with it.
func TestFastSubmit_PlainEnterUnchanged(t *testing.T) {
	initStyles()
	initFormStyles()
	f := buildRemoteForm()
	f.fieldByName(fieldKeyTarget).SetValue("example.com:443")
	f.setFocus(0)

	if submitted, _ := f.update(tea.KeyMsg{Type: tea.KeyEnter}); submitted {
		t.Error("plain Enter in a text field must not submit; that is what F2 is for")
	}
}
