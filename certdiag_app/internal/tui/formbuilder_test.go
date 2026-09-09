package tui

import (
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/pkg/filepicker"
)

func TestSetExtensionWarning(t *testing.T) {
	form := newFormModel("Test")
	fp1 := newFilePickerField("out1", "Output 1", filepicker.TypeSaveFile, "/tmp", ".pem", []string{".pem"})
	fp2 := newFilePickerField("out2", "Output 2", filepicker.TypeSaveFile, "/tmp", ".crt", []string{".crt"})
	form.addField("out1", fp1)
	form.addField("out2", fp2)

	form.setExtensionWarning("test warning")

	if fp1.extensionWarning != "test warning" {
		t.Errorf("fp1.extensionWarning=%q, want %q", fp1.extensionWarning, "test warning")
	}
	if fp2.extensionWarning != "test warning" {
		t.Errorf("fp2.extensionWarning=%q, want %q", fp2.extensionWarning, "test warning")
	}
}

func TestSetExtensionWarning_SkipsNonFilePicker(t *testing.T) {
	form := newFormModel("Test")
	fp := newFilePickerField("out", "Output", filepicker.TypeSaveFile, "/tmp", ".pem", []string{".pem"})
	form.addField("out", fp)
	// Add a non-filepicker field (radio group)
	rg := newRadioGroupField("Format", []string{"PEM", "DER"}, 0)
	form.addField("format", rg)

	form.setExtensionWarning("test warning")

	if fp.extensionWarning != "test warning" {
		t.Errorf("fp.extensionWarning=%q, want %q", fp.extensionWarning, "test warning")
	}
}
