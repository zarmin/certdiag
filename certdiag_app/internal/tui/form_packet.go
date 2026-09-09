package tui

import "github.com/zarmin/certdiag/certdiag_app/pkg/filepicker"

func buildProxyForm(listen, target string, aggressive bool) *formModel {
	f := newFormModel("Start Proxy")

	listenIdx := f.addField(fieldKeyProxyListen, newTextInputField("Listen", ":PORT or addr:PORT", true, nil))
	targetIdx := f.addField(fieldKeyProxyTarget, newTextInputField("Target", "host:port", true, nil))
	aggrIdx := f.addField(fieldKeyProxyAggressive, newCheckboxField("Aggressive (STARTTLS)", aggressive))
	submitIdx := f.addField(fieldKeySubmit, newSubmitButtonField("Start"))

	f.addSection("Proxy", []int{listenIdx, targetIdx, aggrIdx})
	f.addSection("", []int{submitIdx})

	if listen != "" {
		f.fieldByName(fieldKeyProxyListen).SetValue(listen)
	}
	if target != "" {
		f.fieldByName(fieldKeyProxyTarget).SetValue(target)
	}

	f.evaluateVisibility()
	f.initFocus()
	return f
}

func buildPcapForm(scanPath string, aggressive bool) *formModel {
	f := newFormModel("Open PCAP")

	fp := newFilePickerField("pcap_file", "File", filepicker.TypeOpenFile, scanPath, "", nil)
	fp.SetFileFilter([]string{".pcap", ".pcapng", ".pcap.gz", ".dump", ".dmp"})
	fileIdx := f.addField(fieldKeyPcapFile, fp)
	aggrIdx := f.addField(fieldKeyPcapAggressive, newCheckboxField("Aggressive (STARTTLS)", aggressive))
	submitIdx := f.addField(fieldKeySubmit, newSubmitButtonField("Analyze"))

	f.addSection("PCAP", []int{fileIdx, aggrIdx})
	f.addSection("", []int{submitIdx})

	f.evaluateVisibility()
	f.initFocus()
	return f
}
