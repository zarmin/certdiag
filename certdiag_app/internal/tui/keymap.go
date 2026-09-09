package tui

import tea "github.com/charmbracelet/bubbletea"

func isKeyQuit(msg tea.KeyMsg) bool {
	s := msg.String()
	return s == "ctrl+c" || s == "q"
}

// isKeyCtrlC matches only ctrl+c. Handlers that own a focused text input must
// use this (not isKeyQuit) so a literal 'q' can be typed into the field.
func isKeyCtrlC(msg tea.KeyMsg) bool {
	return msg.String() == "ctrl+c"
}

func isKeyUp(msg tea.KeyMsg) bool {
	return msg.String() == "up"
}

func isKeyDown(msg tea.KeyMsg) bool {
	return msg.String() == "down"
}

func isKeyLeft(msg tea.KeyMsg) bool {
	return msg.String() == "left"
}

func isKeyRight(msg tea.KeyMsg) bool {
	return msg.String() == "right"
}

func isKeyEnter(msg tea.KeyMsg) bool {
	return msg.String() == "enter"
}

func isKeyEsc(msg tea.KeyMsg) bool {
	return msg.String() == "esc"
}

// isKeyClose matches the keys that leave a pane or overlay: Esc, and q, which
// quits only from a tree (keypolicy.go). Handlers with a focused text input
// must not use it.
func isKeyClose(msg tea.KeyMsg) bool {
	s := msg.String()
	return s == "esc" || s == "q"
}

// isKeyHelp opens the key overlay for the current view.
func isKeyHelp(msg tea.KeyMsg) bool {
	return msg.String() == "?"
}

func isKeySearch(msg tea.KeyMsg) bool {
	return msg.String() == "/"
}

func isKeyPgUp(msg tea.KeyMsg) bool {
	return msg.String() == "pgup"
}

func isKeyPgDown(msg tea.KeyMsg) bool {
	return msg.String() == "pgdown"
}

func isKeyHome(msg tea.KeyMsg) bool {
	return msg.String() == "home"
}

func isKeyEnd(msg tea.KeyMsg) bool {
	return msg.String() == "end"
}

func isKeyTab(msg tea.KeyMsg) bool {
	return msg.String() == "tab"
}

func isKeyHistoryBack(msg tea.KeyMsg) bool {
	s := msg.String()
	return s == "alt+left" || s == "["
}

func isKeyHistoryForward(msg tea.KeyMsg) bool {
	s := msg.String()
	return s == "alt+right" || s == "]"
}

func isKeyCopy(msg tea.KeyMsg) bool {
	return msg.String() == "c"
}

func isKeyNew(msg tea.KeyMsg) bool {
	return msg.String() == "n"
}

func isKeyAction(msg tea.KeyMsg) bool {
	return msg.String() == "a"
}

func isKeyMultiSelect(msg tea.KeyMsg) bool {
	return msg.String() == "m"
}

func isKeySpace(msg tea.KeyMsg) bool {
	return msg.String() == " "
}

func isKeyDelete(msg tea.KeyMsg) bool {
	return msg.String() == "ctrl+d"
}

func isKeyColumnEditor(msg tea.KeyMsg) bool {
	return msg.String() == "C"
}

func isKeySave(msg tea.KeyMsg) bool {
	return msg.String() == "s"
}

func isKeyOptions(msg tea.KeyMsg) bool {
	return msg.String() == "O"
}

func isKeyWordWrap(msg tea.KeyMsg) bool {
	return msg.String() == "w"
}

func isKeyRescan(msg tea.KeyMsg) bool {
	return msg.String() == "r"
}

func isKeyShell(msg tea.KeyMsg) bool {
	return msg.String() == "!"
}

func isKeyGrouping(msg tea.KeyMsg) bool {
	return msg.String() == "g"
}

func isKeyExport(msg tea.KeyMsg) bool {
	return msg.String() == "E"
}

func isKeyVerify(msg tea.KeyMsg) bool {
	return msg.String() == "V"
}

func isKeyExpandAll(msg tea.KeyMsg) bool {
	return msg.String() == "z"
}

func isKeyFetchAIA(msg tea.KeyMsg) bool {
	return msg.String() == "A"
}

// isKeyFastSubmit reports the "submit from anywhere" gesture, so a form with
// one field that matters does not have to be tabbed to the end.
//
// F2 and Alt+Enter, deliberately not Ctrl+Enter: terminals send plain CR for
// Ctrl+Enter and bubbletea aliases KeyEnter to KeyCtrlM, so the two are
// indistinguishable here. Advertising it would promise a key that cannot work.
func isKeyFastSubmit(msg tea.KeyMsg) bool {
	if msg.Type == tea.KeyF2 {
		return true
	}
	return msg.Type == tea.KeyEnter && msg.Alt
}
