package filepicker

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// simpleInput is a minimal single-line text input that handles key events
// from bubbletea without any clipboard dependency. The terminal handles
// paste natively by injecting key events into the program.
type simpleInput struct {
	value       []rune
	cursor      int
	width       int
	placeholder string
	focused     bool
	charLimit   int
}

func newSimpleInput() simpleInput {
	return simpleInput{charLimit: 512}
}

func (ti *simpleInput) SetValue(s string) {
	ti.value = []rune(s)
	ti.cursor = len(ti.value)
}

func (ti simpleInput) Value() string {
	return string(ti.value)
}

func (ti *simpleInput) Focus() {
	ti.focused = true
}

func (ti *simpleInput) Blur() {
	ti.focused = false
}

func (ti *simpleInput) CursorEnd() {
	ti.cursor = len(ti.value)
}

func (ti simpleInput) Update(msg tea.KeyMsg) (simpleInput, tea.Cmd) {
	switch msg.String() {
	case "left":
		if ti.cursor > 0 {
			ti.cursor--
		}
	case "right":
		if ti.cursor < len(ti.value) {
			ti.cursor++
		}
	case "home", "ctrl+a":
		ti.cursor = 0
	case "end", "ctrl+e":
		ti.cursor = len(ti.value)
	case "backspace", "ctrl+h":
		if ti.cursor > 0 {
			ti.value = append(ti.value[:ti.cursor-1], ti.value[ti.cursor:]...)
			ti.cursor--
		}
	case "delete":
		if ti.cursor < len(ti.value) {
			ti.value = append(ti.value[:ti.cursor], ti.value[ti.cursor+1:]...)
		}
	case "ctrl+k":
		// Kill to end of line
		ti.value = ti.value[:ti.cursor]
	case "ctrl+u":
		// Kill to beginning of line
		ti.value = ti.value[ti.cursor:]
		ti.cursor = 0
	default:
		if len(msg.Runes) == 1 {
			if ti.charLimit <= 0 || len(ti.value) < ti.charLimit {
				ti.value = append(ti.value[:ti.cursor], append([]rune{msg.Runes[0]}, ti.value[ti.cursor:]...)...)
				ti.cursor++
			}
		}
	}
	return ti, nil
}

func (ti simpleInput) View() string {
	w := ti.width
	if w <= 0 {
		w = 20
	}

	val := string(ti.value)
	cur := ti.cursor

	// Compute a visible window of width w around the cursor
	runes := []rune(val)
	n := len(runes)

	// Determine window start so cursor is visible
	start := 0
	if cur >= w {
		start = cur - w + 1
	}
	end := start + w
	if end > n {
		end = n
	}

	var result string
	for i := start; i < end; i++ {
		ch := string(runes[i])
		if i == cur && ti.focused {
			result += lipgloss.NewStyle().Reverse(true).Render(ch)
		} else {
			result += ch
		}
	}
	// Draw cursor at end if at end of string and focused
	if cur == n && ti.focused {
		result += lipgloss.NewStyle().Reverse(true).Render(" ")
	}

	// Pad to width
	visible := lipgloss.Width(result)
	if visible < w {
		result += lipgloss.NewStyle().Render(padToWidth("", w-visible))
	}

	if !ti.focused && val == "" && ti.placeholder != "" {
		return styleGrey.Render(padToWidth(ti.placeholder, w))
	}

	return result
}
