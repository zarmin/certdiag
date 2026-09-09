package tableformat

import "github.com/jedib0t/go-pretty/v6/text"

type BoxChars struct {
	TopLeft     string
	TopRight    string
	BottomLeft  string
	BottomRight string
	LeftEdge    string
	RightEdge   string
	TopEdge     string
	BottomEdge  string
	Cross       string
	Horizontal  string
	Vertical    string
}

var DefaultBoxChars = BoxChars{
	TopLeft:     "┌",
	TopRight:    "┐",
	BottomLeft:  "└",
	BottomRight: "┘",
	LeftEdge:    "├",
	RightEdge:   "┤",
	TopEdge:     "┬",
	BottomEdge:  "┴",
	Cross:       "┼",
	Horizontal:  "─",
	Vertical:    "│",
}

var (
	Bold      = text.Bold
	Italic    = text.Italic
	Red       = text.FgRed
	Green     = text.FgGreen
	Yellow    = text.FgYellow
	Blue      = text.FgBlue
	Magenta   = text.FgMagenta
	Cyan      = text.FgCyan
	White     = text.FgWhite
	BgRed     = text.BgRed
	BgGreen   = text.BgGreen
	BgYellow  = text.BgYellow
	BgBlue    = text.BgBlue
	BgMagenta = text.BgMagenta
	BgCyan    = text.BgCyan
	BgWhite   = text.BgWhite
)
