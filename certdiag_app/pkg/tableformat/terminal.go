package tableformat

import (
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"
)

// detectTerminalWidth asks the terminal; when stdout is not one (a pipe, a
// CI log) it honours COLUMNS, the way pagers and shells do, before falling
// back to 80.
func detectTerminalWidth() int {
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err == nil && width > 0 {
		return width
	}
	if env, err := strconv.Atoi(strings.TrimSpace(os.Getenv("COLUMNS"))); err == nil && env > 0 {
		return env
	}
	return 80
}
