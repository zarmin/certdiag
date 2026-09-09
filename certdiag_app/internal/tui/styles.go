package tui

import (
	"os"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

var noColor = os.Getenv("NO_COLOR") != ""

// Color palette
var (
	colorAccent    = lipgloss.Color("75")  // blue -- focus, buttons, headers
	colorDimGrey   = lipgloss.Color("243") // hint text, separators, info bar
	colorLightGrey = lipgloss.Color("248") // labels, unfocused buttons
	colorDarkGrey  = lipgloss.Color("240") // unfocused borders, separators
	colorWhite     = lipgloss.Color("252") // selectable rows
	colorRed       = lipgloss.Color("196") // errors, critical severity, expired
	colorYellow    = lipgloss.Color("220") // warnings
	colorOrange    = lipgloss.Color("214") // expiry warning (< 90 days)
	colorGreen     = lipgloss.Color("34")  // valid, enabled
	colorTeal      = lipgloss.Color("37")  // notices
	colorLocked    = lipgloss.Color("208") // locked/encrypted items
	colorModal     = lipgloss.Color("63")  // detail modal border
	colorBlack     = lipgloss.Color("0")   // button text foreground
	colorDisabled  = lipgloss.Color("241") // disabled catalog items
)

var (
	styleHeader          lipgloss.Style
	styleNormalRow       lipgloss.Style
	styleCursorRow       lipgloss.Style
	styleBundleRow       lipgloss.Style
	styleChildRow        lipgloss.Style
	styleDimRow          lipgloss.Style
	styleLockedRow       lipgloss.Style
	styleInfoBar         lipgloss.Style
	styleModalTitle      lipgloss.Style
	styleLabel           lipgloss.Style
	styleValue           lipgloss.Style
	styleError           lipgloss.Style
	styleSelectableRow   lipgloss.Style
	styleFocusedBorder   lipgloss.Style
	styleUnfocusedBorder lipgloss.Style
	styleSeparator       lipgloss.Style
	styleWarningLine     lipgloss.Style
	styleCriticalLine    lipgloss.Style
	stylePopupBtn        lipgloss.Style
	stylePopupError      lipgloss.Style
	stylePopupNotice     lipgloss.Style
	stylePopupConfirm    lipgloss.Style
)

func initStyles() {
	if noColor {
		styleHeader = lipgloss.NewStyle().Bold(true)
		styleNormalRow = lipgloss.NewStyle()
		styleCursorRow = lipgloss.NewStyle().Reverse(true)
		styleBundleRow = lipgloss.NewStyle().Bold(true)
		styleChildRow = lipgloss.NewStyle()
		styleDimRow = lipgloss.NewStyle().Faint(true)
		styleLockedRow = lipgloss.NewStyle().Faint(true)
		styleInfoBar = lipgloss.NewStyle()
		styleModalTitle = lipgloss.NewStyle().Bold(true)
		styleLabel = lipgloss.NewStyle().Bold(true)
		styleValue = lipgloss.NewStyle()
		styleError = lipgloss.NewStyle().Bold(true)
		styleSelectableRow = lipgloss.NewStyle()
		styleFocusedBorder = lipgloss.NewStyle()
		styleUnfocusedBorder = lipgloss.NewStyle()
		styleSeparator = lipgloss.NewStyle()
		styleWarningLine = lipgloss.NewStyle().Bold(true)
		styleCriticalLine = lipgloss.NewStyle().Bold(true)
		stylePopupBtn = lipgloss.NewStyle().Reverse(true).Bold(true)
		stylePopupError = lipgloss.NewStyle().Bold(true)
		stylePopupNotice = lipgloss.NewStyle().Bold(true)
		stylePopupConfirm = lipgloss.NewStyle().Bold(true)
	} else {
		styleHeader = lipgloss.NewStyle().Bold(true).Foreground(colorDimGrey)
		styleNormalRow = lipgloss.NewStyle()
		styleCursorRow = lipgloss.NewStyle().Reverse(true)
		styleBundleRow = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
		styleChildRow = lipgloss.NewStyle()
		styleDimRow = lipgloss.NewStyle().Faint(true)
		styleLockedRow = lipgloss.NewStyle().Foreground(colorLocked)
		styleInfoBar = lipgloss.NewStyle().Foreground(colorDimGrey)
		styleModalTitle = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
		styleLabel = lipgloss.NewStyle().Bold(true).Foreground(colorLightGrey)
		styleValue = lipgloss.NewStyle()
		styleError = lipgloss.NewStyle().Bold(true).Foreground(colorRed)
		styleSelectableRow = lipgloss.NewStyle().Foreground(colorWhite)
		styleFocusedBorder = lipgloss.NewStyle().Foreground(colorAccent)
		styleUnfocusedBorder = lipgloss.NewStyle().Foreground(colorDarkGrey)
		styleSeparator = lipgloss.NewStyle().Foreground(colorDarkGrey)
		styleWarningLine = lipgloss.NewStyle().Foreground(colorYellow)
		styleCriticalLine = lipgloss.NewStyle().Bold(true).Foreground(colorRed)
		stylePopupBtn = lipgloss.NewStyle().Background(colorAccent).Foreground(colorBlack).Bold(true)
		stylePopupError = lipgloss.NewStyle().Bold(true).Foreground(colorRed)
		stylePopupNotice = lipgloss.NewStyle().Bold(true).Foreground(colorTeal)
		stylePopupConfirm = lipgloss.NewStyle().Bold(true).Foreground(colorRed)
	}
}

func expiryStyle(t time.Time) lipgloss.Style {
	if noColor {
		return lipgloss.NewStyle()
	}
	now := time.Now()
	days := t.Sub(now).Hours() / 24
	switch {
	case days < 0 || days < float64(certlib.DefaultExpiryWarnDays):
		return lipgloss.NewStyle().Foreground(colorRed)
	case days < float64(certlib.DefaultExpiryNoticeZone):
		return lipgloss.NewStyle().Foreground(colorOrange)
	default:
		return lipgloss.NewStyle().Foreground(colorGreen)
	}
}
