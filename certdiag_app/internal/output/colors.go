package output

import (
	"time"

	"github.com/fatih/color"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

var ColorsEnabled = true

var (
	ExpiredColor    *color.Color
	ExpiringUrgent  *color.Color
	ExpiringWarning *color.Color
	ExpiringOK      *color.Color
)

var (
	FilenameKey       *color.Color
	FilenameKeyBundle *color.Color
	FilenameCert      *color.Color
	FilenameCSR       *color.Color
	FilenamePubKey    *color.Color
)

var (
	ErrorColor      *color.Color
	WarningColor    *color.Color
	SuccessColor    *color.Color
	CABadgeColor    *color.Color
	SelfSignedColor *color.Color
)

var (
	BoldAttr       *color.Color
	DimAttr        *color.Color
	HeaderStyle    *color.Color
	HighlightColor *color.Color
)

func init() {
	InitColors()
}

func InitColors() {
	ColorsEnabled = color.NoColor == false

	ExpiredColor = color.New(color.FgRed, color.Bold)
	ExpiringUrgent = color.New(color.FgHiRed)
	ExpiringWarning = color.New(color.FgYellow)
	ExpiringOK = color.New(color.FgGreen)

	FilenameKey = color.New(color.FgCyan)
	FilenameKeyBundle = color.New(color.FgBlue)
	FilenameCert = color.New()
	FilenameCSR = color.New(color.FgMagenta)
	FilenamePubKey = color.New(color.FgBlue)

	ErrorColor = color.New(color.FgRed, color.Bold)
	WarningColor = color.New(color.FgYellow)
	SuccessColor = color.New(color.FgGreen)
	CABadgeColor = color.New(color.FgGreen, color.Bold)
	SelfSignedColor = color.New(color.FgYellow)

	BoldAttr = color.New(color.Bold)
	DimAttr = color.New(color.Faint)
	HeaderStyle = color.New(color.Bold, color.Underline)
	HighlightColor = color.New(color.BgYellow, color.FgBlack, color.Bold)
}

func ColorizeExpiry(t time.Time) string {
	if !ColorsEnabled {
		return t.Format("2006-01-02")
	}

	now := time.Now()
	daysUntil := int(time.Until(t).Hours() / 24)
	dateStr := t.Format("2006-01-02")

	if t.Before(now) {
		return ExpiredColor.Sprint(dateStr)
	}

	if daysUntil <= certlib.DefaultExpiryCriticalDays {
		return ExpiringUrgent.Sprint(dateStr)
	}

	if daysUntil <= certlib.DefaultExpiryWarnDays {
		return ExpiringWarning.Sprint(dateStr)
	}

	if daysUntil <= certlib.DefaultExpiryNoticeZone {
		return ExpiringOK.Sprint(dateStr)
	}

	return dateStr
}

func ColorizeNotBefore(t time.Time) string {
	if !ColorsEnabled {
		return t.Format("2006-01-02")
	}

	now := time.Now()
	if t.After(now) {
		return ExpiredColor.Sprint(t.Format("2006-01-02"))
	}

	return t.Format("2006-01-02")
}

func ColorizeFilename(filename string, hasKey, hasCert, hasCSR bool) string {
	if !ColorsEnabled {
		return filename
	}

	if hasKey && hasCert {
		return FilenameKeyBundle.Sprint(filename)
	}
	if hasKey {
		return FilenameKey.Sprint(filename)
	}
	if hasCSR {
		return FilenameCSR.Sprint(filename)
	}

	return filename
}

func ColorizeError(msg string) string {
	if !ColorsEnabled {
		return msg
	}
	return ErrorColor.Sprint(msg)
}

func ColorizeWarning(msg string) string {
	if !ColorsEnabled {
		return msg
	}
	return WarningColor.Sprint(msg)
}

func ColorizeIssuer(issuer string, isSelfSigned bool) string {
	if !ColorsEnabled {
		return issuer
	}

	if isSelfSigned {
		return SelfSignedColor.Sprint(issuer)
	}

	return issuer
}

func ColorizeCA(isCA bool) string {
	if !ColorsEnabled || !isCA {
		return ""
	}
	return CABadgeColor.Sprint("CA: true")
}

// ColorizeTrust colours a trust verdict: denial is an error, an untrusted or
// expired chain is a warning, and anchor or trusted reads as success.
func ColorizeTrust(display string) string {
	if !ColorsEnabled || display == "" {
		return display
	}
	switch truststore.ParseTrustVerdict(display) {
	case truststore.VerdictDenied:
		return ErrorColor.Sprint(display)
	case truststore.VerdictUntrusted, truststore.VerdictExpired:
		return WarningColor.Sprint(display)
	case truststore.VerdictAnchor, truststore.VerdictTrusted:
		return SuccessColor.Sprint(display)
	}
	return display
}
