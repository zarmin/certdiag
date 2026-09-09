package cmd

import (
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/config"
)

func TestResolveFingerprintFormat_Precedence(t *testing.T) {
	orig := fingerprintFormatFlag
	t.Cleanup(func() { fingerprintFormatFlag = orig })

	cfg := &config.ConfigFile{}
	cfg.Defaults.Output.FingerprintFormat = "hex-colon"

	// No flag: the config wins.
	fingerprintFormatFlag = ""
	if got := resolveFingerprintFormat(cfg); got != certlib.FingerprintHexColon {
		t.Errorf("expected the config value, got %q", got)
	}

	// Flag set: it beats the config.
	fingerprintFormatFlag = "base64"
	if got := resolveFingerprintFormat(cfg); got != certlib.FingerprintBase64 {
		t.Errorf("expected the flag to win, got %q", got)
	}

	// No flag and no config: hex.
	fingerprintFormatFlag = ""
	if got := resolveFingerprintFormat(&config.ConfigFile{}); got != certlib.FingerprintHex {
		t.Errorf("expected the hex default, got %q", got)
	}
	if got := resolveFingerprintFormat(nil); got != certlib.FingerprintHex {
		t.Errorf("expected the hex default for a nil config, got %q", got)
	}
}

func TestResolveFingerprintFormat_AcceptsEveryFormat(t *testing.T) {
	orig := fingerprintFormatFlag
	t.Cleanup(func() { fingerprintFormatFlag = orig })

	for _, format := range certlib.FingerprintFormats {
		fingerprintFormatFlag = string(format)
		if got := resolveFingerprintFormat(nil); got != format {
			t.Errorf("flag %q resolved to %q", format, got)
		}
	}

	// Surrounding whitespace and case are tolerated.
	fingerprintFormatFlag = "  HEX-COLON "
	if got := resolveFingerprintFormat(nil); got != certlib.FingerprintHexColon {
		t.Errorf("expected case/space tolerance, got %q", got)
	}
}
