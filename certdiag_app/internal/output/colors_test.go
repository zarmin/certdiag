package output

import (
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func enableColors(t *testing.T) {
	t.Helper()
	oldEnabled := ColorsEnabled
	oldNoColor := color.NoColor
	ColorsEnabled = true
	color.NoColor = false
	t.Cleanup(func() {
		ColorsEnabled = oldEnabled
		color.NoColor = oldNoColor
	})
}

func TestColorizeExpiry_NoColor(t *testing.T) {
	disableColors(t)

	tests := []struct {
		name string
		t    time.Time
	}{
		{"expired", time.Now().Add(-24 * time.Hour)},
		{"critical", time.Now().Add(time.Duration(certlib.DefaultExpiryCriticalDays-1) * 24 * time.Hour)},
		{"warning", time.Now().Add(time.Duration(certlib.DefaultExpiryWarnDays-1) * 24 * time.Hour)},
		{"notice", time.Now().Add(time.Duration(certlib.DefaultExpiryNoticeZone-1) * 24 * time.Hour)},
		{"far future", time.Now().Add(365 * 24 * time.Hour)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ColorizeExpiry(tt.t)
			want := tt.t.Format("2006-01-02")
			if got != want {
				t.Errorf("ColorizeExpiry() = %q, want %q", got, want)
			}
		})
	}
}

func TestColorizeExpiry_WithColor(t *testing.T) {
	enableColors(t)

	t.Run("expired has ANSI", func(t *testing.T) {
		got := ColorizeExpiry(time.Now().Add(-24 * time.Hour))
		if !strings.Contains(got, "\x1b[") {
			t.Error("expired date should contain ANSI escape codes")
		}
	})

	t.Run("far future no ANSI", func(t *testing.T) {
		got := ColorizeExpiry(time.Now().Add(365 * 24 * time.Hour))
		if strings.Contains(got, "\x1b[") {
			t.Error("far future date should not contain ANSI escape codes")
		}
	})
}

func TestColorizeNotBefore_NoColor(t *testing.T) {
	disableColors(t)

	future := time.Now().Add(24 * time.Hour)
	past := time.Now().Add(-24 * time.Hour)

	t.Run("future", func(t *testing.T) {
		got := ColorizeNotBefore(future)
		if got != future.Format("2006-01-02") {
			t.Errorf("got %q, want plain date", got)
		}
	})

	t.Run("past", func(t *testing.T) {
		got := ColorizeNotBefore(past)
		if got != past.Format("2006-01-02") {
			t.Errorf("got %q, want plain date", got)
		}
	})
}

func TestColorizeNotBefore_WithColor(t *testing.T) {
	enableColors(t)

	t.Run("future has ANSI", func(t *testing.T) {
		got := ColorizeNotBefore(time.Now().Add(24 * time.Hour))
		if !strings.Contains(got, "\x1b[") {
			t.Error("future not-before should contain ANSI escape codes")
		}
	})

	t.Run("past no ANSI", func(t *testing.T) {
		got := ColorizeNotBefore(time.Now().Add(-24 * time.Hour))
		if strings.Contains(got, "\x1b[") {
			t.Error("past not-before should not contain ANSI escape codes")
		}
	})
}

func TestColorizeFilename_NoColor(t *testing.T) {
	disableColors(t)

	tests := []struct {
		name    string
		hasKey  bool
		hasCert bool
		hasCSR  bool
	}{
		{"key+cert", true, true, false},
		{"key only", true, false, false},
		{"csr only", false, false, true},
		{"none", false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ColorizeFilename("test.pem", tt.hasKey, tt.hasCert, tt.hasCSR)
			if got != "test.pem" {
				t.Errorf("got %q, want %q", got, "test.pem")
			}
		})
	}
}

func TestColorizeError_NoColor(t *testing.T) {
	disableColors(t)
	got := ColorizeError("something failed")
	if got != "something failed" {
		t.Errorf("got %q, want unchanged", got)
	}
}

func TestColorizeWarning_NoColor(t *testing.T) {
	disableColors(t)
	got := ColorizeWarning("be careful")
	if got != "be careful" {
		t.Errorf("got %q, want unchanged", got)
	}
}

func TestColorizeIssuer_NoColor(t *testing.T) {
	disableColors(t)

	t.Run("self-signed", func(t *testing.T) {
		got := ColorizeIssuer("Self-signed", true)
		if got != "Self-signed" {
			t.Errorf("got %q, want %q", got, "Self-signed")
		}
	})

	t.Run("not self-signed", func(t *testing.T) {
		got := ColorizeIssuer("Some CA", false)
		if got != "Some CA" {
			t.Errorf("got %q, want %q", got, "Some CA")
		}
	})
}

func TestColorizeCA_NoColor(t *testing.T) {
	disableColors(t)

	t.Run("isCA true", func(t *testing.T) {
		got := ColorizeCA(true)
		if got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})

	t.Run("isCA false", func(t *testing.T) {
		got := ColorizeCA(false)
		if got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})
}

func TestColorizeCA_WithColor(t *testing.T) {
	enableColors(t)

	t.Run("isCA true", func(t *testing.T) {
		got := ColorizeCA(true)
		if !strings.Contains(got, "CA: true") {
			t.Errorf("got %q, want to contain 'CA: true'", got)
		}
	})

	t.Run("isCA false", func(t *testing.T) {
		got := ColorizeCA(false)
		if got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})
}

func TestColorizeSeverity_NoColor(t *testing.T) {
	disableColors(t)

	tests := []struct {
		sev  certlib.CheckSeverity
		want string
	}{
		{certlib.SeverityCritical, "CRITICAL"},
		{certlib.SeverityWarning, "WARNING"},
		{certlib.SeverityInfo, "INFO"},
	}
	for _, tt := range tests {
		t.Run(string(tt.sev), func(t *testing.T) {
			got := ColorizeSeverity(tt.sev)
			if got != tt.want {
				t.Errorf("ColorizeSeverity() = %q, want %q", got, tt.want)
			}
		})
	}
}
