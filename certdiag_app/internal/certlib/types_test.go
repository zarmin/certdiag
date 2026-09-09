package certlib

import "testing"

func TestIsBundleFormat(t *testing.T) {
	tests := []struct {
		format FileFormat
		want   bool
	}{
		{FormatPKCS12, true},
		{FormatJKS, true},
		{FormatPKCS7, true},
		{FormatPEM, false},
		{FormatDER, false},
	}
	for _, tt := range tests {
		t.Run(string(tt.format), func(t *testing.T) {
			if got := tt.format.IsBundleFormat(); got != tt.want {
				t.Errorf("FileFormat(%q).IsBundleFormat() = %v, want %v", tt.format, got, tt.want)
			}
		})
	}
}
