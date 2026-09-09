package cmd

import "testing"

func TestResolveExpiryThreshold(t *testing.T) {
	cases := []struct {
		name   string
		flag   int
		config int
		want   int
	}{
		{"flag unset, config set", 0, 45, 45},
		{"flag set wins over config", 30, 45, 30},
		{"flag unset, config unset", 0, 0, 0},
		{"explicit zero stays zero when no config", 0, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := resolveExpiryThreshold(c.flag, c.config); got != c.want {
				t.Fatalf("resolveExpiryThreshold(%d, %d) = %d, want %d", c.flag, c.config, got, c.want)
			}
		})
	}
}

func TestResolveExpiryThresholdNoStateLeak(t *testing.T) {
	origWarn := checkExpiryWarn
	origCritical := checkExpiryCritical

	// Run 1: config A supplies the values.
	warn1 := resolveExpiryThreshold(checkExpiryWarn, 60)
	crit1 := resolveExpiryThreshold(checkExpiryCritical, 20)
	if warn1 != 60 || crit1 != 20 {
		t.Fatalf("run 1 resolved to (%d, %d), want (60, 20)", warn1, crit1)
	}

	// The package flag vars must be untouched so run 2 starts clean.
	if checkExpiryWarn != origWarn || checkExpiryCritical != origCritical {
		t.Fatalf("package flag vars mutated: warn %d->%d, critical %d->%d",
			origWarn, checkExpiryWarn, origCritical, checkExpiryCritical)
	}

	// Run 2: config B differs; run 1's value must not leak in.
	warn2 := resolveExpiryThreshold(checkExpiryWarn, 90)
	crit2 := resolveExpiryThreshold(checkExpiryCritical, 5)
	if warn2 != 90 || crit2 != 5 {
		t.Fatalf("run 2 resolved to (%d, %d), want (90, 5) - run 1 leaked", warn2, crit2)
	}
}
