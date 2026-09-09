package cmd

import (
	"testing"

	"github.com/spf13/cobra"
)

// TestDetailsFlag_Count pins the -d / -dd contract on every command that has it.
// A counted flag is what makes an extended level possible; the price is that
// --details=true no longer parses, which is why that case is asserted too.
func TestDetailsFlag_Count(t *testing.T) {
	targets := []struct {
		name string
		cmd  *cobra.Command
		read *int
	}{
		{"root", rootCmd, &details},
		{"list", listCmd, &details},
		{"remote fetch", remoteFetchCmd, &remoteDetails},
		{"diff", diffCmd, &diffDetails},
	}

	cases := []struct {
		args []string
		want int
	}{
		{[]string{"-d"}, 1},
		{[]string{"-dd"}, 2},
		{[]string{"-d", "-d"}, 2},
		{[]string{"--details"}, 1},
		{[]string{"--details", "--details"}, 2},
		{[]string{"--details=2"}, 2},
	}

	for _, target := range targets {
		flags := target.cmd.Flags()
		if flags.Lookup("details") == nil {
			t.Errorf("%s: no --details flag", target.name)
			continue
		}
		for _, tc := range cases {
			*target.read = 0
			if err := flags.Parse(tc.args); err != nil {
				t.Errorf("%s %v: %v", target.name, tc.args, err)
				continue
			}
			if *target.read != tc.want {
				t.Errorf("%s %v: want level %d, got %d", target.name, tc.args, tc.want, *target.read)
			}
		}

		*target.read = 0
		if err := flags.Parse([]string{"--details=true"}); err == nil {
			t.Errorf("%s: --details=true must be rejected now that -d counts", target.name)
		}
	}
}

// TestDetailLevel_InsecureImpliesDetails: --insecure-details on its own is still
// a request for the detail block.
func TestDetailLevel_InsecureImpliesDetails(t *testing.T) {
	cases := []struct {
		count    int
		insecure bool
		want     int
	}{
		{0, false, 0},
		{0, true, 1},
		{1, false, 1},
		{2, true, 2},
	}
	for _, tc := range cases {
		if got := detailLevel(tc.count, tc.insecure); got != tc.want {
			t.Errorf("detailLevel(%d, %v) = %d, want %d", tc.count, tc.insecure, got, tc.want)
		}
	}
}
