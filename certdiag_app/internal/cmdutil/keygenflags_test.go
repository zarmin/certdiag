package cmdutil

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func TestKeyGenFlagsApplyChanged(t *testing.T) {
	tests := []struct {
		name string
		args []string
		base certlib.KeyGenOptions
		want certlib.KeyGenOptions
	}{
		{
			name: "no flags keeps base",
			args: nil,
			base: certlib.KeyGenOptions{Algorithm: "ecdsa", Curve: "p256"},
			want: certlib.KeyGenOptions{Algorithm: "ecdsa", Curve: "p256"},
		},
		{
			name: "algorithm and size override, algorithm lowercased",
			args: []string{"--algorithm", "RSA", "--key-size", "4096"},
			base: certlib.KeyGenOptions{Algorithm: "ecdsa", Curve: "p256"},
			want: certlib.KeyGenOptions{Algorithm: "rsa", KeySize: 4096, Curve: "p256"},
		},
		{
			name: "shorthand and curve override, curve lowercased",
			args: []string{"-a", "ECDSA", "--curve", "P384"},
			base: certlib.KeyGenOptions{},
			want: certlib.KeyGenOptions{Algorithm: "ecdsa", Curve: "p384"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var f KeyGenFlags
			cmd := &cobra.Command{Use: "x", Run: func(*cobra.Command, []string) {}}
			f.Register(cmd, "")
			cmd.SetArgs(tt.args)
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			got := tt.base
			f.ApplyChanged(cmd, &got)
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}
