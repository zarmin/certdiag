package cmdutil

import (
	"testing"

	"github.com/spf13/cobra"
)

func makeCmd(flags map[string]string) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().Int("key-size", 0, "")
	cmd.Flags().String("curve", "", "")
	for k, v := range flags {
		_ = cmd.Flags().Set(k, v)
	}
	return cmd
}

func TestValidateKeyParams(t *testing.T) {
	tests := []struct {
		name    string
		algo    string
		keySize int
		curve   string
		flags   map[string]string
		wantErr bool
	}{
		{"rsa_2048", "rsa", 2048, "", nil, false},
		{"rsa_3072", "rsa", 3072, "", nil, false},
		{"rsa_4096", "rsa", 4096, "", nil, false},
		{"rsa_bad_size", "rsa", 1024, "", nil, true},
		{"rsa_zero_size", "rsa", 0, "", nil, true},
		{"ecdsa_p256", "ecdsa", 0, "p256", nil, false},
		{"ecdsa_p384", "ecdsa", 0, "p384", nil, false},
		{"ecdsa_p521", "ecdsa", 0, "p521", nil, false},
		{"ecdsa_bad_curve", "ecdsa", 0, "secp256k1", nil, true},
		{"ecdsa_empty_curve", "ecdsa", 0, "", nil, true},
		{"ed25519_valid", "ed25519", 0, "", nil, false},
		{"invalid_algo", "blowfish", 0, "", nil, true},
		{"empty_algo", "", 0, "", nil, true},
		{"case_insensitive_RSA", "RSA", 2048, "", nil, false},
		{"case_insensitive_ECDSA", "ECDSA", 0, "P256", nil, false},
		{"case_insensitive_ED25519", "Ed25519", 0, "", nil, false},
		{
			"ed25519_with_keysize_changed", "ed25519", 0, "",
			map[string]string{"key-size": "256"}, true,
		},
		{
			"ed25519_with_curve_changed", "ed25519", 0, "",
			map[string]string{"curve": "p256"}, true,
		},
		{
			"rsa_with_curve_changed", "rsa", 2048, "",
			map[string]string{"curve": "p256"}, true,
		},
		{
			"ecdsa_with_keysize_changed", "ecdsa", 0, "p256",
			map[string]string{"key-size": "2048"}, true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := makeCmd(tt.flags)
			err := ValidateKeyParams(cmd, tt.algo, tt.keySize, tt.curve)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateKeyParams(%q, %d, %q) error = %v, wantErr %v",
					tt.algo, tt.keySize, tt.curve, err, tt.wantErr)
			}
		})
	}
}

func TestParseCheckSeverity(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"info", false},
		{"warning", false},
		{"critical", false},
		{"WARNING", false},
		{"bogus", true},
		{"all", true},
		{"", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			_, err := ParseCheckSeverity(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCheckSeverity(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateDisplayFormat(t *testing.T) {
	tests := []struct {
		name    string
		format  string
		valid   []string
		wantErr bool
	}{
		{"human_ok", OutputHuman, []string{OutputHuman, OutputJSON, OutputYAML}, false},
		{"json_ok", OutputJSON, []string{OutputHuman, OutputJSON, OutputYAML}, false},
		{"yaml_ok", OutputYAML, []string{OutputHuman, OutputJSON, OutputYAML}, false},
		{"bogus", "bogus", []string{OutputHuman, OutputJSON, OutputYAML}, true},
		{"case_sensitive", "JSON", []string{OutputHuman, OutputJSON, OutputYAML}, true},
		{"store_list_ok", OutputList, []string{OutputList, OutputTable, OutputJSON, OutputYAML}, false},
		{"store_table_ok", OutputTable, []string{OutputList, OutputTable, OutputJSON, OutputYAML}, false},
		{"human_not_valid_for_store", OutputHuman, []string{OutputList, OutputTable, OutputJSON, OutputYAML}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDisplayFormat(tt.format, tt.valid...)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDisplayFormat(%q, %v) error = %v, wantErr %v", tt.format, tt.valid, err, tt.wantErr)
			}
		})
	}
}

func TestValidateExtractType(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"all", false},
		{"certs", false},
		{"keys", false},
		{"foo", true},
		{"", true},
		{"ALL", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			err := ValidateExtractType(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateExtractType(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}
