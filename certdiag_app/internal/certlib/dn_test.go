package certlib

import (
	"math/big"
	"testing"
)

func TestParseDN(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantCN  string
		wantO   string
		wantOU  []string
		wantC   string
		wantST  string
		wantL   string
		wantErr bool
	}{
		{
			name:   "SimpleCN",
			input:  "CN=example.com",
			wantCN: "example.com",
		},
		{
			name:   "FullDN",
			input:  "CN=example.com,O=Example Inc,OU=Engineering,C=US,ST=California,L=San Francisco",
			wantCN: "example.com",
			wantO:  "Example Inc",
			wantOU: []string{"Engineering"},
			wantC:  "US",
			wantST: "California",
			wantL:  "San Francisco",
		},
		{
			name:   "Whitespace",
			input:  "CN = foo , O = bar",
			wantCN: "foo",
			wantO:  "bar",
		},
		{
			name:   "EscapedComma",
			input:  `CN=test\,inc,O=Org`,
			wantCN: "test,inc",
			wantO:  "Org",
		},
		{
			name:   "MultipleOU",
			input:  "OU=A,OU=B",
			wantOU: []string{"A", "B"},
		},
		{
			name:    "Error/Empty",
			input:   "",
			wantErr: true,
		},
		{
			name:    "Error/UnknownAttribute",
			input:   "FOO=bar",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			name, err := ParseDN(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tc.wantCN != "" && name.CommonName != tc.wantCN {
				t.Errorf("CN = %q, want %q", name.CommonName, tc.wantCN)
			}
			if tc.wantO != "" {
				if len(name.Organization) == 0 || name.Organization[0] != tc.wantO {
					t.Errorf("O = %v, want [%q]", name.Organization, tc.wantO)
				}
			}
			if tc.wantOU != nil {
				if len(name.OrganizationalUnit) != len(tc.wantOU) {
					t.Errorf("OU count = %d, want %d", len(name.OrganizationalUnit), len(tc.wantOU))
				} else {
					for i, ou := range tc.wantOU {
						if name.OrganizationalUnit[i] != ou {
							t.Errorf("OU[%d] = %q, want %q", i, name.OrganizationalUnit[i], ou)
						}
					}
				}
			}
			if tc.wantC != "" {
				if len(name.Country) == 0 || name.Country[0] != tc.wantC {
					t.Errorf("C = %v, want [%q]", name.Country, tc.wantC)
				}
			}
			if tc.wantST != "" {
				if len(name.Province) == 0 || name.Province[0] != tc.wantST {
					t.Errorf("ST = %v, want [%q]", name.Province, tc.wantST)
				}
			}
			if tc.wantL != "" {
				if len(name.Locality) == 0 || name.Locality[0] != tc.wantL {
					t.Errorf("L = %v, want [%q]", name.Locality, tc.wantL)
				}
			}
		})
	}
}

func TestFormatSerial(t *testing.T) {
	tests := []struct {
		name   string
		serial *big.Int
		want   string
	}{
		{"Nil", nil, ""},
		{"One", big.NewInt(1), "01"},
		{"FF", big.NewInt(255), "ff"},
		{"Large", big.NewInt(0x1234), "12:34"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := FormatSerial(tc.serial)
			if got != tc.want {
				t.Errorf("FormatSerial(%v) = %q, want %q", tc.serial, got, tc.want)
			}
		})
	}
}
