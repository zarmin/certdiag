package certlib

import (
	"net"
	"testing"
)

func TestParseSANString(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantDNS   []string
		wantIPs   []string
		wantEmail []string
		wantURIs  []string
		wantErr   bool
	}{
		{
			name:    "DNS",
			input:   "dns:example.com",
			wantDNS: []string{"example.com"},
		},
		{
			name:    "IP",
			input:   "ip:192.168.1.1",
			wantIPs: []string{"192.168.1.1"},
		},
		{
			name:    "IPv6",
			input:   "ip:::1",
			wantIPs: []string{"::1"},
		},
		{
			name:      "Email",
			input:     "email:user@x.com",
			wantEmail: []string{"user@x.com"},
		},
		{
			name:     "URI",
			input:    "uri:https://x.com",
			wantURIs: []string{"https://x.com"},
		},
		{
			name:      "Mixed",
			input:     "dns:a.com,ip:10.0.0.1,email:u@b.com",
			wantDNS:   []string{"a.com"},
			wantIPs:   []string{"10.0.0.1"},
			wantEmail: []string{"u@b.com"},
		},
		{
			name:    "AutoDetectDNS",
			input:   "example.com",
			wantDNS: []string{"example.com"},
		},
		{
			name:    "AutoDetectIP",
			input:   "10.0.0.1",
			wantIPs: []string{"10.0.0.1"},
		},
		{
			name:  "Empty",
			input: "",
		},
		{
			name:    "Error/InvalidIP",
			input:   "ip:notanip",
			wantErr: true,
		},
		{
			name:    "Error/URINoScheme",
			input:   "uri:noscheme",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseSANString(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(tc.wantDNS) > 0 {
				if len(result.DNSNames) != len(tc.wantDNS) {
					t.Fatalf("DNS count = %d, want %d", len(result.DNSNames), len(tc.wantDNS))
				}
				for i, want := range tc.wantDNS {
					if result.DNSNames[i] != want {
						t.Errorf("DNS[%d] = %q, want %q", i, result.DNSNames[i], want)
					}
				}
			}

			if len(tc.wantIPs) > 0 {
				if len(result.IPAddresses) != len(tc.wantIPs) {
					t.Fatalf("IP count = %d, want %d", len(result.IPAddresses), len(tc.wantIPs))
				}
				for i, want := range tc.wantIPs {
					wantIP := net.ParseIP(want)
					if !result.IPAddresses[i].Equal(wantIP) {
						t.Errorf("IP[%d] = %v, want %v", i, result.IPAddresses[i], wantIP)
					}
				}
			}

			if len(tc.wantEmail) > 0 {
				if len(result.EmailAddresses) != len(tc.wantEmail) {
					t.Fatalf("Email count = %d, want %d", len(result.EmailAddresses), len(tc.wantEmail))
				}
				for i, want := range tc.wantEmail {
					if result.EmailAddresses[i] != want {
						t.Errorf("Email[%d] = %q, want %q", i, result.EmailAddresses[i], want)
					}
				}
			}

			if len(tc.wantURIs) > 0 {
				if len(result.URIs) != len(tc.wantURIs) {
					t.Fatalf("URI count = %d, want %d", len(result.URIs), len(tc.wantURIs))
				}
				for i, want := range tc.wantURIs {
					if result.URIs[i].String() != want {
						t.Errorf("URI[%d] = %q, want %q", i, result.URIs[i].String(), want)
					}
				}
			}
		})
	}
}
