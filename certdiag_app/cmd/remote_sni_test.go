package cmd

import "testing"

func TestRemoteDisableSNIResolution(t *testing.T) {
	tests := []struct {
		name     string
		noSNI    bool
		hostname string
		want     bool
	}{
		{"default", false, "", false},
		{"no_sni_flag", true, "", true},
		{"plain_empty_hostname", false, "", false},
		{"regular_hostname", false, "example.com", false},
	}

	origNoSNI := remoteNoSNI
	origHostname := remoteHostname
	origOutput := remoteOutputFormat
	origConfig := configFile
	defer func() {
		remoteNoSNI = origNoSNI
		remoteHostname = origHostname
		remoteOutputFormat = origOutput
		configFile = origConfig
	}()

	remoteOutputFormat = "human"
	configFile = ""

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			remoteNoSNI = tt.noSNI
			remoteHostname = tt.hostname

			settings, err := loadRemoteSettings()
			if err != nil {
				t.Fatalf("loadRemoteSettings() error = %v", err)
			}
			if settings.disableSNI != tt.want {
				t.Errorf("disableSNI = %v, want %v (noSNI=%v hostname=%q)", settings.disableSNI, tt.want, tt.noSNI, tt.hostname)
			}
		})
	}

	t.Run("hostname_with_no_sni_rejected", func(t *testing.T) {
		remoteNoSNI = true
		remoteHostname = "example.com"
		if _, err := loadRemoteSettings(); err == nil {
			t.Fatal("loadRemoteSettings() accepted --hostname together with --no-sni")
		}
	})
}
