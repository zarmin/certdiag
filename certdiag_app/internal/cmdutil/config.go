package cmdutil

import (
	"fmt"
	"os"

	"github.com/zarmin/certdiag/certdiag_app/internal/config"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
)

// LoadConfigOrExit is the one way a command loads the config file. A config
// that cannot be read is fatal for every command, with one message, so a typo
// in -c never silently runs without the passwords or defaults the user wrote.
// exitCode is the command's error exit code (1 for most, 2 for diff).
func LoadConfigOrExit(path string, exitCode int) *config.ConfigFile {
	cfg, err := config.LoadConfig(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error loading config: %v", err)))
		os.Exit(exitCode)
	}
	return cfg
}
