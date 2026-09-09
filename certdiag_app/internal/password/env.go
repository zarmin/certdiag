package password

import (
	"fmt"
	"os"
	"strings"

	"github.com/zarmin/certdiag/certdiag_app/internal/output"
)

func CollectEnvPasswords() [][]byte {
	var passwords [][]byte
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 && strings.HasPrefix(parts[0], "CERTDIAG_PASSWORD_") {
			if parts[1] == "" {
				fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeWarning(
					fmt.Sprintf("Warning: empty password from env var %s", parts[0])))
			}
			passwords = append(passwords, []byte(parts[1]))
		}
	}
	return passwords
}
