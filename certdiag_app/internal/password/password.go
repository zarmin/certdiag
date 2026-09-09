package password

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/config"
	"github.com/zarmin/certdiag/certdiag_app/internal/crypto"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
)

type PasswordManagerOpts struct {
	CLIPasswords   []string
	PasswordFiles  []string
	Config         *config.ConfigFile
	MasterPassword []byte
	NoTryAll       bool
	Interactive    bool
}

type PasswordManager struct {
	cliPasswords          [][]byte
	filePasswords         [][]byte
	config                *config.ConfigFile
	masterPassword        []byte
	commonDecrypted       [][]byte
	byFilenameDecrypted   [][]byte
	envPasswords          [][]byte
	noTryAll              bool
	interactive           bool
	skipAllInteractive    bool
}

func NewPasswordManager(opts PasswordManagerOpts) (*PasswordManager, error) {
	pm := &PasswordManager{
		config:         opts.Config,
		masterPassword: opts.MasterPassword,
		noTryAll:       opts.NoTryAll,
		interactive:    opts.Interactive,
	}

	if len(opts.CLIPasswords) > 0 {
		fmt.Fprintln(os.Stderr, output.ColorizeWarning("Warning: passwords provided via command line are visible in process listing"))
		for _, p := range opts.CLIPasswords {
			pm.cliPasswords = append(pm.cliPasswords, []byte(p))
		}
	}

	filePasswords, err := ReadPasswordFiles(opts.PasswordFiles)
	if err != nil {
		return nil, err
	}
	pm.filePasswords = filePasswords

	pm.envPasswords = CollectEnvPasswords()

	if opts.Config != nil && len(opts.Config.Passwords.CommonEncrypted) > 0 && len(opts.MasterPassword) > 0 {
		for i, enc := range opts.Config.Passwords.CommonEncrypted {
			decrypted, err := crypto.Decrypt(opts.MasterPassword, enc)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt common_encrypted[%d] (%s): %w", i, enc, err)
			}
			pm.commonDecrypted = append(pm.commonDecrypted, decrypted)
		}
	}

	if opts.Config != nil && len(opts.MasterPassword) > 0 {
		byFilenameDecrypted := make([][]byte, len(opts.Config.Passwords.ByFilename))
		for i, fp := range opts.Config.Passwords.ByFilename {
			if fp.EncryptedPassword == "" {
				continue
			}
			dec, err := crypto.Decrypt(opts.MasterPassword, fp.EncryptedPassword)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt by_filename[%d] (%s) (%s): %w", i, fp.Filename+fp.Filepath, fp.EncryptedPassword, err)
			}
			byFilenameDecrypted[i] = dec
		}
		pm.byFilenameDecrypted = byFilenameDecrypted
	}

	return pm, nil
}

func (pm *PasswordManager) PasswordsForFile(filePath string) []certlib.TaggedPassword {
	var passwords []certlib.TaggedPassword

	if pm.config != nil {
		basename := filepath.Base(filePath)
		for i, m := range pm.config.Passwords.ByFilename {
			matched := false
			if m.Filename != "" {
				ok, err := filepath.Match(m.Filename, basename)
				if err == nil && ok {
					matched = true
				}
			}
			if m.Filepath != "" && m.Filepath == filePath {
				matched = true
			}
			if !matched {
				continue
			}
			if m.PlaintextPassword != "" {
				passwords = append(passwords, certlib.TaggedPassword{
					Password: []byte(m.PlaintextPassword),
					Source:   certlib.PasswordSourceByFilenamePlain,
				})
			}
			if i < len(pm.byFilenameDecrypted) && pm.byFilenameDecrypted[i] != nil {
				passwords = append(passwords, certlib.TaggedPassword{
					Password: pm.byFilenameDecrypted[i],
					Source:   certlib.PasswordSourceByFilenameEncrypted,
				})
			}
		}
	}

	if pm.noTryAll {
		return passwords
	}

	for _, p := range pm.cliPasswords {
		passwords = append(passwords, certlib.TaggedPassword{Password: p, Source: certlib.PasswordSourceCLI})
	}
	for _, p := range pm.filePasswords {
		passwords = append(passwords, certlib.TaggedPassword{Password: p, Source: certlib.PasswordSourcePasswordFile})
	}
	if pm.config != nil {
		for _, p := range pm.config.Passwords.CommonPlaintext {
			if p == "" {
				fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeWarning(
					"Warning: empty password in config common_plaintext"))
			}
			passwords = append(passwords, certlib.TaggedPassword{Password: []byte(p), Source: certlib.PasswordSourceCommonPlaintext})
		}
	}
	for _, p := range pm.commonDecrypted {
		passwords = append(passwords, certlib.TaggedPassword{Password: p, Source: certlib.PasswordSourceCommonEncrypted})
	}
	for _, p := range pm.envPasswords {
		passwords = append(passwords, certlib.TaggedPassword{Password: p, Source: certlib.PasswordSourceEnvVar})
	}
	passwords = append(passwords, certlib.BuiltInPasswords()...)

	return passwords
}

func (pm *PasswordManager) HandleInteractive(filePath string, retryFn func([]byte) bool) bool {
	if !pm.interactive || pm.skipAllInteractive {
		return false
	}

	for {
		pw, err := PromptPassword(fmt.Sprintf("Enter password for %s: ", filePath))
		if err != nil {
			return false
		}

		if retryFn(pw) {
			return true
		}

		fmt.Fprintln(os.Stderr, "  Password incorrect.")
		choice := promptRetryMenu()
		switch choice {
		case 'r':
			continue
		case 's':
			return false
		case 'S':
			pm.skipAllInteractive = true
			return false
		case 'q':
			fmt.Fprintln(os.Stderr, "Quitting.")
			os.Exit(0)
		default:
			return false
		}
	}
}

func (pm *PasswordManager) IsInteractive() bool {
	return pm.interactive && !pm.skipAllInteractive
}

// ReadPasswordFiles returns the passwords listed in the files, one per line,
// blank lines and # comments skipped, in file order.
func ReadPasswordFiles(paths []string) ([][]byte, error) {
	var passwords [][]byte
	for _, path := range paths {
		filePasswords, err := readPasswordFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read password file: %w", err)
		}
		passwords = append(passwords, filePasswords...)
	}
	return passwords, nil
}

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

func readPasswordFile(path string) ([][]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Strip UTF-8 BOM if present (common in Windows-created files)
	data = bytes.TrimPrefix(data, utf8BOM)

	var passwords [][]byte
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			passwords = append(passwords, []byte(line))
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return passwords, nil
}
