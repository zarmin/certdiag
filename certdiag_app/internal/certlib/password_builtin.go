package certlib

import "github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"

// BuiltInPasswords is the tagged form of truststore.DefaultKeystorePassword,
// tried last by every password provider so a file opened with it reports
// "built-in default" rather than a source the user never gave.
func BuiltInPasswords() []TaggedPassword {
	return []TaggedPassword{{Password: truststore.DefaultKeystorePassword, Source: PasswordSourceBuiltIn}}
}
