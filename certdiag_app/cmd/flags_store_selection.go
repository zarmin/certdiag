package cmd

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
)

// storeSelectionFlags is the one trust-store selection every store-facing
// command registers: `store` picks which store to list, `verify` which store to
// verify against, `remote fetch` and `remote check` which stores to compare on
// top of the OS store. One registration site means one spelling and one help
// text per flag, and a command cannot advertise a flag it never reads (M31 H2,
// cmd/flags_consumed_test.go, TestStoreSelectionFlagsAreShared).
type storeSelectionFlags struct {
	Trust    bool
	AIA      bool
	Java     bool
	JavaHome string
	OpenSSL  bool
	NSS      bool
	Mozilla  bool
	Chrome   bool
	File     string
}

// storeSelectionOpts says how a command uses the selection. An additive
// command compares against the OS store plus the selected ones and also gets
// --trust and --aia; a selecting command picks exactly one store. NSS stores
// are per browser profile, so only the listing command offers --nss.
type storeSelectionOpts struct {
	additive      bool
	nss           bool
	fileShorthand string
}

// Register binds the flags. The help text carries the semantic difference:
// "Also verify against ..." on additive commands, the bare store name where
// the flag selects.
func (f *storeSelectionFlags) Register(cmd *cobra.Command, o storeSelectionOpts) {
	usage := func(noun string) string {
		if o.additive {
			return "Also verify against " + noun
		}
		return strings.ToUpper(noun[:1]) + noun[1:]
	}
	fl := cmd.Flags()
	if o.additive {
		fl.BoolVar(&f.Trust, "trust", false, "Evaluate whether this machine trusts the served chain")
		fl.BoolVar(&f.AIA, "aia", false, "Fetch missing issuers over AIA (network; implies --trust)")
	}
	fl.BoolVar(&f.Java, "java", false, usage("Java cacerts (all detected JDKs)"))
	fl.StringVar(&f.JavaHome, "java-home", "", usage("a specific JDK's cacerts"))
	fl.BoolVar(&f.OpenSSL, "openssl", false, usage("the OpenSSL default bundle"))
	if o.nss {
		fl.BoolVar(&f.NSS, "nss", false, "Browser profile stores (Firefox, Thunderbird, Chrome on Linux)")
	}
	fl.BoolVar(&f.Mozilla, "mozilla", false, usage("the shipped Mozilla root snapshot"))
	fl.BoolVar(&f.Chrome, "chrome", false, usage("the shipped Chrome root snapshot"))
	fl.StringVarP(&f.File, "trust-file", o.fileShorthand, "", usage("an arbitrary CA bundle (PEM, JKS, PKCS#12)"))
}

// SingleStore is the rule `verify` and `store` share: the first selected store
// wins, and the OS store is the default. The bundle id is set for the shipped
// snapshots only.
func (f *storeSelectionFlags) SingleStore() (truststore.StoreType, string) {
	switch {
	case f.Java || f.JavaHome != "":
		return truststore.StoreTypeJava, ""
	case f.OpenSSL:
		return truststore.StoreTypeOpenSSL, ""
	case f.NSS:
		return truststore.StoreTypeNSS, ""
	case f.Mozilla:
		return truststore.StoreTypeBundle, truststore.BundleMozilla
	case f.Chrome:
		return truststore.StoreTypeBundle, truststore.BundleChrome
	case f.File != "":
		return truststore.StoreTypeCustom, ""
	}
	return truststore.StoreTypeOS, ""
}

// Selection maps the flags onto the additive selection the remote commands
// use. The OS store is included whenever any trust question was asked, since
// "does this machine trust it" is what the others are compared against.
func (f *storeSelectionFlags) Selection() certops.RemoteTrustSelection {
	sel := certops.RemoteTrustSelection{
		Java:     f.Java,
		JavaHome: f.JavaHome,
		OpenSSL:  f.OpenSSL,
		Mozilla:  f.Mozilla,
		Chrome:   f.Chrome,
		File:     f.File,
	}
	sel.OS = f.Trust || sel.Any()
	return sel
}

// Asked reports whether any trust evaluation was requested at all.
func (f *storeSelectionFlags) Asked() bool {
	return f.Trust || f.AIA || f.Selection().Any()
}
