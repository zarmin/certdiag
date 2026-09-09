package certlib

func registerInfoChecks() {
	// info
	registerCheck(CheckDefinition{
		ID: "self_signed_leaf", Category: "info", Severity: SeverityInfo,
		AppliesTo:   kindsLeaf,
		Description: "Non-CA self-signed certificate",
		check:       checkSelfSignedLeaf,
	})
	registerCheck(CheckDefinition{
		ID: "wildcard", Category: "info", Severity: SeverityInfo,
		AppliesTo:   kindsLeaf,
		Description: "Certificate uses wildcard DNS names",
		check:       checkWildcard,
	})
}
