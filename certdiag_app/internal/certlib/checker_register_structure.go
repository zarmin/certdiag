package certlib

func registerStructureChecks() {
	// structure
	registerCheck(CheckDefinition{
		ID: "serial", Category: "structure", Severity: SeverityWarning,
		AppliesTo:   kindsCert,
		Description: "Serial number is negative, zero, or > 20 octets",
		check:       checkSerial,
	})
	registerCheck(CheckDefinition{
		ID: "version", Category: "structure", Severity: SeverityInfo,
		AppliesTo:   kindsCert,
		Description: "Certificate uses extensions but is not v3",
		check:       checkVersion,
	})
	registerCheck(CheckDefinition{
		ID: "unknown_ext", Category: "structure", Severity: SeverityInfo,
		AppliesTo:   kindsCert,
		Description: "Certificate has non-standard critical extension",
		check:       checkUnknownExt,
	})
	registerCheck(CheckDefinition{
		ID: "long_validity", Category: "structure", Severity: SeverityInfo,
		AppliesTo:   kindsLeaf,
		Description: "Leaf cert valid for > 398 days",
		check:       checkLongValidity,
	})
}
