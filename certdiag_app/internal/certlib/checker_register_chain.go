package certlib

func registerChainChecks() {
	// chain
	registerCheck(CheckDefinition{
		ID: "chain_incomplete", Category: "chain", Severity: SeverityWarning,
		AppliesTo:   kindsCert,
		Description: "Issuer certificate not found in scan",
		check:       checkChainIncomplete,
	})
	registerCheck(CheckDefinition{
		ID: "chain_order", Category: "chain", Severity: SeverityInfo,
		AppliesTo:   kindsCert,
		Description: "PEM chain in wrong order (leaf should be first)",
		check:       checkChainOrder,
	})
	registerCheck(CheckDefinition{
		ID: "key_cert_mismatch", Category: "chain", Severity: SeverityWarning,
		AppliesTo:   kindsKey,
		Description: "Private key does not match any certificate in the bundle",
		check:       checkKeyCertMismatch,
	})
}
