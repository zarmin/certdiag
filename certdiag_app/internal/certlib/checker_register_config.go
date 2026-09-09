package certlib

func registerConfigChecks() {
	// config
	registerCheck(CheckDefinition{
		ID: "unprotected_key", Category: "config", Severity: SeverityInfo,
		AppliesTo:   kindsKey,
		Description: "Private key not password-protected",
		check:       checkUnprotectedKey,
	})
	registerCheck(CheckDefinition{
		ID: "empty_password", Category: "config", Severity: SeverityInfo,
		AppliesTo:   kindsKey,
		Description: "Protected with empty password",
		check:       checkEmptyPassword,
	})
	registerCheck(CheckDefinition{
		ID: "entry_password_mismatch", Category: "config", Severity: SeverityInfo,
		AppliesTo:   kindsKey,
		Description: "Key entry uses different password than store",
		check:       checkEntryPasswordMismatch,
	})
	registerCheck(CheckDefinition{
		ID: "missing_sans", Category: "config", Severity: SeverityInfo,
		AppliesTo:   kindsLeaf,
		Description: "Certificate has CN but no SANs",
		check:       checkMissingSANs,
	})
	registerCheck(CheckDefinition{
		ID: "ca_no_keyusage", Category: "config", Severity: SeverityWarning,
		AppliesTo:   kindsCA,
		Description: "CA cert missing keyCertSign in key usage",
		check:       checkCANoKeyUsage,
	})
	registerCheck(CheckDefinition{
		ID: "ca_no_bc", Category: "config", Severity: SeverityWarning,
		AppliesTo:   kindsCert,
		Description: "CA cert missing BasicConstraints extension",
		check:       checkCANoBC,
	})
	registerCheck(CheckDefinition{
		ID: "leaf_certsign", Category: "config", Severity: SeverityWarning,
		AppliesTo:   kindsLeaf,
		Description: "Non-CA cert has keyCertSign key usage",
		check:       checkLeafCertSign,
	})
	registerCheck(CheckDefinition{
		ID: "ip_in_cn", Category: "config", Severity: SeverityInfo,
		AppliesTo:   kindsLeaf,
		Description: "IP address in CN but not in SAN",
		check:       checkIPInCN,
	})
}
