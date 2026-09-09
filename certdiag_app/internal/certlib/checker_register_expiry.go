package certlib

func registerExpiryChecks() {
	// expiry
	registerCheck(CheckDefinition{
		ID: "expired", Category: "expiry", Severity: SeverityCritical,
		AppliesTo:   kindsCert,
		Description: "Certificate has expired",
		check:       checkExpired,
	})
	registerCheck(CheckDefinition{
		ID: "expiring_soon_critical", Category: "expiry", Severity: SeverityCritical,
		AppliesTo:   kindsCert,
		Description: "Certificate expires within N days (critical threshold)",
		check:       checkExpiringSoonCritical,
	})
	registerCheck(CheckDefinition{
		ID: "expiring_soon_warning", Category: "expiry", Severity: SeverityWarning,
		AppliesTo:   kindsCert,
		Description: "Certificate expires within N days (warning threshold)",
		check:       checkExpiringSoonWarning,
	})
	registerCheck(CheckDefinition{
		ID: "not_yet_valid", Category: "expiry", Severity: SeverityWarning,
		AppliesTo:   kindsCert,
		Description: "Certificate is not yet valid (NotBefore > now)",
		check:       checkNotYetValid,
	})
}
