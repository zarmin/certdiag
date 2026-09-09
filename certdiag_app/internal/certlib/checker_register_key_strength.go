package certlib

func registerKeyStrengthChecks() {
	// key_strength
	registerCheck(CheckDefinition{
		ID: "very_weak_rsa", Category: "key_strength", Severity: SeverityCritical,
		AppliesTo:   kindsAny,
		Description: "RSA key shorter than 1024 bits",
		check:       checkVeryWeakRSA,
	})
	registerCheck(CheckDefinition{
		ID: "weak_rsa", Category: "key_strength", Severity: SeverityWarning,
		AppliesTo:   kindsAny,
		Description: "RSA key shorter than 2048 bits",
		check:       checkWeakRSA,
	})
	registerCheck(CheckDefinition{
		ID: "weak_ec_curve", Category: "key_strength", Severity: SeverityWarning,
		AppliesTo:   kindsAny,
		Description: "ECDSA curve weaker than P-256",
		check:       checkWeakECCurve,
	})
	registerCheck(CheckDefinition{
		ID: "rsa_exponent", Category: "key_strength", Severity: SeverityWarning,
		AppliesTo:   kindsAny,
		Description: "RSA public exponent is not 65537",
		check:       checkRSAExponent,
	})
	registerCheck(CheckDefinition{
		ID: "deprecated_key", Category: "key_strength", Severity: SeverityWarning,
		AppliesTo:   kindsAny,
		Description: "Deprecated key type (DSA)",
		check:       checkDeprecatedKey,
	})
}
