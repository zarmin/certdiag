package certlib

func registerAlgorithmChecks() {
	// algorithm
	registerCheck(CheckDefinition{
		ID: "md5_sig", Category: "algorithm", Severity: SeverityCritical,
		AppliesTo:   kindsCert,
		Description: "MD5 signature algorithm",
		check:       checkMD5Sig,
	})
	registerCheck(CheckDefinition{
		ID: "sha1_sig", Category: "algorithm", Severity: SeverityWarning,
		AppliesTo:   kindsCert,
		Description: "SHA-1 signature algorithm",
		check:       checkSHA1Sig,
	})
	registerCheck(CheckDefinition{
		ID: "sig_mismatch", Category: "algorithm", Severity: SeverityWarning,
		AppliesTo:   kindsCert,
		Description: "Outer and TBS signature algorithms differ",
		check:       checkSigMismatch,
	})
}
