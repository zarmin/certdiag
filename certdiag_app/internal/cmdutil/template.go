package cmdutil

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

// TemplateInputs is what --template (an existing certificate) or
// --template-profile (a YAML profile) contributes to a create-cert or
// create-csr run. Either pointer may be nil.
type TemplateInputs struct {
	Cert *certlib.CertGenOptions
	Key  *certlib.KeyGenOptions
}

// LoadTemplateInputs reads the template certificate and/or profile. The
// certificate file is read through the password manager's passwords for that
// path, so a PKCS#12 or an encrypted bundle works as a template (M16).
func LoadTemplateInputs(templatePath, profilePath string, passwords []certlib.TaggedPassword) (TemplateInputs, error) {
	var in TemplateInputs
	if templatePath != "" {
		container, err := certlib.ReadFile(templatePath, passwords)
		if err != nil {
			return in, fmt.Errorf("cannot read template cert: %w", err)
		}
		var cert *x509.Certificate
		for _, item := range container.Items {
			if item.Certificate != nil {
				cert = item.Certificate
				break
			}
		}
		if cert == nil {
			return in, fmt.Errorf("template file contains no certificate")
		}
		opts := certlib.TemplateFromCert(cert)
		in.Cert = &opts
	}
	if profilePath != "" {
		profile, err := certlib.LoadCertProfile(profilePath)
		if err != nil {
			return in, fmt.Errorf("cannot load profile: %w", err)
		}
		opts, kOpts, err := profile.ToCertGenOptions()
		if err != nil {
			return in, fmt.Errorf("invalid profile: %w", err)
		}
		in.Cert = &opts
		if kOpts.Algorithm != "" || kOpts.KeySize > 0 || kOpts.Curve != "" {
			in.Key = &kOpts
		}
	}
	return in, nil
}

// ApplyKeyDefaults overlays the template's key parameters on the config
// defaults; the CLI flags are applied afterwards by KeyGenFlags.ApplyChanged.
func (in TemplateInputs) ApplyKeyDefaults(dst *certlib.KeyGenOptions) {
	if in.Key == nil {
		return
	}
	if in.Key.Algorithm != "" {
		dst.Algorithm = in.Key.Algorithm
	}
	if in.Key.KeySize > 0 {
		dst.KeySize = in.Key.KeySize
	}
	if in.Key.Curve != "" {
		dst.Curve = in.Key.Curve
	}
}

// ResolveSubject layers config defaults, then the template subject, then the
// --subject DN string.
func (in TemplateInputs) ResolveSubject(defaults pkix.Name, subjectFlag string) (pkix.Name, error) {
	subject := defaults
	if in.Cert != nil {
		subject = certlib.MergeSubject(subject, in.Cert.Subject)
	}
	if subjectFlag != "" {
		parsed, err := certlib.ParseDN(subjectFlag)
		if err != nil {
			return subject, fmt.Errorf("invalid subject: %w", err)
		}
		certlib.ApplyParsedDN(&subject, parsed)
	}
	return subject, nil
}

// ResolveSANs takes the template's SANs unless --san was given, which
// replaces them entirely.
func (in TemplateInputs) ResolveSANs(sanFlag string, sanChanged bool) (certlib.SANList, error) {
	var sans certlib.SANList
	if in.Cert != nil && !in.Cert.SANs.IsEmpty() {
		sans = in.Cert.SANs
	}
	if sanChanged {
		parsed, err := certlib.ParseSANString(sanFlag)
		if err != nil {
			return sans, fmt.Errorf("invalid SAN: %w", err)
		}
		sans = parsed
	}
	return sans, nil
}
