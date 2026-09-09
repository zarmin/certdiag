package certops

import (
	"crypto"
	"crypto/x509"
	"os"
	"path/filepath"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

type FindCAOptions struct {
	SearchDirs []string
	Passwords  []certlib.TaggedPassword
}

type FindCAResult struct {
	CACert     *x509.Certificate
	CACertPath string
	CAKey      crypto.PrivateKey
	CAKeyPath  string
}

func FindCA(opts FindCAOptions) (*FindCAResult, error) {
	if len(opts.SearchDirs) == 0 {
		return nil, &OperationError{Op: "autosign", Message: "no search directories specified"}
	}

	provider := &staticPasswordProvider{passwords: opts.Passwords}

	store := certlib.NewCertStore()
	for _, dir := range opts.SearchDirs {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		s, err := certlib.ScanPathWithOptions(dir, certlib.ScanOptions{
			Recursive:        false,
			PasswordProvider: provider,
		})
		if err != nil {
			continue
		}
		for _, c := range s.Containers {
			store.AddContainer(c)
		}
	}

	if store.TotalItems() == 0 {
		return nil, &OperationError{Op: "autosign", Message: "no certificates found in search directories"}
	}

	relations := certlib.DetectRelations(store)

	// Build a set of key->cert pairs
	type caCandidate struct {
		cert     *x509.Certificate
		certPath string
		key      crypto.PrivateKey
		keyPath  string
	}

	var candidates []caCandidate
	for _, rel := range relations {
		if rel.Type != certlib.RelationKeyCert {
			continue
		}

		keyItem := store.SafeItem(rel.Source)
		certItem := store.SafeItem(rel.Target)

		if keyItem == nil || certItem == nil || keyItem.PrivateKey == nil || certItem.Certificate == nil {
			continue
		}

		cert := certItem.Certificate
		if !isCertSigningCA(cert) {
			continue
		}

		candidates = append(candidates, caCandidate{
			cert:     cert,
			certPath: store.Containers[rel.Target.ContainerIdx].FilePath,
			key:      keyItem.PrivateKey,
			keyPath:  store.Containers[rel.Source.ContainerIdx].FilePath,
		})
	}

	if len(candidates) == 0 {
		return nil, &OperationError{Op: "autosign", Message: "no CA with matching private key found"}
	}

	// Select best: prefer intermediate (not self-signed) over root, then most recent NotAfter
	best := candidates[0]
	for _, c := range candidates[1:] {
		bestSS := isCertSelfSigned(best.cert)
		cSS := isCertSelfSigned(c.cert)

		if bestSS && !cSS {
			best = c
			continue
		}
		if !bestSS && cSS {
			continue
		}

		if c.cert.NotAfter.After(best.cert.NotAfter) {
			best = c
		}
	}

	return &FindCAResult{
		CACert:     best.cert,
		CACertPath: best.certPath,
		CAKey:      best.key,
		CAKeyPath:  best.keyPath,
	}, nil
}

func AutosignSearchDirs(outputPath string) []string {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}

	dirs := []string{cwd}
	if outputPath != "" {
		outDir, err := filepath.Abs(filepath.Dir(outputPath))
		if err == nil {
			cwdAbs, err := filepath.Abs(cwd)
			if err != nil || outDir != cwdAbs {
				dirs = append(dirs, outDir)
			}
		}
	}

	return dirs
}

func isCertSelfSigned(cert *x509.Certificate) bool {
	return cert.Subject.String() == cert.Issuer.String()
}

func isCertSigningCA(cert *x509.Certificate) bool {
	if !cert.IsCA {
		return false
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return false
	}
	return true
}

type staticPasswordProvider struct {
	passwords []certlib.TaggedPassword
}

func (s *staticPasswordProvider) PasswordsForFile(_ string) []certlib.TaggedPassword {
	return s.passwords
}
