package certops

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"github.com/zarmin/certdiag/certdiag_app/internal/stringutil"
	"path/filepath"
	"strings"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

type SaveRemoteOptions struct {
	// AIAProvenance records which certificates were fetched rather than served,
	// keyed by SHA-256. A saved chain that quietly contains certificates the
	// server never sent would be misleading, so each one is annotated.
	AIAProvenance map[[32]byte]certlib.AIAFetched

	SaveChain  bool
	SaveLeaf   bool
	SaveAll    bool
	SaveTo     string
	OutputDir  string
	Overwrite  bool
	SaveFormat string
}

type SaveRemoteResult struct {
	SavedFiles []string
}

func (o *SaveRemoteOptions) ShouldSave() bool {
	return o.SaveChain || o.SaveLeaf || o.SaveAll || o.SaveTo != ""
}

func (o *SaveRemoteOptions) formatExt() string {
	switch strings.ToLower(o.SaveFormat) {
	case "der":
		return ".der"
	case "p7b", "pkcs7":
		return ".p7b"
	default:
		return ".pem"
	}
}

func SaveRemoteCerts(target string, certs []*x509.Certificate, opts SaveRemoteOptions) (*SaveRemoteResult, error) {
	if len(certs) == 0 {
		return nil, &OperationError{Op: "save-remote", Message: "no certificates to save"}
	}

	result := &SaveRemoteResult{}

	if opts.SaveTo != "" {
		path := opts.SaveTo
		data, err := encodeCerts(certs, opts.SaveFormat)
		if err != nil {
			return nil, &OperationError{Op: "save-remote", Message: "encoding failed", Err: err}
		}
		data = annotateAIA(data, certs, opts.AIAProvenance)
		if err := certlib.WriteToFile(path, data, opts.Overwrite); err != nil {
			return nil, &OperationError{Op: "save-remote", Message: "write failed", Err: err}
		}
		result.SavedFiles = append(result.SavedFiles, path)
		return result, nil
	}

	dir := opts.OutputDir
	if dir == "" {
		dir = "."
	}
	sanitized := stringutil.SanitizeFilename(target)
	if sanitized == "" {
		sanitized = "remote"
	}
	ext := opts.formatExt()

	if opts.SaveChain {
		filename := fmt.Sprintf("%s_chain%s", sanitized, ext)
		path := filepath.Join(dir, filename)
		data, err := encodeCerts(certs, opts.SaveFormat)
		if err != nil {
			return nil, &OperationError{Op: "save-remote", Message: "encoding chain failed", Err: err}
		}
		data = annotateAIA(data, certs, opts.AIAProvenance)
		if err := certlib.WriteToFile(path, data, opts.Overwrite); err != nil {
			return nil, &OperationError{Op: "save-remote", Message: "write chain failed", Err: err}
		}
		result.SavedFiles = append(result.SavedFiles, path)
	}

	if opts.SaveLeaf {
		filename := fmt.Sprintf("%s_leaf%s", sanitized, ext)
		path := filepath.Join(dir, filename)
		data, err := encodeCerts(certs[:1], opts.SaveFormat)
		if err != nil {
			return nil, &OperationError{Op: "save-remote", Message: "encoding leaf failed", Err: err}
		}
		if err := certlib.WriteToFile(path, data, opts.Overwrite); err != nil {
			return nil, &OperationError{Op: "save-remote", Message: "write leaf failed", Err: err}
		}
		result.SavedFiles = append(result.SavedFiles, path)
	}

	if opts.SaveAll {
		for i, cert := range certs {
			cn := stringutil.SanitizeFilename(cert.Subject.CommonName)
			if cn == "" {
				cn = "unknown"
			}
			filename := fmt.Sprintf("%s_%d_%s%s", sanitized, i+1, cn, ext)
			path := filepath.Join(dir, filename)
			data, err := encodeCerts([]*x509.Certificate{cert}, opts.SaveFormat)
			if err != nil {
				return nil, &OperationError{Op: "save-remote", Message: fmt.Sprintf("encoding cert %d failed", i+1), Err: err}
			}
			if err := certlib.WriteToFile(path, data, opts.Overwrite); err != nil {
				return nil, &OperationError{Op: "save-remote", Message: fmt.Sprintf("write cert %d failed", i+1), Err: err}
			}
			result.SavedFiles = append(result.SavedFiles, path)
		}
	}

	return result, nil
}

func encodeCerts(certs []*x509.Certificate, format string) ([]byte, error) {
	items := certsToItems(certs)
	switch strings.ToLower(format) {
	case "der":
		if len(items) != 1 {
			return nil, fmt.Errorf("DER format supports only a single certificate; got %d", len(items))
		}
		return certlib.EncodeDER(items[0])
	case "p7b", "pkcs7":
		return certlib.EncodePKCS7(items)
	default:
		return encodeCertsAsPEM(certs)
	}
}

func certsToItems(certs []*x509.Certificate) []certlib.CertItem {
	items := make([]certlib.CertItem, len(certs))
	for i, cert := range certs {
		items[i] = certlib.CertItem{
			Type:        certlib.ContentCertificate,
			Certificate: cert,
			RawBytes:    cert.Raw,
		}
	}
	return items
}

func encodeCertsAsPEM(certs []*x509.Certificate) ([]byte, error) {
	items := certsToItems(certs)
	var buf bytes.Buffer
	if err := certlib.WritePEM(&buf, items); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// annotateAIA prefixes each fetched certificate's PEM block with a comment
// naming where it came from. PEM readers ignore text outside the blocks, so the
// file still parses everywhere, including in certdiag itself.
func annotateAIA(data []byte, certs []*x509.Certificate, provenance map[[32]byte]certlib.AIAFetched) []byte {
	if len(provenance) == 0 {
		return data
	}

	blocks := strings.SplitAfter(string(data), "-----END CERTIFICATE-----\n")
	var out strings.Builder
	for i, block := range blocks {
		if i < len(certs) {
			if f, ok := provenance[sha256.Sum256(certs[i].Raw)]; ok {
				fmt.Fprintf(&out, "# AIA: %s from %s on %s\n",
					f.Source, f.URL, f.FetchedAt.Format("2006-01-02"))
			}
		}
		out.WriteString(block)
	}
	return []byte(out.String())
}
