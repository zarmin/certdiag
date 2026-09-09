package opensslcmd

import "github.com/zarmin/certdiag/certdiag_app/internal/certlib"

// Inspect returns the openssl (or keytool) command that reproduces certdiag's
// inspection of an item. Container formats (PKCS#12, PKCS#7, JKS) map to their
// listing commands; otherwise the content type selects x509/req/pkey.
func Inspect(path string, ct certlib.ContentType, format certlib.FileFormat) Command {
	switch format {
	case certlib.FormatPKCS12:
		return Command{
			Tool:  ToolOpenSSL,
			Args:  []string{"pkcs12", "-in", path, "-info", "-nodes"},
			Notes: []string{"PKCS#12 is a container; this lists its contents and prompts for the password"},
		}
	case certlib.FormatPKCS7:
		return Command{
			Tool: ToolOpenSSL,
			Args: []string{"pkcs7", "-in", path, "-print_certs", "-text", "-noout"},
		}
	case certlib.FormatJKS:
		return Command{
			Tool:  ToolKeytool,
			Args:  []string{"-list", "-v", "-keystore", path},
			Notes: []string{"JKS is a Java keystore; use keytool, not openssl"},
		}
	}

	var c Command
	switch ct {
	case certlib.ContentCSR:
		c = Command{Tool: ToolOpenSSL, Args: []string{"req", "-in", path, "-text", "-noout"}}
	case certlib.ContentPrivateKey:
		c = Command{Tool: ToolOpenSSL, Args: []string{"pkey", "-in", path, "-text", "-noout"}}
	case certlib.ContentPublicKey:
		c = Command{Tool: ToolOpenSSL, Args: []string{"pkey", "-pubin", "-in", path, "-text", "-noout"}}
	default:
		c = Command{Tool: ToolOpenSSL, Args: []string{"x509", "-in", path, "-text", "-noout"}}
	}
	if format == certlib.FormatDER {
		c.Args = append(c.Args, "-inform", "DER")
	}
	return c
}
