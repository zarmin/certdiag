package opensslcmd

import (
	"fmt"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

// Convert returns the openssl (or keytool) command(s) equivalent to a certdiag
// format conversion. include is "certs", "keys", or "all". Because the emitted
// commands cannot know a container's exact contents, PKCS#12/PKCS#7 recipes use
// placeholder password tokens and carry explanatory notes.
func Convert(inputPath string, inputFormat certlib.FileFormat, outputPath string, outputFormat certlib.FileFormat, include string, legacyPKCS12 bool) []Command {
	// JKS on either side is keytool territory, never openssl.
	if inputFormat == certlib.FormatJKS || outputFormat == certlib.FormatJKS {
		return jksConvert(inputPath, inputFormat, outputPath, outputFormat)
	}

	// --include keys extracts the private key, which is openssl pkey, not the
	// x509/cert recipes below. (certs/all keep the cert-oriented recipes.)
	if include == "keys" && (outputFormat == certlib.FormatPEM || outputFormat == certlib.FormatDER) {
		src, pre := pemSource(inputPath, inputFormat)
		args := []string{"pkey", "-in", src}
		if outputFormat == certlib.FormatDER {
			args = append(args, "-outform", "DER")
		}
		args = append(args, "-out", outputPath)
		return append(pre, Command{Tool: ToolOpenSSL, Args: args,
			Notes: []string{"extracts the private key only (--include keys)"}})
	}

	switch outputFormat { //nolint:exhaustive // remaining formats fall through to noEquivalent
	case certlib.FormatPEM:
		return toPEM(inputPath, inputFormat, outputPath)
	case certlib.FormatDER:
		// x509 reads PEM or DER cert bytes directly; a PKCS#12/PKCS#7 container
		// needs a PEM extraction step first.
		if inputFormat == certlib.FormatPEM || inputFormat == certlib.FormatDER {
			return []Command{{
				Tool:  ToolOpenSSL,
				Args:  x509FormatArgs(inputPath, inputFormat, outputPath, certlib.FormatDER),
				Notes: []string{"assumes a single certificate; use openssl pkey for a private key"},
			}}
		}
		src, pre := pemSource(inputPath, inputFormat)
		return append(pre, Command{Tool: ToolOpenSSL,
			Args:  x509FormatArgs(src, certlib.FormatPEM, outputPath, certlib.FormatDER),
			Notes: []string{"assumes a single certificate"}})
	case certlib.FormatPKCS12:
		src, pre := pemSource(inputPath, inputFormat)
		return append(pre, toPKCS12(src, outputPath, include, legacyPKCS12))
	case certlib.FormatPKCS7:
		src, pre := pemSource(inputPath, inputFormat)
		return append(pre, Command{
			Tool:  ToolOpenSSL,
			Args:  []string{"crl2pkcs7", "-nocrl", "-certfile", src, "-out", outputPath},
			Notes: []string{"PKCS#7 holds certificates only; any private key in the input is dropped"},
		})
	}
	return []Command{noEquivalent(fmt.Sprintf("no simple openssl equivalent for %s -> %s conversion", inputFormat, outputFormat))}
}

// pemSource returns a PEM path to feed to a PEM-only openssl recipe, plus any
// commands needed to produce it. When the input is already PEM there is no extra
// step; otherwise it is converted to a PEM intermediate first.
func pemSource(inputPath string, inputFormat certlib.FileFormat) (string, []Command) {
	if inputFormat == certlib.FormatPEM {
		return inputPath, nil
	}
	const interPEM = "intermediate.pem"
	return interPEM, toPEM(inputPath, inputFormat, interPEM)
}

func toPEM(inputPath string, inputFormat certlib.FileFormat, outputPath string) []Command {
	switch inputFormat {
	case certlib.FormatDER:
		return []Command{{
			Tool:  ToolOpenSSL,
			Args:  x509FormatArgs(inputPath, certlib.FormatDER, outputPath, certlib.FormatPEM),
			Notes: []string{"assumes a single certificate; use openssl pkey for a private key"},
		}}
	case certlib.FormatPKCS12:
		return []Command{{
			Tool:  ToolOpenSSL,
			Args:  []string{"pkcs12", "-in", inputPath, "-passin", "pass:INPUT_PASSWORD", "-nodes", "-out", outputPath},
			Notes: []string{"replace INPUT_PASSWORD with the keystore password; -nodes leaves the key unencrypted"},
		}}
	case certlib.FormatPKCS7:
		return []Command{{
			Tool: ToolOpenSSL,
			Args: []string{"pkcs7", "-in", inputPath, "-print_certs", "-out", outputPath},
		}}
	case certlib.FormatPEM:
		return []Command{{
			Tool:  ToolOpenSSL,
			Args:  []string{"x509", "-in", inputPath, "-out", outputPath},
			Notes: []string{"PEM -> PEM is effectively a copy; shown for a single certificate"},
		}}
	}
	return []Command{noEquivalent(fmt.Sprintf("no simple openssl equivalent for %s -> pem conversion", inputFormat))}
}

func toPKCS12(inputPath, outputPath, include string, legacy bool) Command {
	c := Command{Tool: ToolOpenSSL, Args: []string{"pkcs12", "-export", "-in", inputPath, "-out", outputPath, "-passout", "pass:OUTPUT_PASSWORD"}}
	switch include {
	case "certs":
		c.Args = append(c.Args, "-nokeys")
	case "keys":
		c.Args = append(c.Args, "-nocerts")
	}
	if legacy {
		c.Args = append(c.Args, "-legacy", "-descert")
		c.Notes = append(c.Notes, "legacy mode: certdiag uses PBE-SHA1-3DES for keys and certs, HMAC-SHA1 for the MAC")
	} else {
		c.Notes = append(c.Notes, "certdiag uses PBES2 (PBKDF2-HMAC-SHA256, AES-256-CBC) and an HMAC-SHA256 MAC, matching OpenSSL 3 defaults")
	}
	c.Notes = append(c.Notes, "replace OUTPUT_PASSWORD with the export password; supply -inkey/-in for separate key and cert files")
	return c
}

// keytoolImport builds a keytool -importkeystore command. keytool only reads and
// writes JKS or PKCS#12 keystores, never PEM/DER/PKCS#7.
func keytoolImport(inputPath string, inputFormat certlib.FileFormat, outputPath string, dstStore string) Command {
	srcStore := "PKCS12"
	if inputFormat == certlib.FormatJKS {
		srcStore = "JKS"
	}
	c := Command{Tool: ToolKeytool, Args: []string{
		"-importkeystore",
		"-srckeystore", inputPath, "-srcstoretype", srcStore,
		"-destkeystore", outputPath, "-deststoretype", dstStore,
	}}
	c.Notes = []string{
		"JKS is a Java keystore; use keytool, not openssl",
		"keytool will prompt for the source and destination store passwords",
		"certdiag encodes JKS passwords as UTF-8; keytool uses UTF-16BE, so non-ASCII passwords may not interoperate",
	}
	return c
}

// jksConvert emits the keytool (and, when the other side is PEM/DER/PKCS#7,
// openssl) commands for a conversion involving JKS. keytool cannot read or write
// PEM/DER/PKCS#7 directly, so those go through a PKCS#12 intermediate.
func jksConvert(inputPath string, inputFormat certlib.FileFormat, outputPath string, outputFormat certlib.FileFormat) []Command {
	// Output is a keystore: a single keytool import does it (input must be a
	// keystore too; note when it is not).
	if outputFormat == certlib.FormatJKS {
		c := keytoolImport(inputPath, inputFormat, outputPath, "JKS")
		if inputFormat != certlib.FormatJKS && inputFormat != certlib.FormatPKCS12 {
			c.Notes = append(c.Notes, fmt.Sprintf("convert %s to PKCS#12 first; keytool imports only from JKS or PKCS#12", inputFormat))
		}
		return []Command{c}
	}
	if outputFormat == certlib.FormatPKCS12 {
		return []Command{keytoolImport(inputPath, inputFormat, outputPath, "PKCS12")}
	}

	// Input is JKS, output is PEM/DER/PKCS#7: keytool JKS -> intermediate PKCS#12,
	// then the normal openssl recipe from that PKCS#12.
	interP12 := "intermediate.p12"
	step1 := keytoolImport(inputPath, certlib.FormatJKS, interP12, "PKCS12")
	step1.Notes = append(step1.Notes, fmt.Sprintf("keytool cannot write %s; export to a PKCS#12 intermediate, then convert with openssl", outputFormat))

	cmds := []Command{step1}
	switch outputFormat { //nolint:exhaustive // JKS/PKCS12 handled above
	case certlib.FormatPEM:
		cmds = append(cmds, toPEM(interP12, certlib.FormatPKCS12, outputPath)...)
	case certlib.FormatDER, certlib.FormatPKCS7:
		// DER/PKCS#7 need a PEM step in between (x509/crl2pkcs7 read PEM/DER cert
		// bytes, not a PKCS#12 container).
		interPEM := "intermediate.pem"
		cmds = append(cmds, toPEM(interP12, certlib.FormatPKCS12, interPEM)...)
		if outputFormat == certlib.FormatDER {
			cmds = append(cmds, Command{Tool: ToolOpenSSL,
				Args:  x509FormatArgs(interPEM, certlib.FormatPEM, outputPath, certlib.FormatDER),
				Notes: []string{"assumes a single certificate"}})
		} else {
			cmds = append(cmds, Command{Tool: ToolOpenSSL,
				Args:  []string{"crl2pkcs7", "-nocrl", "-certfile", interPEM, "-out", outputPath},
				Notes: []string{"PKCS#7 holds certificates only; any private key is dropped"}})
		}
	}
	return cmds
}

func x509FormatArgs(inputPath string, inFormat certlib.FileFormat, outputPath string, outFormat certlib.FileFormat) []string {
	args := []string{"x509", "-in", inputPath}
	if inFormat == certlib.FormatDER {
		args = append(args, "-inform", "DER")
	}
	if outFormat == certlib.FormatDER {
		args = append(args, "-outform", "DER")
	}
	return append(args, "-out", outputPath)
}

// noEquivalent is a notes-only command (no Tool) so it renders as a comment,
// not a bare, runnable "openssl" line that would drop into an interactive prompt.
func noEquivalent(msg string) Command {
	return Command{Notes: []string{msg}}
}

// Note returns a notes-only command (rendered as a comment, no runnable line).
func Note(msg string) Command {
	return noEquivalent(msg)
}
