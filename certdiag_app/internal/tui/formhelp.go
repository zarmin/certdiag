package tui

type fieldHelp struct {
	Body string
}

var fieldHelpMap = map[string]fieldHelp{
	"cn": {
		Body: `The primary identifier for the certificate subject.
For web servers, use the FQDN (e.g. example.com).
For internal or personal certs, use a descriptive name.
Not strictly needed if SANs cover all domains.`,
	},
	"org": {
		Body: `The legal name of the organization that owns the cert.
Optional for most use cases, required by some public CAs.
Example: My Corp Inc.`,
	},
	"country": {
		Body: `Two-letter ISO 3166-1 country code.
Example: US, DE, GB, JP.
Optional for self-signed certs, often required by public CAs.`,
	},
	"extra_dn": {
		Body: `Additional Distinguished Name fields beyond CN, O, C.
Format: KEY=Value,KEY=Value
Common fields: OU (Org Unit), L (Locality), ST (State/Province).
Example: OU=Engineering,L=New York,ST=New York`,
	},
	"sans": {
		Body: `DNS names, IPs, emails, or URIs the certificate is valid for.
Modern browsers require SANs -- CN alone is not enough.
Format: dns:example.com, ip:10.0.0.1, email:user@example.com
Multiple entries are separated by pressing Enter.`,
	},
	"algo": {
		Body: `RSA: widely compatible, larger keys (2048/4096 bits).
ECDSA: faster, smaller keys, modern (P-256/P-384/P-521).
Ed25519: fastest, smallest, not universally supported yet.`,
	},
	"size": {
		Body: `RSA key size in bits.
2048: minimum acceptable, good performance.
4096: higher security, slower operations.
Most CAs and browsers accept both.`,
	},
	"curve": {
		Body: `P-256: most widely supported, good default.
P-384: higher security, slightly larger.
P-521: highest security, rarely needed, slower.`,
	},
	"signing": {
		Body: `Self-signed: signs itself (for root CAs or testing).
Sign with CA: signed by an existing CA cert + key you provide.
Autosign: auto-find a matching CA in scanned files.`,
	},
	"cert_type": {
		Body: `Leaf: end-entity certificate (web server, client, email).
CA: certificate authority that can sign other certificates.
Choose CA only when building a PKI chain.`,
	},
	"days": {
		Body: `How many days the certificate will be valid.
Common values: 365 (1 year), 730 (2 years), 3650 (10 years for CAs).
Public web certs are limited to 397 days max by browsers.`,
	},
	"path_len": {
		Body: `Max depth of the CA chain below this CA certificate.
0 = can only sign leaf certs (no intermediate CAs).
1 = can sign one level of intermediate CAs.
Only relevant when certificate type is CA.`,
	},
	"format": {
		Body: `PEM: base64 text, most common on Linux/macOS.
DER: binary encoding, compact.
PKCS#12: binary bundle with cert+key+chain, password-protected.
PKCS#7: certificate-only bundle (no keys).
JKS: Java keystore, password-protected.`,
	},
	"encrypt": {
		Body: `Whether to encrypt the private key file with a password.
Recommended for keys stored on disk.
Required for PKCS#12 and JKS formats.
Unencrypted keys are easier to use but less secure.`,
	},
	"password": {
		Body: `Password for encrypting the output file or private key.
Used for PKCS#12, JKS, and encrypted PEM keys.
Choose a strong password for production keys.`,
	},
	"alias": {
		Body: `Entry name inside a Java keystore (JKS) or PKCS#12 file.
Used to identify specific entries when a keystore has multiple items.
Default alias is usually fine for single-entry files.`,
	},
	"include": {
		Body: `What to include in the converted output.
All: certificates and private keys.
Certificates only: skip private keys.
Keys only: skip certificates.`,
	},
	"auto_chain": {
		Body: `Reorder certificates in chain order: leaf first, root last.
Required by most TLS servers (Apache, Nginx, etc.).
If disabled, certificates are bundled in selection order.`,
	},
	"include_root": {
		Body: `Whether to include the root CA certificate in the bundle.
Most TLS configs exclude the root -- clients already have it.
Include it for PKCS#12 bundles or non-web use cases.`,
	},
	"legacy": {
		Body: `Use legacy encryption (3DES/RC2) for PKCS#12 files.
Needed for compatibility with older software:
Java < 17, Windows XP/7, OpenSSL < 3.0, macOS Keychain.
Modern systems support the default AES encryption.`,
	},
	"key_source": {
		Body: `Reuse existing: keep the same private key (same public key).
  Useful for key pinning or HPKP scenarios.
Generate new: create a fresh key pair.
  Recommended unless you have a reason to reuse.`,
	},
	"output_mode": {
		Body: `Individual files: separate .crt and .key files.
Bundle (PEM): single PEM file containing both cert and key.
Bundles are convenient but some servers need separate files.`,
	},
	"type_filter": {
		Body: `Filter which items to extract from the container file.
All: extract every certificate and key found.
Certificates only: skip private keys.
Keys only: skip certificates.`,
	},
	"new_password": {
		Body: `The new password to protect the file.
Used for PKCS#12 and JKS keystore formats.
Choose a strong password for production use.`,
	},
	"confirm_password": {
		Body: `Re-enter the new password to confirm.
Must match the password entered above exactly.`,
	},
	"items": {
		Body: `The certificates and keys selected for bundling.
Items are listed in selection order.
Enable "Order by chain" to auto-sort into chain order.`,
	},
	"proxy_listen": {
		Body: `Format: :PORT or ADDRESS:PORT
Examples: :8443, 0.0.0.0:8443, 127.0.0.1:8443
Ports below 1024 require root/sudo privileges.`,
	},
	"key_usage": {
		Body: `X.509 Key Usage flags for the certificate.
Left/Right navigates, Space toggles selection.
Leaf defaults: DigSig + KeyEnc.
CA defaults: CertSign + CRLSign.`,
	},
	"ext_key_usage": {
		Body: `Extended Key Usage purposes for the certificate.
Left/Right navigates, Space toggles selection.
Leaf defaults: Server + Client auth.
CAs typically have no EKU set.`,
	},
}
