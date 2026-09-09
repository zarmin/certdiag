# Files and checks

[README](../README.md) · files and checks · [remote](remote.md) · [trust](trust.md) ·
[create and convert](create-and-convert.md) · [pcap](pcap.md) · [TUI](tui.md) ·
[config](config.md) · [scripting](scripting.md)

## Reading files

```sh
certdiag server.crt                  # one file
certdiag server.crt -d               # fingerprints, key IDs, AIA, CRL, extensions
certdiag server.crt -dd              # plus PEM and full DNs
certdiag server.key -d --insecure-details    # also print private key material
certdiag ~/certs -r --depth 2        # bounded recursion
certdiag ~/certs -r -t               # table instead of list
certdiag ~/certs -D                  # pull in related files next to each hit
certdiag ~/certs -q digicert         # filter: filename, subject, issuer, SANs, serial
certdiag ~/certs --check             # inline health warnings per item
certdiag ~/certs --trust             # does this machine trust each certificate
certdiag ~/certs --file-signature-scan       # identify by magic bytes, not extension
certdiag ~/certs --no-relationships  # flat list
certdiag ~/certs --fingerprint-format hex-colon
```

`list` is an alias for the root command. Reads PEM, DER, PKCS#12, PKCS#7 and JKS, including
per-entry aliases and per-entry key passwords. Bundles are opened and their entries listed.

Relationships are computed on every run: which certificate signed which, which key belongs to
which certificate, which files hold the same certificate. Chains render in issuance order and `->`
means "signed":

```
root-ca.crt -> intermediate.crt -> server.crt
```

`-D` / `--discover` is the one to remember: given `server.crt` it pulls in the sibling `server.key`
and `chain.pem`, so the relationship view has something to work with.

`--trust` and `--aia` load the trust stores; nothing trust-related is read unless one of them is
given. `--aia` fetches missing issuers over the network and implies `--trust`.

What a scan could not read is reported, never hidden. Unreadable and locked files appear in a
"skipped" list with the reason.

### Comparing two certificates

```sh
certdiag diff old.crt new.crt
certdiag diff old.crt new.crt --only-changes
certdiag diff bundle.p12 new.crt --index 2:1 -p secret   # item 2 of the first file
```

Exit `0` identical, `1` differ, `2` error.

## Checks

```sh
certdiag check ~/certs -r
certdiag check --list-checks                       # every check, ID, category, severity
certdiag check ~/certs --category expiry,key_strength
certdiag check ~/certs --severity critical
certdiag check ~/certs --expiry-warn 60 --expiry-critical 14
certdiag check ~/certs --strict                    # any warning fails
certdiag check ~/certs --trust                     # add the trust checks
certdiag check ~/certs -o json
```

Exit `0` clean, `1` warnings, `2` critical. `--severity` filters what is shown and what counts.

| Category | Checks |
|---|---|
| `expiry` | `expired`, `expiring_soon_critical`, `expiring_soon_warning`, `not_yet_valid` |
| `key_strength` | `very_weak_rsa` (under 1024, critical), `weak_rsa` (under 2048), `weak_ec_curve`, `rsa_exponent`, `deprecated_key` (DSA) |
| `algorithm` | `md5_sig` (critical), `sha1_sig`, `sig_mismatch` |
| `chain` | `chain_incomplete`, `chain_order`, `key_cert_mismatch`, `path_length_violation` (critical), `name_constraints_violation` (critical) |
| `config` | `unprotected_key`, `empty_password`, `entry_password_mismatch`, `missing_sans`, `ca_no_keyusage`, `ca_no_bc`, `leaf_certsign`, `ip_in_cn` |
| `structure` | `serial`, `version`, `unknown_ext`, `long_validity`, `precert_as_cert`, `netscape_type_conflict`, `name_constraints_on_root` |
| `trust` | `untrusted_chain`, `distrusted_root` (critical); only with `--trust` |
| `revocation` | `revocation_revoked` (critical), `revocation_undetermined`, `revocation_unverified`; only with `--revocation` or `--crl-file` |
| `info` | `self_signed_leaf`, `wildcard` |

`long_validity` follows the CA/Browser Forum schedule (ballot SC-081): the allowed leaf lifetime
depends on the issue date, and the limit shrinks in steps through 2029. The schedule lives in one
file in the source with its date and source.

Checks you never want to hear about go in `defaults.check.disabled_checks` in the
[config file](config.md).

### Revocation

Revocation is opt-in and uses the network, except `--crl-file`:

```sh
certdiag check server.crt --revocation                      # stapled OCSP -> live OCSP -> CRL
certdiag check server.crt --revocation --revocation-method ocsp
certdiag check server.crt --crl-file ca.crl                 # offline, local CRL, never fetches
certdiag check server.crt --revocation --revocation-require # undetermined becomes critical
```

Status is tri-state: `good`, `revoked` (critical), `undetermined` (warning). A live OCSP query
tells the issuing CA that you are looking at this certificate, right now. That is why it is never
on by default.

## Passwords

Every command that reads encrypted files takes `-p` (repeatable) and `-P passwords.txt` (one
password per line, repeatable). A scan tries every known password against every locked file:
filename matches from the config first, then `-p`, then the common config entries, then
`CERTDIAG_PASSWORD_*` environment variables, then the built-in `changeit`. `--no-try-all-passwords`
restricts it to filename matches only, for when a wrong-password attempt is itself a problem. `-i`
prompts when everything else fails. Details in [config](config.md).
