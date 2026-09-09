# Creating and converting

[README](../README.md) · [files and checks](files-and-checks.md) · [remote](remote.md) ·
[trust](trust.md) · create and convert · [pcap](pcap.md) · [TUI](tui.md) ·
[config](config.md) · [scripting](scripting.md)

Every command here writes files. Nothing is overwritten without confirmation unless `--no-confirm`
is given. A command that generates a private key writes it next to `-o` as `<name>.key`, never
overwriting an existing key, or prints both PEM blocks to stdout when there is no `-o`. Generated
keys are written with mode 0600.

`--show-openssl` on any of these prints the equivalent openssl invocation next to the work it did;
`--dry-run` prints the command and does nothing else.

## Keys

```sh
certdiag create-key                                     # ECDSA P-256 to stdout
certdiag create-key -a rsa -s 4096 -o key.pem           # rsa, ecdsa (--curve p256|p384|p521), ed25519
certdiag create-key -a ed25519 -o ed.key
certdiag create-key --encrypt-key -p secret -o key.pem  # or -P passwords.txt
certdiag create-key -f der -o key.der
```

Defaults come from `defaults.key` in the [config](config.md). certdiag refuses to generate RSA
keys shorter than 2048 bits.

## Certificates and a small CA

```sh
# a root CA
certdiag create-cert --ca --subject 'CN=Home Root CA,O=Home' --days 3650 \
  --with-key --key-output root.key -o root.crt

# an issuing CA, constrained to one level and one domain
certdiag create-cert --ca --path-length 0 --permitted-names 'DNS:home.lan' \
  --subject 'CN=Home Issuing CA' --days 1825 \
  --with-key --key-output issuing.key --sign-ca root.crt --sign-key root.key -o issuing.crt

# a leaf
certdiag create-cert --subject 'CN=nas.home.lan' --san 'DNS:nas.home.lan,IP:192.168.1.10' \
  --with-key --key-output nas.key --sign-ca issuing.crt --sign-key issuing.key -o nas.crt

# a leaf, finding the CA in the working directory
certdiag create-cert --subject 'CN=nas.home.lan' --with-key --autosign -o nas.crt

# self-signed
certdiag create-cert --subject 'CN=dev.local' --with-key -o dev.crt
```

Useful flags: `--key-usage`, `--ext-key-usage` (`serverAuth,clientAuth,...`), `--not-before`,
`--serial`, `--excluded-names`, `-k existing.key` instead of `--with-key`, `-f der`.

### Templates

`--template old.crt` clones subject, SANs and extensions from an existing certificate; flags given
on the command line win. `--template-profile` loads them from YAML:

```sh
certdiag templates cert > leaf.yaml             # also: ca, csr
certdiag templates cert --from server.crt > server-profile.yaml
certdiag templates csr --from ca.crt > csr-from-ca.yaml
certdiag create-cert --with-key --template-profile leaf.yaml -o new.crt --key-output new.key
```

## CSRs and signing

```sh
certdiag create-csr --with-key --subject 'CN=web' --san 'DNS:web.local' -o web.csr --key-output web.key
certdiag create-csr -k existing.key --template old-server.crt -o web.csr
certdiag sign web.csr --ca-cert issuing.crt --ca-key issuing.key -o web.crt
certdiag sign web.csr --ca-cert root.crt --ca-key root.key --ca --path-length 0 -o sub-ca.crt
certdiag sign web.csr --autosign --days 730 -o web.crt
```

## Renewal

```sh
certdiag renew server.crt                               # -> server-renewed.crt, same key
certdiag renew server.crt --new-key --key-output server-new.key -o server-new.crt
certdiag renew server.crt --days 730 --sign-ca issuing.crt --sign-key issuing.key
certdiag renew server.crt --autosign
certdiag renew root.crt --days 3650                     # self-signed stays self-signed
```

Subject, SANs, key usage and the other extensions are preserved; serial and validity are new. The
original key is discovered from the same file or a sibling unless `--new-key` or `-k` says
otherwise.

## Bundles

```sh
certdiag bundle server.crt issuing.crt -o chain.pem
certdiag bundle server.crt server.key issuing.crt root.crt --auto-chain -o fullchain.pem
certdiag bundle server.crt server.key issuing.crt -o server.p12 -f pkcs12 --output-password secret --alias server
certdiag bundle root.crt issuing.crt -o truststore.jks -f jks --output-password changeit
certdiag bundle server.crt issuing.crt -o chain.p7b
certdiag bundle --auto-assemble ./certs -o server.p12 --output-password secret
```

`--auto-chain` orders the certificates leaf first; `--include-root=false` drops the root, which
is what a TLS server bundle usually wants. `--auto-assemble DIR` finds a leaf, its key and its
chain in a directory by itself. `--legacy-pkcs12` writes the older PKCS#12 algorithms for consumers
that cannot read a modern file.

## Converting, extracting, re-encrypting

```sh
certdiag convert server.crt -o server.der               # format from the extension, or -f
certdiag convert server.pem -o server.p12 -f pkcs12 --output-password secret
certdiag convert bundle.p12 -p secret -o certs.pem --include certs    # certs|keys|all
certdiag convert keystore.jks -p secret -o keystore.p12 --output-password secret

certdiag extract bundle.p12 -p secret --output-dir ./out
certdiag extract bundle.p12 -p secret --naming '{subject}-{type}'    # {filename} {index} {type} {alias} {subject} {format}
certdiag extract keystore.jks -p changeit --alias server -o server.pem
certdiag extract bundle.pem --type certs --index 2 -o second.crt

certdiag reencrypt server.p12 -p old --new-password new
certdiag reencrypt server.p12 -p old --remove-password
certdiag reencrypt keystore.jks -p store --entry mykey --new-password newkeypass
certdiag reencrypt key.pem -p old --new-password new -o key-new.pem
```

Without `-o`, `reencrypt` rewrites the file in place. Input passwords for any of these can also
come from `-P passwords.txt`.
