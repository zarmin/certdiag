# certdiag

A single static binary that **diagnoses X.509 certificates**: on disk, on the wire, in trust stores
and inside packet captures.

certdiag answers the questions that usually cost multiple minutes of `openssl` incantations:

- What is inside this directory of `.pem`, `.p12` and `.jks` files, and which signed which?
- Which of these expires next week, still uses SHA-1, or carries a 1024-bit key?
- Does this key belong to this cert? Is the chain complete and in the right order?
- Would **Java** trust this endpoint? Would **OpenSSL**? Would the **OS**? Which node behind the
  load balancer is still serving last year's certificate?
- What does my OS trust that Mozilla does not?
- What certificate did the server in this pcap actually present?

![certdiag: check a directory, verify a chain, browse it](docs/assets/demo-overview.gif)

> certdiag is a **diagnostic tool, not a certificate manager**. It computes everything fresh on every
> run, keeps no state, never modifies a system trust store, and touches the network only when a flag
> instructs it. It is built for hosts with no route to the internet. Altough for homelabs and small
> setups it can be used to quickly create self-signed root CAs and issue certificates.

## Install

Download the binary for your platform from the [releases page](../../releases) and put it on your
`PATH`. No cgo, no libpcap, no OpenSSL at runtime.

```sh
certdiag version
certdiag completion zsh > "${fpath[1]}/_certdiag"   # also bash, fish, powershell
certdiag config init                                # optional: a commented ~/.certdiag/certdiag.yaml
```

Nothing is written to your home directory unless you run `config init` or save options in the TUI.

macOS shows a Gatekeeper warning for an unsigned binary; `xattr -d com.apple.quarantine certdiag`
clears it. Windows SmartScreen does the same. Build from source: [DEVELOPMENT.md](DEVELOPMENT.md).

## What it can do?

### What is in this directory

```sh
certdiag ~/certs -r                                 # the inventory
certdiag ~/certs -r --trust                         # plus: does this machine trust each one
certdiag server.crt -D                              # one file, and everything related to it
```

Recursive scan, bundles opened and their entries listed. Relationships are worked out on the fly:
which cert signed which, which key belongs to which cert, which files are duplicates. `-D` pulls in
the siblings of a file so the relationship view has something to work with. Chains render in
issuance order, `->` means "signed":

```
root-ca.crt -> intermediate.crt -> server.crt
```

![scanning a directory](docs/assets/demo-scan.gif)

### Which one is about to break

```sh
certdiag check ~/certs -r
certdiag check ~/certs -r --severity critical
```

Exit `0` clean, `1` when the worst finding is a warning, `2` when anything is critical. It drops
straight into CI:

```yaml
- run: certdiag check ./deploy/certs -r --expiry-warn 45 --strict
```

Leaf validity limits follow the CA/Browser Forum schedule (SC-081) for the certificate's issue date,
so a 398-day certificate issued next year is flagged before a public CA would refuse it.

![health check with exit codes](docs/assets/demo-check.gif)

### But it works in curl

```sh
certdiag verify server.crt                          # the leaf, against the OS store
certdiag verify fullchain.pem                       # leaf plus intermediate
certdiag verify --java server.crt                   # would a JVM trust it?
certdiag verify --trust-file our-root.pem server.crt  # against a bundle of your own
```

The answer is usually a missing intermediate, or a root that ships with the OS but not with the JDK.
`verify` names which one. Verdicts use one vocabulary everywhere: `anchor`, `trusted`, `expired`,
`untrusted`, and `denied` when a store explicitly distrusts it.

![trust verification, leaf versus full chain](docs/assets/demo-verify.gif)

### What does this machine actually trust

```sh
certdiag store discover                             # every trust store on this machine
certdiag store --java                               # every JDK it can find
certdiag store diff mozilla os                      # what the OS trusts that Mozilla does not
certdiag store diff java:/opt/jdk-17 java:/opt/jdk-21
```

The Mozilla and Chrome root programs are compiled in as dated snapshots, so an air-gapped host always
has an answer. `store update` fetches newer ones on a connected machine; copy `~/.certdiag/bundles/`
across and the offline host uses them. Store reads are read-only on every platform.

![comparing trust stores](docs/assets/demo-store.gif)

### The live endpoint

```sh
certdiag example.com                                # no subcommand needed
certdiag remote check example.com                   # trust, hostname, chain, TLS hygiene
certdiag remote probe example.com                   # which versions and ciphers it accepts (slow)
certdiag remote fetch mail.example.com:587 --starttls smtp --save-chain -O ./out
```

A hostname that resolves to five addresses is checked at all five. The verdict describes what a client
on *this* network sees: certdiag never completes the chain on the server's behalf unless you pass
`--aia`. A chain that completes through your local store is reported as such, not as incomplete.

![checking a live endpoint](docs/assets/demo-remote.gif)

### The certificate inside a capture

```sh
certdiag pcap check capture.pcap
certdiag pcap check capture.pcap --keylog keys.txt
```

TLS 1.3 encrypts the Certificate message, so a passive capture cannot show it. certdiag says so
instead of showing nothing, and decrypts once you hand it an `SSLKEYLOGFILE`.

![pulling a certificate out of a TLS 1.3 capture](docs/assets/demo-pcap.gif)

### A small CA for the homelab

```sh
certdiag create-cert --ca --subject 'CN=Home Root CA' --days 3650 --with-key --key-output root.key -o root.crt
certdiag create-cert --subject 'CN=nas.home.lan' --san 'DNS:nas.home.lan,IP:192.168.1.10' \
  --with-key --key-output nas.key --sign-ca root.crt --sign-key root.key -o nas.crt
certdiag renew nas.crt --new-key --key-output nas-new.key
certdiag bundle nas.crt root.crt nas.key -o nas.p12 -f pkcs12 --output-password changeit
```

Every command that writes a key puts it next to `-o`, never overwrites without asking, and prints the
equivalent `openssl` invocation on `--show-openssl`. `--template old.crt` clones subject, SANs and
extensions from an existing certificate.

### All of it, interactively

```sh
certdiag tui ~/certs
certdiag tui store                                  # the read-only trust store browser
```

One tree of everything found, bundles expanded inline. `C` opens the column editor: SANs, key
usage, relations, inline warnings, trust verdicts, fingerprints; the tree follows as you toggle, and
`z` folds the bundles. Column choices are saved to the config when you ask.

![the lister and its column editor](docs/assets/demo-tui-lister.gif)

`Enter` for full detail, `/` to search, `a` for the actions that make sense on the selection, `?`
for every key. A keystore password typed once is tried against every other locked file for the rest
of the session. Here: find the expired certificate and renew it with a fresh key, signed by the CA
found next to it.

![browsing and renewing](docs/assets/demo-tui-browse.gif)

`m` multi-selects. Pick the leaf, its key and the intermediate, `Enter`, choose PEM, PKCS#12, PKCS#7
or JKS, and the bundle is written and shows up in the tree:

![building a bundle from several files](docs/assets/demo-tui-bundle.gif)

`F` opens the other tools: remote fetch, packet analyzer, trust store browser. A fetched chain is a
tree like any other, with detail, the check suite, save chain and AIA fetch one key away:

![fetching a remote chain](docs/assets/demo-tui-remote.gif)

## What talks to the network

Nothing, unless one of these is on the command line. Every outbound call has a short hard timeout and
a single attempt; an unreachable host is reported as a failed fetch, never as a hang.

| Command or flag | Who is contacted | What they learn |
|---|---|---|
| `remote *`, `verify host:port` | the named target | that you connected |
| `--aia`, `aia cache` | the issuing CA's AIA URL | which certificate you hold |
| `--revocation` | the CA's OCSP responder or CRL host | which certificate you are checking, now |
| `store update` | Mozilla and Chromium root-store hosts | nothing about you |

`--crl-file` is offline. There is no telemetry and no update check. Passwords never appear in
`--show-openssl` output or in the TUI shell popup; a `-p` on the command line does land in your shell
history, `-P passwords.txt` does not.

## Platform matrix

| | Linux | macOS | Windows |
|---|---|---|---|
| Files, checks, create/convert, pcap files, TUI | yes | yes | yes |
| OS trust store | CA bundles | Keychains (read-only) | ROOT store (read-only) |
| Java, OpenSSL, NSS (Firefox) stores, Mozilla and Chrome snapshots | yes | yes | yes |
| Live capture (`pcap live`) | yes, AF_PACKET | no | no |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | ok |
| `1` | usage, config or runtime error; warnings on `check` and `remote check`; "differ" on `diff` and `store diff` |
| `2` | critical findings on `check` and `remote check`; error on `diff` and `store diff` |
| `3` | connection failure on `remote *` |

## Everything else

`certdiag --manual` prints the full command tree with every flag through your pager. The longer
reads live in [docs/](docs/):

- [Files and checks](docs/files-and-checks.md): scan, relationships, `-D` discovery, every check
  with its severity, revocation
- [Remote endpoints](docs/remote.md): fetch, check, probe, http, pipe, STARTTLS, proxies, client
  certificates
- [Trust stores](docs/trust.md): `store`, `verify`, `store diff`, `store update`, the trust
  vocabulary, root snapshots, the AIA cache
- [Creating and converting](docs/create-and-convert.md): keys, certs, CSRs, signing, renewal,
  templates, bundles, PKCS#12 and JKS, `--show-openssl`
- [Captures](docs/pcap.md): pcap, live capture, the TLS proxy, key logs per stack
- [TUI](docs/tui.md): views, keys, column editor, password cache
- [Passwords and configuration](docs/config.md): password sources, encrypted config passwords,
  `config init`, `~/.certdiag/certdiag.yaml`, environment variables
- [Scripting](docs/scripting.md): `-o json|yaml|jsonpath`, schemas

## License

Apache-2.0. See [LICENSE](LICENSE).
