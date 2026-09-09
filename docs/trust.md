# Trust stores

[README](../README.md) · [files and checks](files-and-checks.md) · [remote](remote.md) · trust ·
[create and convert](create-and-convert.md) · [pcap](pcap.md) · [TUI](tui.md) ·
[config](config.md) · [scripting](scripting.md)

`check` asks whether a certificate is healthy. `verify` asks whether one specific store trusts it.
Different questions.

## Which stores

| Flag | Store |
|---|---|
| (none) | the OS store: macOS keychains, Windows ROOT and disallowed stores, Linux CA bundles |
| `--java`, `--java-home DIR` | every JDK `cacerts` certdiag can find, or one JDK |
| `--openssl` | the OpenSSL default bundle |
| `--nss` | browser profile databases (Firefox, Thunderbird, Chrome on Linux); `store` only |
| `--mozilla`, `--chrome` | the shipped Mozilla and Chrome root snapshots |
| `--trust-file FILE` | any CA bundle: PEM, JKS or PKCS#12 |

On `store` the flag selects the one store to list (`-f` is short for `--trust-file`). On `verify`,
`remote check` and `remote fetch` the flags add stores on top of the OS store and every store gets
its own verdict. Every store read is read-only, on every platform.

```sh
certdiag store                                  # OS store
certdiag store --java -q DigiCert -o table
certdiag store --mozilla -d
certdiag store discover                         # inventory of every store on this machine
certdiag store diff os java                     # what differs, by fingerprint
certdiag store diff java:/opt/jdk17 java:/opt/jdk21
certdiag store diff os mozilla
certdiag store diff os /mnt/image/etc/ssl/certs/ca-certificates.crt
```

`store diff` specs are `os`, `java`, `java:<home>`, `openssl`, `nss`, `mozilla`, `chrome`,
`file:<path>` or a bare path. It reports certificates present on one side only and "rotated" roots
(same subject, different certificate). Exit `0` identical, `1` differ, `2` error.

## verify

```sh
certdiag verify server.crt                      # leaf, against the OS store
certdiag verify fullchain.pem                   # leaf plus intermediates
certdiag verify --java server.crt
certdiag verify --trust-file our-root.pem server.crt
certdiag verify example.com:443                 # a live endpoint
certdiag verify --java https://example.com
```

The spelling of the argument decides what it is: `host:port` or a URL is dialed, anything else is
a file, and a bare name is never dialed. The remote form takes the same
[connection flags](remote.md#connection-control) as `remote`.

## Verdicts

One vocabulary everywhere, in the CLI, JSON and the TUI TRUST column:

| Verdict | Meaning |
|---|---|
| `anchor` | the certificate itself is in the store |
| `trusted` | chains to an anchor in the store |
| `expired` | chains to an anchor, but something on the path is outside its validity |
| `untrusted` | no path to an anchor |
| `denied` | the store explicitly distrusts it; beats every other verdict |

A cross-signed copy of a store anchor (same subject and key) is `trusted` through that anchor.
Verdicts are computed fresh against the store contents on every run; nothing is cached.

## Root CA snapshots

The Mozilla and Chrome root programs are compiled into the binary as dated snapshots built from the
vendors' published source data (NSS `certdata.txt`, MPL-2.0; Chromium `chrome_root_store`,
BSD-3-Clause). They are snapshots, not a live view of a browser, and the date is shown wherever one
is used. certdiag does not, and cannot, read the root list out of an installed browser; `--nss`
reads what a profile on this machine has added or overridden.

```sh
certdiag version                                # snapshot dates
certdiag store update --status
certdiag store update                           # network: refresh from the vendors
certdiag store update --dry-run
certdiag store update --import /media/usb/bundles   # air-gapped host
```

A refreshed snapshot is installed under `~/.certdiag/bundles/` and takes precedence over the
compiled-in one. `store update` is the only command that contacts the vendor hosts, and only when
`--import` and `--from` are absent.

## AIA

`--aia` on a scan, `check`, `remote fetch` or `remote check` fetches missing issuer certificates
from the URL in the certificate's Authority Information Access extension. It is opt-in everywhere:
the fetch tells the CA which certificate you hold, and a verdict with `--aia` no longer describes
what an offline client sees. Fetched certificates are attributed to the target that needed them.

A cache of fetched issuer certificates can be enabled with `defaults.aia.cache` in the config. It
stores certificates, never verdicts: a cached certificate is signature-checked again on every use.

```sh
certdiag aia cache list
certdiag aia cache clear
certdiag check server.crt --aia --aia-refresh   # ignore the cache for this run
```
