# Remote endpoints

[README](../README.md) · [files and checks](files-and-checks.md) · remote · [trust](trust.md) ·
[create and convert](create-and-convert.md) · [pcap](pcap.md) · [TUI](tui.md) ·
[config](config.md) · [scripting](scripting.md)

Everything under `remote` opens a TLS connection to the named target, and nothing else: the chain
is never completed over the network unless `--aia` is given, so the verdict describes what a client
on this network sees. Targets are `host`, `host:port`, an IP, a bracketed IPv6 address, or an
`https://` or `tls://` URL. An `http://` target is a usage error.

```sh
certdiag example.com                                # bare target: same as remote fetch
certdiag remote fetch example.com
certdiag remote fetch example.com -d                # extended details
certdiag remote fetch example.com --save-chain -O ./out
certdiag remote fetch example.com --save-leaf --save-format der
certdiag remote fetch example.com --save-all        # one file per certificate
certdiag remote fetch a.example.com b.example.com --parallel 8
certdiag remote check example.com
certdiag remote check example.com --java --trust-file our-root.pem
certdiag remote check example.com --aia             # complete the chain over AIA (network)
certdiag remote probe example.com
certdiag remote http example.com --headers-only
certdiag remote http example.com --follow-redirects --header 'Accept: text/html'
printf 'GET / HTTP/1.0\r\n\r\n' | certdiag remote pipe example.com
```

`fetch` and `check` accept several targets and connect concurrently (`--parallel`, default 4). A
hostname that resolves to several addresses is checked at every one of them; `--single-ip` stops
after the first.

## Connection control

Shared by every subcommand and by `verify host:port`:

```sh
--tls-version tls1.0|tls1.1|tls1.2|tls1.3
--hostname NAME | --no-sni          # SNI override, or no SNI at all (mutually exclusive)
--alpn h2,http/1.1 | --alpn none
--starttls smtp|imap|pop3|ftp|ldap|mysql|postgres
--proxy socks5://host:port | http://host:port
--timeout 10s   -4 | -6   --single-ip
--client-cert / --client-key / --client-p12 / --client-jks / --client-alias / --client-password
```

Every connection has one attempt and a hard timeout. An unreachable host is a failed fetch with
exit `3`, never a hang.

## remote check

Runs the [local check suite](files-and-checks.md#checks) on the served chain and adds the
`remote` category: untrusted chain, hostname mismatch, incomplete chain, self-signed, no OCSP
staple, weak TLS version, weak cipher, no ALPN, SNI mismatch. `--category`, `--severity`,
`--strict`, `--expiry-warn` and `--revocation` work as on `check`.

Trust is evaluated against the OS store plus whatever store flags are given (`--java`,
`--java-home`, `--openssl`, `--mozilla`, `--chrome`, `--trust-file`), one verdict per store. A
served chain that stops at an intermediate but completes through a local store is reported as
completing through that store, not as incomplete.

## remote probe

Tries each TLS version and the cipher suites it can negotiate, and reports the features the server
offered. A cell that was not measured says "not probed" or "not applicable"; certdiag never prints
a value it did not observe. Probing older protocol versions uses a legacy TLS stack compiled into
the binary.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | ok |
| `1` | warnings (`remote check`), or a usage or runtime error |
| `2` | critical findings (`remote check`) |
| `3` | connection failure |
