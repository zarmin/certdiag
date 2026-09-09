# Scripting

[README](../README.md) · [files and checks](files-and-checks.md) · [remote](remote.md) ·
[trust](trust.md) · [create and convert](create-and-convert.md) · [pcap](pcap.md) · [TUI](tui.md) ·
[config](config.md) · scripting

```sh
certdiag ~/certs -o json
certdiag ~/certs -o yaml
certdiag ~/certs -o 'jsonpath={.files[*].items[*].certificate.subject}'
certdiag check ~/certs -o json | jq '.issues[] | select(.severity=="critical")'
certdiag remote check example.com -o json
certdiag store --java -o json
certdiag store diff os java -o json
certdiag verify server.crt -o yaml
certdiag proxy -l :8443 -t backend:443 --ndjson
```

`-o` accepts `list`, `table`, `yaml`, `json` and `jsonpath=EXPR` on scans and `store`, and `human`,
`json`, `yaml` on `check`, `verify`, `diff`, `store diff` and `remote`. Colours switch off on piped
output and under `NO_COLOR`.

Contract: collections in JSON and YAML are never `null`, they start empty. Fingerprints in JSON
and YAML are canonical lowercase hex regardless of `--fingerprint-format`, which only affects human
output. Trust verdicts use the [one vocabulary](trust.md#verdicts).

```sh
certdiag schema             # scan output schema
certdiag schema --remote    # remote inspection output
certdiag schema --config    # the config file
```

All schemas are JSON Schema Draft 2020-12.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | ok; `diff` and `store diff` found no differences |
| `1` | usage, config or runtime error on every command; warnings on `check` and `remote check`; `diff` and `store diff` found differences |
| `2` | critical findings on `check` and `remote check`; error on `diff` and `store diff` |
| `3` | connection failure on `remote *` (`verify host:port` exits `1`) |

A CI step that fails on any finding:

```yaml
- run: certdiag check ./deploy/certs -r --expiry-warn 45 --strict
- run: certdiag remote check api.example.com --strict --java
```
