# Development

Everything here runs from `certdiag_app/`. Requires Go 1.25 or newer and
[go-task](https://taskfile.dev); `make` is a thin proxy over `Taskfile.yml`.

## Build

```sh
make build      # -> dist/certdiag
make install    # -> /usr/local/bin/certdiag (linux, darwin)
make all        # every release platform -> dist/
make clean
make help       # every available target
```

Builds are `CGO_ENABLED=0` and stamp version, build date and git commit through `-ldflags`; they
surface in `certdiag version`. `make all` covers linux (amd64, 386, arm64, armv7), darwin (amd64,
arm64) and windows (amd64, 386, arm64). `make localtest` builds the smaller set used for local
multi-platform smoke testing.

## Test tiers

| Target | What it runs |
|---|---|
| `make test` | Go unit tests, through the harness formatter |
| `make extended-unit-test` | Go tests behind the `fulltest` build tag |
| `make cli-test` | CLI suite against the built binary, loopback TLS servers, no network |
| `make stress-test` | password-cache stress test |
| `make remote-docker-test` | suites against the Docker test infrastructure (`make testinfra-up`) |
| `make fulltest` | all of the above; `make fulltest-nodocker` without the Docker suites |

Add `race` as a modifier: `make test race`. The CLI suites are a Python harness in
`../tools/testing`: `cd ../tools/testing && python3 -m harness --phase cli --suite t01,t19`.

Rules the tests enforce, so a change that breaks them is a change to think about: every registered
flag is consumed by its command; every command with `-p` has `-P`; `x509.SystemCertPool` and a nil
`Roots` verify are forbidden in the library layers; store-load tests never read the real keychain,
JDKs or browser profiles; fixture dates are relative; nothing asserts on embedded bundle membership.

## Layout

```
cmd/            Cobra commands: flag binding, user interaction, exit codes
internal/
  cmdutil/      what commands share: config loading, key destination, flag helpers
  certops/      operations layer: Options struct -> function -> Result struct, no terminal I/O
  certlib/      core library: read, write, parse, scan, generate, check, revocation
    truststore/ OS, Java, OpenSSL, NSS and file trust stores; embedded root snapshots
  tui/          Bubble Tea interactive UI
  output/       list, table, json, yaml, jsonpath rendering
  config/       ~/.certdiag/certdiag.yaml
  password/     password sources and aggregation
  crypto/       AES-256-GCM + Argon2 for config password encryption
  opensslcmd/   --show-openssl equivalents
  pcapint/      pcap analysis integration
pkg/            reusable, certdiag-independent packages
  filepicker/   Bubble Tea file picker
  tableformat/  terminal tables with column priorities
  oscountry/    locale and timezone based country detection, no network
  packet_anal/  TLS, TCP, pcap, proxy and session analysis
tools/          mkbundle and mktables (dated tables), test fixtures generators
```

Layers go `cmd` -> `certops` -> `certlib` -> `pkg`. A command parses flags, builds an Options
struct, calls into `certops`, and renders the Result; `certops` never prompts and never writes to
the terminal. Anything under `pkg/` has no certdiag-specific dependencies.

The design notes that explain why things are the way they are live in `.claude/docs/`
(architecture, CLI, packages, trust engine, bundles).

## Platform

The project targets darwin, linux and windows. Platform-specific code lives behind build tags or
explicit runtime checks; no Unix-only assumption without a fallback.

## Dated tables

Some rules change on a calendar: `task update-bundles` refreshes the embedded Mozilla and Chrome
root snapshots, `task refresh-tables` the IANA TLS names and the CT log list,
`certlib/validity_schedule.go` carries the CA/Browser Forum leaf validity schedule. Each file names
its source and date. Refresh them before a release.

## Demo recordings

The README gifs in `docs/assets/` are recorded with [VHS](https://github.com/charmbracelet/vhs)
from the tapes in `demo/`.

```sh
brew install vhs        # or see the VHS README for other platforms
make demo               # record every tape into docs/assets/
make demo DEMO=check    # record one tape
make demo-fixtures      # rebuild the demo certificates without recording
```

`demo/fixtures.sh` builds a throwaway certificate set in `/tmp/certdiag-demo` (config in
`/tmp/certdiag-demo.yaml`) and every tape runs against it. Three details matter and are easy to
break:

- The fixtures live outside the repo, in a neutral path, because the detail view prints absolute
  paths and a recording must not show the operator's home directory.
- The tapes export `CERTDIAG_CONFIG` at the throwaway config, so a recording never picks up
  personal defaults from `~/.certdiag/certdiag.yaml`.
- Expiry findings are relative to the render date, so the fixtures are regenerated on every run:
  one certificate expires in 5 days, one in 20, one expired in 2023.

`old-api.example.com.crt` uses an RSA-1024 key generated by `openssl`, because certdiag refuses to
generate one that weak; that step is skipped when openssl is unavailable. `remote.tape` and
`tui-remote.tape` reach the network (`www.example.com`, `expired.badssl.com`); the rest are offline.
The TUI tapes end inside the TUI on purpose, so the last frame of the loop shows the result.
