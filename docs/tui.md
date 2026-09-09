# TUI

[README](../README.md) · [files and checks](files-and-checks.md) · [remote](remote.md) ·
[trust](trust.md) · [create and convert](create-and-convert.md) · [pcap](pcap.md) · TUI ·
[config](config.md) · [scripting](scripting.md)

```sh
certdiag tui                        # the current directory
certdiag tui ~/certs -r -D
certdiag tui store                  # the read-only trust store browser
certdiag tui store --group kind --trust-file our-root.pem
certdiag tui pcap capture.pcap
certdiag tui proxy -l :8443 -t backend:443
```

Needs a terminal of at least 80x22. The footer always shows the keys of the current view, trimmed
to one row; `?` opens a help overlay with the complete list. The scan and pcap views use the same
engine as the CLI, so what the TUI shows is what `certdiag` prints.

## Keys

Global: `Ctrl+C` quits anywhere. `q` quits from a tree and closes the pane, popup or overlay in
every other view. `Esc` undoes the most recent transient state (cancels a load, closes a popup,
cancels a search, closes a pane) and never quits. A focused text input receives `q` and
`Esc` as text and cancel respectively.

Tree view (files):

| Key | Does |
|---|---|
| `Enter` | full detail of the selection; `o` inside shows the openssl equivalent, `c` copies to the clipboard |
| `/` | search; the tree filters as you type and `Enter` keeps the filter. `Esc` while the search line is open drops the filter; to clear an applied filter press `/` and then `Esc` |
| `a` | actions for the selection: Renew, New Cert like this, New CSR like this, Convert, Extract, Change Password, Remove Passphrase, Sign |
| `n` | new key, certificate or CSR |
| `m` | multi-select: `Space` toggles, `a` auto-selects the chain of the selected certificate, `Enter` opens the bundle form, `d` diffs two, `Ctrl+D` deletes |
| `F` | functions: Cert Lister, Remote Fetch, Packet Analyzer, Trust Stores |
| `W` | run the checks on the tree |
| `C` | column editor; `O` options; `g` grouping; `z` fold; `w` wrap |
| `r` | rescan; `[` and `]` history back and forward |
| `!` | a shell in the current directory; the password cache is never exposed to it |

Remote result view: `c` runs the check suite on the served chain, `s` save chain, `S` save all, `A`
fetch missing issuers over AIA (network), `R` new remote target, `r` re-fetch.

Trust store view: `V` verify a file against the loaded stores, `d` details, `g` grouping, `E`
export, `r` reload. Trust store data is read-only everywhere: no action that writes is offered on a
store entry.

Forms: `Tab` and `Shift+Tab` move between fields, `Space` or `Enter` toggles radio and checkbox
fields, `Enter` on a file field opens the file picker, `F2` or `Alt+Enter` submits, `F1` help,
`Esc` cancels (with a confirm if something was typed).

## Bundles, passwords, columns

A `.p12` or `.jks` shows its entries as children of the file. Locked files appear locked; unlock
with a password and every password from any source (flags, config, environment, typed) joins a
session-wide cache that is tried against every other locked file.

Column choices and the options set with `O` are written back to the config file when you save
them; that is the only time the TUI writes the config. Columns: subject, issuer, expiry, algo,
valid_from, sans, usage, relations, trust, fingerprints.
