# Passwords and configuration

[README](../README.md) · [files and checks](files-and-checks.md) · [remote](remote.md) ·
[trust](trust.md) · [create and convert](create-and-convert.md) · [pcap](pcap.md) · [TUI](tui.md) ·
config · [scripting](scripting.md)

## Passwords

certdiag pools every password it can find and tries them against every encrypted file in a scan.
This is the difference between one command and twenty.

| Source | How |
|---|---|
| CLI | `-p secret` (repeatable) |
| Password file | `-P passwords.txt`, one per line (repeatable); every command with `-p` has it |
| Config, per file | `passwords.by_filename` entries, glob or exact path |
| Config, shared | `passwords.common_plaintext`, `passwords.common_encrypted` |
| Environment | any `CERTDIAG_PASSWORD_*` variable |
| Built in | `changeit`, tried last |
| Interactive | `-i` prompts when everything else fails |

Order per file: filename matches, then CLI flags, then common entries, then environment, then the
built-in default. `--no-try-all-passwords` restricts it to filename matches only, for when a wrong
attempt is itself a problem (a store that counts failures). In the TUI, all of these plus anything
typed during the session form a session-wide cache.

A `-p` on the command line lands in your shell history and is visible in the process list; a
password file does not. Passwords never appear in `--show-openssl` output, in the TUI shell popup,
or in `config show`.

Config passwords can be encrypted with AES-256-GCM behind an Argon2 key derivation:

```sh
certdiag password encrypt --master-password KEY -p PW      # paste the blob into the config
echo PW | CERTDIAG_MASTER_KEY=KEY certdiag password encrypt
certdiag password decrypt --master-password KEY
certdiag password change-master-key                        # re-encrypts every entry
```

The master password comes from `--master-password`, `CERTDIAG_MASTER_KEY` or a prompt.

## The config file

`~/.certdiag/certdiag.yaml`, with root CA snapshots installed by `store update` next to it in
`~/.certdiag/bundles/`. Nothing in it is required and no command creates it on its own: a
diagnostic run leaves your home directory alone.

```sh
certdiag config init                  # write the commented example; --force to replace
certdiag config path                  # the path in effect and whether it exists
certdiag config show                  # resolved settings, passwords redacted
certdiag config migrate               # move a legacy ~/.certdiag.yaml; --dry-run to preview
certdiag -c ./project.yaml ~/certs    # or CERTDIAG_CONFIG=./project.yaml
certdiag schema --config              # JSON Schema for the file
```

A legacy `~/.certdiag.yaml` keeps working as a fallback and is moved only by `config migrate`. A
config that cannot be parsed is fatal on every command.

```yaml
kind: certdiag-config
version: "1"

defaults:
  key:      { algorithm: ecdsa, rsa_key_size: 2048, ecdsa_curve: p256 }
  cert:     { days: 365, ca_days: 3650 }
  subject:  { organization: "", country: "" }
  output:   { format: pem, overwrite_confirm: true, fingerprint_format: hex }
  keystore: { pkcs12_algorithm: modern }
  check:    { expiry_warn_days: 30, expiry_critical_days: 7, disabled_checks: [] }
  remote:   { timeout: 10s, parallel: 4, proxy: "" }
  aia:      { cache: false }
  tui:
    recursive: false
    max_depth: 0
    file_signature_scan: false
    auto_discover: false
    path_display: filename          # filename, relative, absolute
    columns: [subject, issuer, expiry, algo]

passwords:
  common_plaintext: [password123]
  common_encrypted: ["base64encryptedblob=="]
  by_filename:
    - filename: "*.p12"
      plaintext_password: p12password
    - filepath: /etc/ssl/private/server.p12
      encrypted_password: "base64encryptedblob=="
```

## Environment variables

| Variable | Effect |
|---|---|
| `CERTDIAG_CONFIG` | config file path |
| `CERTDIAG_MASTER_KEY` | master password for encrypted config passwords |
| `CERTDIAG_NEW_MASTER_KEY` | the new master password for `password change-master-key` |
| `CERTDIAG_PASSWORD_*` | any such variable becomes an available password |
| `CERTDIAG_SHELL` | the shell for the TUI `!` popup |
| `SSLKEYLOGFILE` | default key log for `pcap` TLS 1.3 decryption |
| `NO_COLOR` | disable coloured output (so does `--no-color`) |
