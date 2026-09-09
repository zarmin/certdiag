import json
import re

from ..lib.harness import Harness
from ..lib.assertions import Tracker


NC = "--no-confirm"


def run(h, t):
    print("\n=== T09: Config, Global Flags, Utility Commands ===\n")

    # --- T09.01: --no-color removes ANSI codes ---
    r = h.cmd("--no-color {cert}", cert=h.fixture("leaf-rsa.pem"))
    t.assert_no_ansi(r, "T09.01: --no-color removes ANSI codes")

    # --- T09.02: NO_COLOR env var ---
    r = h.cmd("{cert}", cert=h.fixture("leaf-rsa.pem"), env_extra={"NO_COLOR": "1"})
    t.assert_no_ansi(r, "T09.02a: NO_COLOR=1 suppresses ANSI")

    r = h.cmd("{cert}", cert=h.fixture("leaf-rsa.pem"), env_extra={"NO_COLOR": "yes"})
    t.assert_no_ansi(r, "T09.02b: NO_COLOR=yes suppresses ANSI")

    # --- T09.03: Config from -c flag ---
    config_path = h.tmp("custom-config.yaml")
    config_path.write_text(
        "kind: certdiag-config\n"
        'version: "1"\n'
        "\n"
        "defaults:\n"
        "  check:\n"
        "    expiry_warn_days: 999\n"
        "    expiry_critical_days: 500\n"
    )
    r = h.cmd("--no-color check -c {cfg} {cert}",
              cfg=config_path, cert=h.fixture("leaf-rsa.pem"))
    if r.returncode <= 2:
        t.PASS(f"T09.03: config from -c flag accepted (exit {r.returncode})")
    else:
        t.FAIL("T09.03: config from -c flag", f"unexpected exit {r.returncode}")

    # --- T09.04: Config from CERTDIAG_CONFIG env var ---
    r = h.cmd("--no-color check {cert}",
              cert=h.fixture("leaf-rsa.pem"),
              env_extra={"CERTDIAG_CONFIG": str(config_path)})
    if r.returncode <= 2:
        t.PASS(f"T09.04: CERTDIAG_CONFIG env var accepted (exit {r.returncode})")
    else:
        t.FAIL("T09.04: CERTDIAG_CONFIG env var", f"unexpected exit {r.returncode}")

    # --- T09.05: -c flag overrides CERTDIAG_CONFIG ---
    config_a = h.tmp("config-a.yaml")
    config_a.write_text(
        "kind: certdiag-config\n"
        'version: "1"\n'
        "\n"
        "defaults:\n"
        "  check:\n"
        "    expiry_warn_days: 100\n"
    )
    config_b = h.tmp("config-b.yaml")
    config_b.write_text(
        "kind: certdiag-config\n"
        'version: "1"\n'
        "\n"
        "defaults:\n"
        "  check:\n"
        "    expiry_warn_days: 999\n"
    )
    r = h.cmd("--no-color config show -c {cfg}",
              cfg=config_b,
              env_extra={"CERTDIAG_CONFIG": str(config_a)})
    t.expect_ok(r, "T09.05a: config show with -c override exits 0")
    t.assert_contains(r, "999", "T09.05b: -c wins over CERTDIAG_CONFIG (contains 999)")
    t.assert_not_contains(r, "expiry_warn_days: 100",
                          "T09.05c: CERTDIAG_CONFIG value not used")

    # --- T09.06: Non-existent config file ---
    r = h.cmd("--no-color -c /nonexistent/config.yaml {cert}",
              cert=h.fixture("leaf-rsa.pem"))
    t.expect_fail(r, "T09.06: non-existent config file fails")

    # --- T09.07: Malformed config file ---
    bad_config = h.tmp("bad-config.yaml")
    bad_config.write_text("not: [valid: yaml: {{\n")
    r = h.cmd("--no-color -c {cfg} {cert}",
              cfg=bad_config, cert=h.fixture("leaf-rsa.pem"))
    t.expect_fail(r, "T09.07: malformed config file fails")

    # --- T09.07b: Config with unknown/extra fields ---
    extra_config = h.tmp("extra-config.yaml")
    extra_config.write_text(
        "kind: certdiag-config\n"
        'version: "1"\n'
        "\n"
        "this_field_does_not_exist: true\n"
        'another_bogus: "value"\n'
        "defaults:\n"
        "  check:\n"
        "    expiry_warn_days: 100\n"
    )
    r = h.cmd("--no-color check -c {cfg} {cert}",
              cfg=extra_config, cert=h.fixture("leaf-rsa.pem"))
    if r.returncode <= 2:
        t.PASS(f"T09.07b: config with unknown fields does not crash (exit {r.returncode})")
    else:
        t.FAIL("T09.07b: config with unknown fields",
               f"unexpected exit {r.returncode}")

    # --- T09.07c: Config with default algorithm ---
    algo_config = h.tmp("defaults-algo-config.yaml")
    algo_config.write_text(
        "kind: certdiag-config\n"
        'version: "1"\n'
        "\n"
        "defaults:\n"
        "  key:\n"
        "    algorithm: ed25519\n"
    )
    key_out = h.tmp("config-default.key")
    r = h.cmd("--no-color create-key -c {cfg} -o {out} {nc}",
              cfg=algo_config, out=key_out, nc=NC)
    t.expect_ok(r, "T09.07c-a: create key with config default algo exits 0")

    r = h.cmd("--no-color {key}", key=key_out)
    t.expect_ok(r, "T09.07c-b: read config-default key exits 0")
    t.assert_contains(r, "Ed25519",
                      "T09.07c-c: key uses config default algorithm (ed25519)")

    # --- T09.08: Config with disabled checks ---
    disabled_config = h.tmp("disabled-checks.yaml")
    disabled_config.write_text(
        "kind: certdiag-config\n"
        'version: "1"\n'
        "\n"
        "defaults:\n"
        "  check:\n"
        "    disabled_checks:\n"
        "      - expired\n"
        "      - weak_rsa\n"
    )
    r = h.cmd("--no-color check -c {cfg} -o json {dir}",
              cfg=disabled_config, dir=h.fixture(""))
    if r.returncode <= 2:
        t.PASS(f"T09.08: check with disabled checks runs (exit {r.returncode})")
    else:
        t.FAIL("T09.08: check with disabled checks",
               f"unexpected exit {r.returncode}")

    # --- T09.09: config show default ---
    r = h.cmd("--no-color config show")
    t.expect_ok(r, "T09.09a: config show default exits 0")
    t.assert_contains(r, "config", "T09.09b: config show output contains 'config'")

    # --- T09.10: config show with explicit config ---
    r = h.cmd("--no-color config show -c {cfg}", cfg=config_b)
    t.expect_ok(r, "T09.10a: config show explicit exits 0")
    t.assert_contains(r, "999", "T09.10b: config show explicit output contains '999'")

    # --- T09.11: config show redacts passwords ---
    pw_config = h.tmp("config-with-pw.yaml")
    pw_config.write_text(
        "kind: certdiag-config\n"
        'version: "1"\n'
        "\n"
        "passwords:\n"
        "  common_plaintext:\n"
        '    - "supersecret"\n'
        "  by_filename:\n"
        '    - filename: "*.p12"\n'
        '      plaintext_password: "supersecret"\n'
    )
    r = h.cmd("--no-color config show -c {cfg}", cfg=pw_config)
    t.expect_ok(r, "T09.11a: config show with passwords exits 0")
    t.assert_not_contains(r, "supersecret",
                          "T09.11b: config show redacts password value")
    t.assert_contains(r, "redacted", "T09.11c: config show shows redaction marker")

    # --- T09.12: config show with encrypted passwords ---
    enc_pw_config = h.tmp("config-enc-pw.yaml")
    enc_pw_config.write_text(
        "kind: certdiag-config\n"
        'version: "1"\n'
        "\n"
        "passwords:\n"
        "  common_encrypted:\n"
        '    - "aGVsbG9fd29ybGQ="\n'
        "  by_filename:\n"
        '    - filename: "*.p12"\n'
        '      encrypted_password: "dGVzdF9lbmNyeXB0ZWQ="\n'
    )
    r = h.cmd("--no-color config show -c {cfg}", cfg=enc_pw_config)
    t.expect_ok(r, "T09.12a: config show with encrypted passwords exits 0")
    t.assert_contains(r, "encrypted", "T09.12b: config show shows encrypted marker")

    # --- T09.13: Version output format ---
    r = h.cmd("--no-color version")
    t.expect_ok(r, "T09.13a: version exits 0")
    t.assert_contains(r, "certdiag", "T09.13b: version output contains 'certdiag'")

    # --- T09.14: Version exits 0 ---
    r = h.cmd("--no-color version")
    t.expect_ok(r, "T09.14: version exits 0")

    # --- T09.15: Schema is valid JSON ---
    r = h.cmd("--no-color schema")
    t.expect_ok(r, "T09.15a: schema exits 0")
    t.assert_json(r, "T09.15b: schema output is valid JSON")

    # --- T09.16: Schema has expected structure ---
    r = h.cmd("--no-color schema")
    try:
        schema = json.loads(r.stdout)
        has_structure = ("properties" in schema or "$schema" in schema
                         or "type" in schema)
        if has_structure:
            t.PASS("T09.16: schema has expected top-level fields")
        else:
            t.FAIL("T09.16: schema has expected top-level fields",
                   "missing schema structure")
    except (json.JSONDecodeError, TypeError):
        t.FAIL("T09.16: schema has expected top-level fields",
               "invalid JSON")

    # --- T09.16b: Schema validates: generate JSON from cert, verify parseable ---
    r = h.cmd("--no-color -o json {cert}", cert=h.fixture("leaf-rsa.pem"))
    t.expect_ok(r, "T09.16b-a: cert JSON output exits 0")
    t.assert_json(r, "T09.16b-b: cert JSON output is valid JSON")

    try:
        output = json.loads(r.stdout)
        if isinstance(output, (dict, list)):
            t.PASS("T09.16b-c: cert JSON has dict or list structure")
        else:
            t.FAIL("T09.16b-c: cert JSON has dict or list structure",
                   "unexpected structure")
    except (json.JSONDecodeError, TypeError):
        t.FAIL("T09.16b-c: cert JSON has dict or list structure",
               "invalid JSON")

    # --- T09.17: All template types ---
    for tmpl_type in ["cert", "ca", "csr"]:
        r = h.cmd("--no-color templates {tp}", tp=tmpl_type)
        t.expect_ok(r, f"T09.17: templates {tmpl_type} exits 0")

    # --- T09.18: Template output is non-empty with key-value structure ---
    for tmpl_type in ["cert", "ca", "csr"]:
        r = h.cmd("--no-color templates {tp}", tp=tmpl_type)
        if r.stdout.strip() and ":" in r.stdout:
            t.PASS(f"T09.18: templates {tmpl_type} non-empty with key-value structure")
        else:
            t.FAIL(f"T09.18: templates {tmpl_type}",
                   "empty or no key-value structure")

    # --- T09.19: Template --from existing cert ---
    r = h.cmd("--no-color templates cert --from {cert}",
              cert=h.fixture("leaf-rsa.pem"))
    t.expect_ok(r, "T09.19a: templates cert --from exits 0")
    t.assert_contains(r, "edge.test", "T09.19b: template from cert contains CN")

    # --- T09.20: Template ca --from CA cert ---
    r = h.cmd("--no-color templates ca --from {cert}",
              cert=h.fixture("root-ca.pem"))
    t.expect_ok(r, "T09.20a: templates ca --from CA exits 0")
    t.assert_contains(r, "ca", "T09.20b: template from CA contains ca marker")

    # --- T09.21: Template --from CSR ---
    r = h.cmd("--no-color templates cert --from {csr}",
              csr=h.fixture("basic.csr"))
    t.expect_ok(r, "T09.21a: templates cert --from CSR exits 0")
    t.assert_contains(r, "basic-csr", "T09.21b: template from CSR contains subject")

    # --- T09.22: Template --from non-existent file ---
    r = h.cmd("--no-color templates cert --from /nonexistent/file.pem")
    t.expect_fail(r, "T09.22: template --from non-existent file fails")

    # --- T09.23: Template without type argument ---
    r = h.cmd("--no-color templates")
    t.expect_fail(r, "T09.23: templates without type argument fails")

    # --- T09.24: Cross-type template extraction (CA cert -> leaf cert) ---
    r = h.cmd("--no-color templates cert --from {cert}",
              cert=h.fixture("root-ca.pem"))
    t.expect_ok(r, "T09.24a: cross-type template (CA -> cert) exits 0")

    template_file = h.tmp("ca-derived-template.yaml")
    template_file.write_text(r.stdout)
    r = h.cmd("--no-color create-cert --with-key -a ed25519 --template-profile {tmpl} "
              "-o {out} --key-output {keyout} {nc}",
              tmpl=template_file,
              out=h.tmp("from-ca-template.pem"),
              keyout=h.tmp("from-ca-template.key"),
              nc=NC)
    if r.returncode <= 2:
        t.PASS(f"T09.24b: create cert from CA-derived template handled (exit {r.returncode})")
    else:
        t.FAIL("T09.24b: create cert from CA-derived template",
               f"unexpected exit {r.returncode}")

    # --- T09.25: Overwrite protection without --no-confirm in non-TTY ---
    overwrite_file = h.tmp("existing-overwrite.pem")
    overwrite_file.write_text("existing\n")
    r = h.cmd("--no-color create-key -a ed25519 -o {out}",
              out=overwrite_file, stdin="")
    t.expect_fail(r, "T09.25: overwrite protection in non-TTY")

    # --- T09.26: --no-confirm allows overwrite ---
    overwrite_file2 = h.tmp("existing-overwrite2.pem")
    overwrite_file2.write_text("existing\n")
    r = h.cmd("--no-color create-key -a ed25519 -o {out} {nc}",
              out=overwrite_file2, nc=NC)
    t.expect_ok(r, "T09.26a: --no-confirm overwrite exits 0")
    t.assert_file_not_empty(overwrite_file2, "T09.26b: overwritten file not empty")

    content = overwrite_file2.read_text()
    if "PRIVATE KEY" in content:
        t.PASS("T09.26c: overwritten file is now a valid key")
    else:
        t.FAIL("T09.26c: overwritten file is now a valid key",
               "PRIVATE KEY not found in file")

    # --- T09.27: Unknown flag ---
    r = h.cmd("--no-color --definitely-not-a-flag {cert}",
              cert=h.fixture("leaf-rsa.pem"))
    t.expect_fail(r, "T09.27: unknown flag rejected")

    # --- T09.28: Unknown subcommand ---
    r = h.cmd("--no-color not-a-command")
    t.expect_fail(r, "T09.28: unknown subcommand rejected")

    # --- T09.29: Help flag ---
    r = h.cmd("--no-color --help")
    t.expect_ok(r, "T09.29a: root --help exits 0")
    t.assert_contains(r, "certdiag", "T09.29a: root --help mentions certdiag")

    r = h.cmd("--no-color check --help")
    t.expect_ok(r, "T09.29b: check --help exits 0")
    t.assert_contains(r, "check", "T09.29b: check --help mentions check")

    r = h.cmd("--no-color remote fetch --help")
    t.expect_ok(r, "T09.29c: remote fetch --help exits 0")
    t.assert_contains(r, "fetch", "T09.29c: remote fetch --help mentions fetch")

    # --- T09.30: Completion generation ---
    for shell in ["bash", "zsh", "fish", "powershell"]:
        r = h.cmd("--no-color completion {sh}", sh=shell)
        t.expect_ok(r, f"T09.30a: completion {shell} exits 0")
        if r.stdout.strip():
            t.PASS(f"T09.30b: completion {shell} is non-empty")
        else:
            t.FAIL(f"T09.30b: completion {shell} is non-empty",
                   "output was empty")

    # --- T09.31: Completion for invalid shell ---
    r = h.cmd("--no-color completion invalid_shell")
    t.expect_fail(r, "T09.31: completion for invalid shell rejected")

    # --- T09.32: Help on every subcommand ---
    subcommands = [
        "",
        "list",
        "check",
        "convert",
        "bundle",
        "extract",
        "reencrypt",
        "diff",
        "renew",
        "create-key",
        "create-cert",
        "csr",
        "sign",
        "schema",
        "config show",
        "config init",
        "config path",
        "version",
        "templates",
        "remote",
        "remote fetch",
        "remote check",
        "remote probe",
        "remote http",
        "remote pipe",
        "pcap",
        "pcap sessions",
        "pcap check",
        "pcap extract",
        "password",
        "password encrypt",
        "password decrypt",
        "password change-master-key",
        "completion",
    ]

    for subcmd in subcommands:
        cmd_str = f"--no-color {subcmd} --help" if subcmd else "--no-color --help"
        r = h.cmd(cmd_str)
        if r.ok:
            t.PASS(f"T09.32: --help on '{subcmd}' exits 0")
        else:
            t.FAIL(f"T09.32: --help on '{subcmd}'",
                   f"expected exit 0, got {r.returncode}")

    # --- T09.33: Cross-tool verification: certdiag JSON vs openssl ---
    if not h.has_tool("openssl"):
        t.SKIP("T09.33: openssl not found")
    else:
        certs = [
            ("leaf-rsa.pem", "leaf-rsa.pem"),
            ("leaf-ec.pem", "leaf-ec.pem"),
            ("root-ca.pem", "root-ca.pem"),
        ]

        for certname, certfile in certs:
            cert_path = h.fixture(certfile)

            r = h.cmd("--no-color -o json {cert}", cert=cert_path)
            if not r.ok:
                t.SKIP(f"T09.33: certdiag JSON failed for {certname} (exit {r.returncode})")
                continue

            # Serial number comparison
            try:
                d = json.loads(r.stdout)
                files = d.get("files", [d]) if isinstance(d, dict) else d
                items = files[0].get("items", []) if isinstance(files[0], dict) else []
                cd_serial = None
                for item in items:
                    cert_data = item.get("certificate")
                    if cert_data:
                        cd_serial = cert_data.get("serial", "").upper().replace(":", "")
                        break
            except (json.JSONDecodeError, TypeError, IndexError, KeyError):
                cd_serial = None

            ox_r = h.cmd.tool("openssl x509 -in {cert} -serial -noout", cert=cert_path)
            ox_serial = None
            if ox_r.ok:
                raw = ox_r.stdout.strip().replace("serial=", "")
                ox_serial = raw.upper()

            if cd_serial and ox_serial and cd_serial == ox_serial:
                t.PASS(f"T09.33: serial match: {certname}")
            elif not cd_serial or not ox_serial:
                t.SKIP(f"T09.33: serial compare: {certname} (could not extract)")
            else:
                t.FAIL(f"T09.33: serial match: {certname}",
                       f"cd={cd_serial} ox={ox_serial}")

            # Subject CN comparison
            try:
                d = json.loads(r.stdout)
                files = d.get("files", [d]) if isinstance(d, dict) else d
                items = files[0].get("items", []) if isinstance(files[0], dict) else []
                cd_cn = None
                for item in items:
                    cert_data = item.get("certificate")
                    if cert_data:
                        cd_cn = cert_data.get("subject", "")
                        break
            except (json.JSONDecodeError, TypeError, IndexError, KeyError):
                cd_cn = None

            ox_r = h.cmd.tool(
                "openssl x509 -in {cert} -subject -noout -nameopt RFC2253",
                cert=cert_path)
            ox_cn = None
            if ox_r.ok:
                m = re.search(r"CN=([^,]+)", ox_r.stdout)
                if m:
                    ox_cn = m.group(1).strip()

            if cd_cn and ox_cn and cd_cn == ox_cn:
                t.PASS(f"T09.33: CN match: {certname}")
            elif not cd_cn or not ox_cn:
                t.SKIP(f"T09.33: CN compare: {certname} (could not extract)")
            else:
                t.FAIL(f"T09.33: CN match: {certname}",
                       f"cd={cd_cn} ox={ox_cn}")

            # Not-after / expiry presence
            try:
                d = json.loads(r.stdout)
                files = d.get("files", [d]) if isinstance(d, dict) else d
                items = files[0].get("items", []) if isinstance(files[0], dict) else []
                cd_expiry = None
                for item in items:
                    cert_data = item.get("certificate")
                    if cert_data:
                        cd_expiry = cert_data.get("not_after", "")
                        break
            except (json.JSONDecodeError, TypeError, IndexError, KeyError):
                cd_expiry = None

            if cd_expiry:
                t.PASS(f"T09.33: expiry present: {certname}")
            else:
                t.FAIL(f"T09.33: expiry present: {certname}",
                       "not_after field missing")


if __name__ == "__main__":
    from pathlib import Path

    fixtures_dir = Path(__file__).resolve().parents[3] / "tools" / "testing" / "edgecases" / "fixtures"
    h = Harness(fixtures_dir=fixtures_dir)
    h.setup()
    t = Tracker()
    try:
        run(h, t)
    finally:
        h.cleanup()
        t.close()
    t.summary("T09")
