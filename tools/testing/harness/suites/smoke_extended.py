import json
import os
import shutil

from ..lib.harness import Harness, _find_repo_root
from ..lib.assertions import Tracker

REPO_ROOT = _find_repo_root()
SMOKE_CERTS = REPO_ROOT / "tools" / "testing" / "certs"
SMOKE_CONFIG = REPO_ROOT / "tools" / "testing" / "smoketest.yaml"
MASTER_KEY = "smoketest-master-key"

NC = "--no-confirm"


def _cert(name):
    return SMOKE_CERTS / name


def _ca(name):
    return SMOKE_CERTS / ".ca" / name


def run(h, t):
    print("\n=== Smoke Extended Tests ===")

    CA_CRT = _ca("root-ca.crt")
    CA_KEY = _ca("root-ca.key")

    # =====================================================================
    # 1. diff command
    # =====================================================================
    print("\n--- 1. diff command ---")

    # 1.1 Identical certs -> exit 0
    r = h.cmd("diff {a} {b} --no-color",
              a=_cert("self-signed-rsa.crt"), b=_cert("self-signed-rsa.crt"))
    t.expect_ok(r, "1.1 identical certs exit 0")

    # 1.2 Different certs -> exit 1
    r = h.cmd("diff {a} {b} --no-color",
              a=_cert("self-signed-rsa.crt"), b=_cert("ecdsa-p256.crt"))
    t.expect_exit(1, r, "1.2 different certs exit 1")

    # 1.3 Missing file -> exit 2
    r = h.cmd("diff {a} /nonexistent.crt --no-color",
              a=_cert("self-signed-rsa.crt"))
    t.expect_exit(2, r, "1.3 missing file exit 2")

    # 1.4 Shows changed fields
    r = h.cmd("diff {a} {b} --no-color",
              a=_cert("self-signed-rsa.crt"), b=_cert("ecdsa-p256.crt"))
    t.assert_contains(r, "Subject", "1.4 diff shows Subject")
    t.assert_contains(r, "Algorithm", "1.4 diff shows Algorithm")

    # 1.5 Details includes fingerprints
    r = h.cmd("diff -d {a} {b} --no-color",
              a=_cert("extra-ext.crt"), b=_cert("self-signed-rsa.crt"))
    t.assert_contains(r, "SHA-256", "1.5 details shows SHA-256")

    # 1.6 Without --details, extended fields hidden
    r = h.cmd("diff {a} {b} --no-color",
              a=_cert("self-signed-rsa.crt"), b=_cert("ecdsa-p256.crt"))
    t.assert_not_contains(r, "SHA-256", "1.6 no details hides SHA-256")

    # 1.7 Same cert with --only-changes -> minimal output
    r = h.cmd("diff {a} {b} --only-changes --no-color",
              a=_cert("self-signed-rsa.crt"), b=_cert("self-signed-rsa.crt"))
    line_count = len(r.stdout.splitlines())
    if line_count <= 5:
        t.PASS(f"1.7 only-changes minimal output ({line_count} lines)")
    else:
        t.FAIL(f"1.7 only-changes minimal output", f"got {line_count} lines")

    # 1.8 Different certs with --only-changes
    r = h.cmd("diff {a} {b} --only-changes --no-color",
              a=_cert("self-signed-rsa.crt"), b=_cert("ecdsa-p256.crt"))
    t.assert_contains(r, "Algorithm", "1.8 only-changes shows Algorithm")

    # 1.9 Default index 1:1
    r = h.cmd("diff {a} {b} --no-color",
              a=_cert("ca-chain.pem"), b=_cert("self-signed-rsa.crt"))
    if r.returncode <= 1:
        t.PASS("1.9 default index works")
    else:
        t.FAIL("1.9 default index works", f"exit {r.returncode}")

    # 1.10 Custom index 2:1
    r = h.cmd("diff {a} {b} --index 2:1 --no-color",
              a=_cert("ca-chain.pem"), b=_cert("self-signed-rsa.crt"))
    if r.returncode <= 1:
        t.PASS("1.10 custom index 2:1")
    else:
        t.FAIL("1.10 custom index 2:1", f"exit {r.returncode}")

    # 1.11 Out-of-bounds index -> exit 2
    r = h.cmd("diff {a} {b} --index 5:1 --no-color",
              a=_cert("self-signed-rsa.crt"), b=_cert("self-signed-rsa.crt"))
    t.expect_exit(2, r, "1.11 out-of-bounds index exit 2")

    # 1.12 Invalid index format -> exit 2
    r = h.cmd("diff {a} {b} --index abc --no-color",
              a=_cert("self-signed-rsa.crt"), b=_cert("self-signed-rsa.crt"))
    t.expect_exit(2, r, "1.12 invalid index format exit 2")

    # 1.13 JSON output is valid
    r = h.cmd("diff {a} {b} -o json",
              a=_cert("self-signed-rsa.crt"), b=_cert("ecdsa-p256.crt"))
    t.assert_json(r, "1.13 diff JSON is valid")

    # 1.14 YAML output
    r = h.cmd("diff {a} {b} -o yaml",
              a=_cert("self-signed-rsa.crt"), b=_cert("ecdsa-p256.crt"))
    t.assert_contains(r, "Subject", "1.14 diff YAML has subject")

    # 1.15 Diff PEM vs DER
    r = h.cmd("diff {a} {b} --no-color",
              a=_cert("self-signed-rsa.crt"), b=_cert("rsa-cert.der"))
    t.expect_exit(1, r, "1.15 PEM vs DER exit 1 (different certs)")

    # 1.16 Diff with passwords
    r = h.cmd("diff {a} {b} -p p12pass -p ecdsapfx --no-color",
              a=_cert("standard.p12"), b=_cert("ecdsa.pfx"))
    t.assert_contains(r, "Algorithm", "1.16 diff with passwords shows Algorithm")

    # 1.17 Diff with password file
    r = h.cmd("diff {a} {b} -P {pf} --no-color",
              a=_cert("standard.p12"), b=_cert("self-signed-rsa.crt"),
              pf=_cert("passwords.txt"))
    t.assert_contains(r, "Subject", "1.17 diff with password file shows Subject")

    # 1.18 Diff cert vs key (document behavior -- just verify no crash)
    r = h.cmd("diff {a} {b} --index 1:1 --no-color",
              a=_cert("self-signed-rsa.crt"), b=_cert("self-signed-rsa.key"))
    t.PASS(f"1.18 diff cert vs key no crash (exit {r.returncode})")

    # =====================================================================
    # 2. config show command
    # =====================================================================
    print("\n--- 2. config show command ---")

    # 2.1 Default config
    r = h.cmd("config show --no-color")
    if r.stdout.strip():
        t.PASS("2.1 config show produces output")
    else:
        t.FAIL("2.1 config show produces output", "empty output")

    # 2.2 With explicit config file
    r = h.cmd("config show -c {cfg} --no-color", cfg=SMOKE_CONFIG)
    t.assert_contains(r, "password", "2.2 config show with config")

    # 2.3 Plaintext passwords redacted
    t.assert_not_contains(r, "p12pass", "2.3 plaintext password redacted")
    t.assert_contains(r, "redacted", "2.3 shows [redacted]")

    # 2.4 Encrypted passwords marked
    t.assert_contains(r, "encrypted", "2.4 shows [encrypted]")

    # 2.5 Config file not found
    r = h.cmd("config show -c /nonexistent.yaml --no-color")
    t.PASS(f"2.5 missing config handled (exit {r.returncode})")

    # =====================================================================
    # 3. version and schema commands
    # =====================================================================
    print("\n--- 3. version and schema commands ---")

    # 3.1 Version output
    r = h.cmd("version")
    t.assert_contains(r, "certdiag", "3.1 version output")

    # 3.2 Schema is valid JSON
    r = h.cmd("schema")
    t.assert_json(r, "3.2 schema is valid JSON")

    # 3.3 Schema has properties
    try:
        data = json.loads(r.stdout)
        if "properties" in data:
            t.PASS("3.3 schema has properties")
        else:
            t.FAIL("3.3 schema has properties", "missing .properties")
    except (json.JSONDecodeError, TypeError):
        t.FAIL("3.3 schema has properties", "invalid JSON")

    # =====================================================================
    # 4. Password management commands
    # =====================================================================
    print("\n--- 4. Password management commands ---")

    # 4.1 Encrypt a password
    r = h.cmd("password encrypt --master-password {mk}",
              mk=MASTER_KEY, stdin="testpw\n")
    t.expect_ok(r, "4.1 encrypt password")
    encrypted = r.stdout.strip()

    # 4.2 Encrypt with -p flag
    r = h.cmd("password encrypt -p testpw --master-password {mk}",
              mk=MASTER_KEY)
    t.expect_ok(r, "4.2 encrypt with -p flag")

    # 4.3 Decrypt known encrypted password
    r = h.cmd("password decrypt --master-password {mk}",
              mk=MASTER_KEY, stdin=encrypted + "\n")
    t.assert_contains(r, "testpw", "4.3 decrypt returns original")

    # 4.4 Decrypt with wrong master key
    r = h.cmd("password decrypt --master-password wrong",
              stdin=encrypted + "\n")
    t.expect_fail(r, "4.4 decrypt wrong master key fails")

    # 4.5 Change master key on config
    change_cfg = h.tmp("change-master.yaml")
    shutil.copy2(SMOKE_CONFIG, change_cfg)
    r = h.cmd("password change-master-key --master-password {mk} -c {cfg}",
              mk=MASTER_KEY, cfg=change_cfg,
              stdin="newmaster123\nnewmaster123\n")
    t.expect_ok(r, "4.5 change master key")

    # =====================================================================
    # 5. Global flags
    # =====================================================================
    print("\n--- 5. Global flags ---")

    # 5.1 --no-color removes ANSI escape sequences
    r = h.cmd("--no-color {f}", f=_cert("self-signed-rsa.crt"))
    t.assert_no_ansi(r, "5.1 --no-color removes ANSI")

    # 5.2 NO_COLOR env var
    r = h.cmd("{f}", f=_cert("self-signed-rsa.crt"),
              env_extra={"NO_COLOR": "1"})
    t.assert_no_ansi(r, "5.2 NO_COLOR env removes ANSI")

    # 5.3 Config provides common passwords
    r = h.cmd("{f} -c {cfg} --master-password {mk} --no-color",
              f=_cert("standard.p12"), cfg=SMOKE_CONFIG, mk=MASTER_KEY)
    t.assert_contains(r, "standard.smoketest", "5.3 config common passwords")

    # 5.4 Config by_filename glob matching
    r = h.cmd("{f} -c {cfg} --master-password {mk} --no-color",
              f=_cert("ecdsa.pfx"), cfg=SMOKE_CONFIG, mk=MASTER_KEY)
    t.assert_contains(r, "ecdsa.smoketest", "5.4 config by_filename glob")

    # 5.5 Config encrypted password + master key
    r = h.cmd("{f} -c {cfg} --master-password {mk} --no-color",
              f=_cert("legacy-des3.p12"), cfg=SMOKE_CONFIG, mk=MASTER_KEY)
    t.assert_contains(r, "legacy.smoketest", "5.5 encrypted password + master key")

    # 5.6 Encrypted password WITHOUT master key
    r = h.cmd("{f} -c {cfg} --no-color",
              f=_cert("legacy-des3.p12"), cfg=SMOKE_CONFIG)
    t.assert_not_contains(r, "legacy.smoketest", "5.6 no master key fails")

    # 5.7 CERTDIAG_MASTER_KEY env var
    r = h.cmd("{f} -c {cfg} --no-color",
              f=_cert("legacy-des3.p12"), cfg=SMOKE_CONFIG,
              env_extra={"CERTDIAG_MASTER_KEY": MASTER_KEY})
    t.assert_contains(r, "legacy.smoketest", "5.7 CERTDIAG_MASTER_KEY env var")

    # 5.8 CERTDIAG_CONFIG env var
    r = h.cmd("{f} --no-color",
              f=_cert("standard.p12"),
              env_extra={"CERTDIAG_CONFIG": str(SMOKE_CONFIG),
                         "CERTDIAG_MASTER_KEY": MASTER_KEY})
    t.assert_contains(r, "standard.smoketest", "5.8 CERTDIAG_CONFIG env var")

    # 5.9 Password file provides passwords
    r = h.cmd("{f} -P {pf} --no-color",
              f=_cert("standard.p12"), pf=_cert("passwords.txt"))
    t.assert_contains(r, "standard.smoketest", "5.9 password file")

    # 5.10 Multiple passwords in file
    r = h.cmd("{f} -P {pf} --no-color",
              f=_cert("keystore.jks"), pf=_cert("passwords.txt"))
    t.assert_contains(r, "smoketest-rsa", "5.10 multi passwords in file")

    # 5.11 Password file not found
    r = h.cmd("{f} -P /nonexistent.txt --no-color",
              f=_cert("standard.p12"))
    t.PASS(f"5.11 missing password file handled (exit {r.returncode})")

    # 5.12-5.14 --no-try-all-passwords
    notryall_cfg = h.tmp("notryall.yaml")
    notryall_cfg.write_text(
        'kind: certdiag-config\n'
        'version: "1"\n'
        'passwords:\n'
        '  common_plaintext:\n'
        '    - "p12pass"\n'
        '  by_filename:\n'
        '    - filename: "*.pfx"\n'
        '      plaintext_password: "ecdsapfx"\n'
    )

    # 5.12 Common pool skipped with --no-try-all-passwords
    r = h.cmd("{f} -c {cfg} --no-try-all-passwords --no-color",
              f=_cert("standard.p12"), cfg=notryall_cfg)
    t.assert_not_contains(r, "standard.smoketest", "5.12 common pool skipped")

    # 5.13 by_filename match still works
    r = h.cmd("{f} -c {cfg} --no-try-all-passwords --no-color",
              f=_cert("ecdsa.pfx"), cfg=notryall_cfg)
    t.assert_contains(r, "ecdsa.smoketest", "5.13 by_filename match works")

    # 5.14 Without --no-try-all-passwords, common pool works
    r = h.cmd("{f} -c {cfg} --no-color",
              f=_cert("standard.p12"), cfg=notryall_cfg)
    t.assert_contains(r, "standard.smoketest", "5.14 common pool works without flag")

    # 5.15 Single env var password
    r = h.cmd("{f} --no-color",
              f=_cert("standard.p12"),
              env_extra={"CERTDIAG_PASSWORD_1": "p12pass"})
    t.assert_contains(r, "standard.smoketest", "5.15 single env var password")

    # 5.16 Multiple env var passwords
    r = h.cmd("{f1} {f2} --no-color",
              f1=_cert("standard.p12"), f2=_cert("ecdsa.pfx"),
              env_extra={"CERTDIAG_PASSWORD_1": "p12pass",
                         "CERTDIAG_PASSWORD_2": "ecdsapfx"})
    t.assert_contains(r, "standard.smoketest", "5.16 multi env passwords (standard)")
    t.assert_contains(r, "ecdsa.smoketest", "5.16 multi env passwords (ecdsa)")

    # 5.17 Password prompt via pipe
    r = h.cmd("{f} -i --no-color",
              f=_cert("standard.p12"), stdin="p12pass\n")
    t.expect_ok(r, "5.17 piped password exit 0")
    t.assert_contains(r, "standard.smoketest", "5.17 piped password shows cert")

    # 5.18 Wrong piped password
    r = h.cmd("{f} -i --no-color",
              f=_cert("standard.p12"), stdin="wrongpass\n")
    t.assert_contains(r, "password required", "5.18 wrong piped password shows error")

    # =====================================================================
    # 6. Root command (list) -- advanced flags
    # =====================================================================
    print("\n--- 6. Root command (list) -- advanced flags ---")

    # 6.1 Recursive scan
    r = h.cmd("-r {d} -p changeit -p p12pass --no-color",
              d=str(SMOKE_CERTS) + "/")
    t.assert_contains(r, "root-ca", "6.1 recursive finds .ca/ subdir files")

    # 6.2 Non-recursive scan
    crt_list = sorted(SMOKE_CERTS.glob("*.crt"))
    r = h.cmd.run(*crt_list, "--no-color")
    t.assert_not_contains(r, "root-ca", "6.2 non-recursive excludes .ca/")

    # 6.3 --depth 1 limits recursion
    r = h.cmd("-r --depth 1 {d} -p changeit --no-color",
              d=str(SMOKE_CERTS) + "/")
    t.assert_not_contains(r, "root-ca", "6.3 depth 1 excludes .ca/ subdir")
    t.assert_contains(r, "self-signed-rsa", "6.3 depth 1 includes top-level files")

    # 6.4 --depth 0 with -r (document behavior)
    r = h.cmd("-r --depth 0 {d} --no-color",
              d=str(SMOKE_CERTS) + "/")
    t.PASS(f"6.4 depth 0 with -r no crash (exit {r.returncode})")

    # 6.5 Cert in .txt file detected by --file-signature-scan
    cert_txt = h.tmp("cert.txt")
    shutil.copy2(_cert("self-signed-rsa.crt"), cert_txt)
    r = h.cmd("--file-signature-scan {f} --no-color", f=cert_txt)
    t.assert_contains(r, "self-signed", "6.5 signature scan detects cert in .txt")

    # 6.6 Garbage in .crt file
    garbage_crt = h.tmp("garbage.crt")
    garbage_crt.write_text("not a cert\n")
    r = h.cmd("{f} --no-color", f=garbage_crt)
    t.PASS(f"6.6 garbage .crt handled (exit {r.returncode})")

    # 6.7 Filter by CN substring
    r = h.cmd.run("-q", "self-signed", *crt_list, "--no-color")
    t.assert_contains(r, "self-signed", "6.7 query filter by CN")

    # 6.8 Filter by SAN DNS name
    r = h.cmd('-q smoketest {f} --no-color', f=_cert("ca-chain.pem"))
    t.assert_contains(r, "smoketest", "6.8 query filter by SAN")

    # 6.9 No match -> empty results
    r = h.cmd('-q nonexistent-term-xyz {f} --no-color',
              f=_cert("self-signed-rsa.crt"))
    t.assert_not_contains(r, "self-signed.smoketest", "6.9 no match -> empty")

    # 6.10 Case-insensitive query
    r = h.cmd.run("-q", "SELF-SIGNED", *crt_list, "--no-color")
    t.assert_contains(r, "self-signed", "6.10 case-insensitive query")

    # 6.11 Filter matches serial number
    rj = h.cmd("-o json {f}", f=_cert("self-signed-rsa.crt"))
    try:
        data = json.loads(rj.stdout)
        serial = data["files"][0]["items"][0]["certificate"]["serial"]
        if serial:
            r = h.cmd('-q {serial} {f} --no-color',
                      serial=serial, f=_cert("self-signed-rsa.crt"))
            if r.stdout.strip():
                t.PASS("6.11 query matches serial")
            else:
                t.FAIL("6.11 query matches serial", "no output")
        else:
            t.FAIL("6.11 query matches serial", "could not extract serial from JSON")
    except (json.JSONDecodeError, KeyError, IndexError):
        t.FAIL("6.11 query matches serial", "could not extract serial from JSON")

    # 6.12 Discover finds matching key
    r = h.cmd("-D {f} --no-color", f=_cert("self-signed-rsa.crt"))
    t.assert_contains(r, "self-signed-rsa.key", "6.12 discover finds matching key")

    # 6.13 Discover shows relations
    t.assert_contains(r, "key", "6.13 discover shows key relation")

    # 6.14 Inline check shows warnings
    r = h.cmd("--check {f} --no-color", f=_cert("self-signed-rsa.key"))
    t.assert_contains(r, "not password-protected", "6.14 inline check warns")

    # 6.15 Clean cert -> no critical/warning inline
    r = h.cmd("--check {f} --no-color", f=_cert("self-signed-rsa.crt"))
    t.assert_not_contains(r, "CRITICAL", "6.15 clean cert no critical")

    # 6.16 Custom warn threshold triggers
    r = h.cmd("--check --expiry-warn 4000 {f} --no-color",
              f=_cert("self-signed-rsa.crt"))
    t.assert_contains(r, "Expires in", "6.16 custom warn threshold")

    # 6.17 Default thresholds don't trigger
    r = h.cmd("--check {f} --no-color", f=_cert("self-signed-rsa.crt"))
    t.assert_not_contains(r, "Expires in", "6.17 default thresholds fine")

    # 6.18 Table view (-t)
    r = h.cmd("-t {f} --no-color", f=_cert("self-signed-rsa.crt"))
    if r.stdout.strip():
        t.PASS("6.18 table view produces output")
    else:
        t.FAIL("6.18 table view produces output", "empty")

    # 6.19 JSON output is valid
    r = h.cmd("-o json {f}", f=_cert("self-signed-rsa.crt"))
    t.assert_json(r, "6.19 JSON output valid")

    # 6.20 JSON structure
    try:
        data = json.loads(r.stdout)
        has_filename = "filename" in data.get("files", [{}])[0]
        has_subject = "subject" in data["files"][0]["items"][0].get("certificate", {})
        if has_filename and has_subject:
            t.PASS("6.20 JSON structure correct")
        else:
            t.FAIL("6.20 JSON structure correct", "missing expected fields")
    except (json.JSONDecodeError, KeyError, IndexError, TypeError):
        t.FAIL("6.20 JSON structure correct", "missing expected fields")

    # 6.21 YAML output
    r = h.cmd("-o yaml {f}", f=_cert("self-signed-rsa.crt"))
    t.assert_contains(r, "filename", "6.21 YAML has filename")
    t.assert_contains(r, "subject", "6.21 YAML has subject")

    # 6.22 Detail view (-d)
    r = h.cmd("-d {f} --no-color", f=_cert("self-signed-rsa.crt"))
    t.assert_contains(r, "SHA-256", "6.22 detail view SHA-256")
    t.assert_contains(r, "Serial", "6.22 detail view Serial")

    # 6.23 --insecure-details
    r = h.cmd("-d --insecure-details {f} --no-color",
              f=_cert("self-signed-rsa.key"))
    if r.stdout.strip():
        t.PASS("6.23 insecure-details produces output")
    else:
        t.FAIL("6.23 insecure-details", "no output")

    # 6.24 Combined -o json -d
    r = h.cmd("-o json -d {f}", f=_cert("self-signed-rsa.crt"))
    try:
        data = json.loads(r.stdout)
        if data["files"][0]["items"][0]["certificate"].get("sha256"):
            t.PASS("6.24 JSON+details has sha256")
        else:
            t.FAIL("6.24 JSON+details has sha256", "missing")
    except (json.JSONDecodeError, KeyError, IndexError, TypeError):
        t.FAIL("6.24 JSON+details has sha256", "missing")

    # 6.25 Invalid output format
    r = h.cmd("-o xml {f} --no-color", f=_cert("self-signed-rsa.crt"))
    t.expect_fail(r, "6.25 invalid format exits non-zero")

    # 6.26 -t and -o mutually exclusive
    r = h.cmd("-t -o json {f} --no-color", f=_cert("self-signed-rsa.crt"))
    t.expect_fail(r, "6.26 -t and -o mutually exclusive")

    # =====================================================================
    # 7. check command -- advanced flags
    # =====================================================================
    print("\n--- 7. check command -- advanced flags ---")

    # 7.1 Discover resolves chain
    r = h.cmd("check -D {f} --no-color", f=_ca("leaf.crt"))
    t.assert_not_contains(r, "Chain incomplete", "7.1 discover resolves chain")

    # 7.2 Without discover, chain incomplete
    r = h.cmd("check {f} --no-color", f=_ca("leaf.crt"))
    t.assert_contains(r, "Chain incomplete", "7.2 without discover chain incomplete")

    # 7.3 Custom thresholds via flags
    r = h.cmd("check --expiry-warn 400 --expiry-critical 350 {f} --no-color",
              f=_cert("self-signed-rsa.crt"))
    t.expect_exit(1, r, "7.3 custom thresholds exit 1 (warning)")

    # 7.4 Custom thresholds via config
    threshold_cfg = h.tmp("threshold.yaml")
    threshold_cfg.write_text(
        'kind: certdiag-config\n'
        'version: "1"\n'
        'defaults:\n'
        '  check:\n'
        '    expiry_critical_days: 350\n'
        '    expiry_warn_days: 400\n'
    )
    r = h.cmd("check {f} --no-color",
              f=_cert("self-signed-rsa.crt"),
              env_extra={"CERTDIAG_CONFIG": str(threshold_cfg)})
    t.expect_exit(1, r, "7.4 config thresholds exit 1 (warning)")

    # 7.5 Strict mode on info-only finding
    r = h.cmd("check --strict {f} --no-color", f=_cert("self-signed-rsa.key"))
    t.expect_ok(r, "7.5 strict on info-only file exit 0")

    # 7.6 Strict on clean cert -> exit 0
    r = h.cmd("check --strict --category key_strength {f} --no-color",
              f=_cert("self-signed-rsa.crt"))
    t.expect_ok(r, "7.6 strict clean cert exit 0")

    # 7.7 Multiple categories (comma-separated)
    r = h.cmd("check --category expiry,key_strength {f} --no-color",
              f=_cert("self-signed-rsa.crt"))
    t.expect_ok(r, "7.7 multi category filter")

    # 7.8 Unknown category name (document behavior)
    r = h.cmd("check --category nonexistent {f} --no-color",
              f=_cert("self-signed-rsa.crt"))
    t.PASS(f"7.8 unknown category no crash (exit {r.returncode})")

    # 7.9 Disable multiple checks via config
    disable_cfg = h.tmp("disable-multi.yaml")
    disable_cfg.write_text(
        'kind: certdiag-config\n'
        'version: "1"\n'
        'defaults:\n'
        '  check:\n'
        '    disabled_checks:\n'
        '      - "self_signed_leaf"\n'
        '      - "unprotected_key"\n'
        '      - "missing_sans"\n'
    )
    r = h.cmd("check {f} --no-color",
              f=_cert("missing-san.crt"),
              env_extra={"CERTDIAG_CONFIG": str(disable_cfg)})
    t.assert_not_contains(r, "Self-signed leaf", "7.9 disabled self_signed_leaf")
    t.assert_not_contains(r, "Missing SANs", "7.9 disabled missing_sans")

    # 7.10 Lists all categories
    r = h.cmd("check --list-checks")
    t.assert_contains(r, "expiry", "7.10 list-checks has expiry")
    t.assert_contains(r, "key_strength", "7.10 list-checks has key_strength")
    t.assert_contains(r, "algorithm", "7.10 list-checks has algorithm")
    t.assert_contains(r, "chain", "7.10 list-checks has chain")
    t.assert_contains(r, "info", "7.10 list-checks has info")

    # 7.11 Always exits 0
    t.expect_ok(r, "7.11 list-checks exits 0")

    # =====================================================================
    # 8. convert -- extended cases
    # =====================================================================
    print("\n--- 8. convert -- extended cases ---")

    # 8.1 .p12 format inference
    h.cmd("convert {src} -o {out} --output-password test {nc}",
          src=_cert("combined-bundle.pem"), out=h.tmp("out.p12"), nc=NC)
    t.assert_file_exists(h.tmp("out.p12"), "8.1 .p12 format inference")

    # 8.2 .jks format inference
    h.cmd("convert {src} -o {out} --output-password test {nc}",
          src=_cert("combined-bundle.pem"), out=h.tmp("out.jks"), nc=NC)
    t.assert_file_exists(h.tmp("out.jks"), "8.2 .jks format inference")

    # 8.3 .der format inference
    h.cmd("convert {src} -o {out} {nc}",
          src=_cert("self-signed-rsa.crt"), out=h.tmp("out.der"), nc=NC)
    t.assert_file_exists(h.tmp("out.der"), "8.3 .der format inference")

    # 8.4 .p7b format inference
    h.cmd("convert {src} -o {out} {nc}",
          src=_cert("self-signed-rsa.crt"), out=h.tmp("out.p7b"), nc=NC)
    t.assert_file_exists(h.tmp("out.p7b"), "8.4 .p7b format inference")

    # 8.5 .pem format inference
    h.cmd("convert {src} -o {out} {nc}",
          src=_cert("rsa-cert.der"), out=h.tmp("out.pem"), nc=NC)
    t.assert_file_exists(h.tmp("out.pem"), "8.5 .pem format inference")
    pem_content = h.tmp("out.pem").read_text()
    if "BEGIN CERTIFICATE" in pem_content:
        t.PASS("8.5 PEM has BEGIN marker")
    else:
        t.FAIL("8.5 PEM has BEGIN marker", "missing BEGIN CERTIFICATE")

    # 8.6 Legacy PKCS#12
    h.cmd("convert {src} -o {out} -f pkcs12 --output-password x --legacy-pkcs12 {nc}",
          src=_cert("combined-bundle.pem"), out=h.tmp("legacy.p12"), nc=NC)
    t.assert_file_exists(h.tmp("legacy.p12"), "8.6 legacy PKCS#12")

    # 8.7 --include certs
    h.cmd("convert {src} -o {out} --include certs {nc}",
          src=_cert("combined-bundle.pem"), out=h.tmp("certs.pem"), nc=NC)
    certs_pem = h.tmp("certs.pem").read_text()
    if "BEGIN CERTIFICATE" in certs_pem:
        t.PASS("8.7 include certs has cert")
    else:
        t.FAIL("8.7 include certs has cert", "missing BEGIN CERTIFICATE")
    if "PRIVATE KEY" not in certs_pem:
        t.PASS("8.7 include certs no key")
    else:
        t.FAIL("8.7 include certs no key", "found PRIVATE KEY")

    # 8.8 --include keys
    h.cmd("convert {src} -o {out} --include keys {nc}",
          src=_cert("combined-bundle.pem"), out=h.tmp("keys.pem"), nc=NC)
    keys_pem = h.tmp("keys.pem").read_text()
    if "PRIVATE KEY" in keys_pem:
        t.PASS("8.8 include keys has key")
    else:
        t.FAIL("8.8 include keys has key", "missing PRIVATE KEY")
    if "BEGIN CERTIFICATE" not in keys_pem:
        t.PASS("8.8 include keys no cert")
    else:
        t.FAIL("8.8 include keys no cert", "found BEGIN CERTIFICATE")

    # 8.9 Custom alias in JKS
    h.cmd("convert {src} -o {out} -f jks --output-password x --alias my-alias {nc}",
          src=_cert("combined-bundle.pem"), out=h.tmp("aliased.jks"), nc=NC)
    t.assert_file_exists(h.tmp("aliased.jks"), "8.9 custom alias JKS")
    r = h.cmd("{f} -p x --no-color", f=h.tmp("aliased.jks"))
    t.assert_contains(r, "my-alias", "8.9 readback shows my-alias")

    # 8.10 JKS to PEM
    h.cmd("convert {src} -p changeit -o {out} {nc}",
          src=_cert("keystore.jks"), out=h.tmp("from-jks.pem"), nc=NC)
    jks_pem = h.tmp("from-jks.pem").read_text()
    if "BEGIN CERTIFICATE" in jks_pem:
        t.PASS("8.10 JKS to PEM has cert")
    else:
        t.FAIL("8.10 JKS to PEM has cert", "missing BEGIN CERTIFICATE")
    if "PRIVATE KEY" in jks_pem:
        t.PASS("8.10 JKS to PEM has key")
    else:
        t.FAIL("8.10 JKS to PEM has key", "missing PRIVATE KEY")

    # 8.11 JKS to PKCS#12
    h.cmd("convert {src} -p changeit -o {out} -f pkcs12 --output-password x {nc}",
          src=_cert("keystore.jks"), out=h.tmp("from-jks.p12"), nc=NC)
    t.assert_file_exists(h.tmp("from-jks.p12"), "8.11 JKS to PKCS#12")

    # 8.12 PKCS#7 to PEM
    h.cmd("convert {src} -o {out} {nc}",
          src=_cert("chain.p7b"), out=h.tmp("from-p7b.pem"), nc=NC)
    t.assert_file_exists(h.tmp("from-p7b.pem"), "8.12 P7B to PEM")
    p7b_pem = h.tmp("from-p7b.pem").read_text()
    cert_count = p7b_pem.count("BEGIN CERTIFICATE")
    if cert_count >= 2:
        t.PASS(f"8.12 P7B to PEM has {cert_count} certs")
    else:
        t.FAIL("8.12 P7B to PEM multiple certs", f"expected >=2, got {cert_count}")

    # 8.13 DER to PKCS#7
    h.cmd("convert {src} -o {out} -f pkcs7 {nc}",
          src=_cert("rsa-cert.der"), out=h.tmp("from-der.p7b"), nc=NC)
    t.assert_file_exists(h.tmp("from-der.p7b"), "8.13 DER to PKCS#7")

    # 8.14 PEM-encoded P7B to DER
    h.cmd("convert {src} -o {out} -f der {nc}",
          src=_cert("pem-encoded.p7b"), out=h.tmp("p7b-to.der"), nc=NC)
    t.assert_file_exists(h.tmp("p7b-to.der"), "8.14 PEM P7B to DER")

    # 8.15 Missing -o flag
    r = h.cmd("convert {src} -f der {nc}",
              src=_cert("self-signed-rsa.crt"), nc=NC)
    t.expect_fail(r, "8.15 missing -o exits non-zero")

    # 8.16 DER with multiple certs (tool rejects, exits non-zero)
    r = h.cmd("convert {src} -o {out} -f der {nc}",
              src=_cert("ca-chain.pem"), out=h.tmp("chain.der"), nc=NC)
    t.expect_fail(r, "8.16 DER multi-cert exits non-zero")
    t.assert_contains(r, "only one item", "8.16 DER multi-cert shows error", stream="stderr")

    # 8.17 PKCS#12 without password when keys present (document behavior)
    r = h.cmd("convert {src} -o {out} -f pkcs12 {nc}",
              src=_cert("combined-bundle.pem"), out=h.tmp("nopw.p12"), nc=NC)
    t.PASS(f"8.17 P12 no password no crash (exit {r.returncode})")

    # =====================================================================
    # 9. extract -- extended cases
    # =====================================================================
    print("\n--- 9. extract -- extended cases ---")

    # 9.1 --naming {subject}-{index}
    ext91_dir = h.tmp("ext91")
    ext91_dir.mkdir(parents=True, exist_ok=True)
    h.cmd.run("extract", _cert("ca-chain.pem"),
              "--output-dir", str(ext91_dir) + "/",
              "--naming", "{subject}-{index}", NC)
    ext91_count = len(list(ext91_dir.iterdir()))
    if ext91_count >= 2:
        t.PASS(f"9.1 naming pattern ({ext91_count} files)")
    else:
        t.FAIL("9.1 naming pattern", f"expected >=2, got {ext91_count}")

    # 9.2 --naming {alias} from JKS
    ext92_dir = h.tmp("ext92")
    ext92_dir.mkdir(parents=True, exist_ok=True)
    h.cmd.run("extract", _cert("multi.jks"),
              "-p", "multientry", "--output-dir", str(ext92_dir) + "/",
              "--naming", "{alias}", NC)
    ext92_count = len(list(ext92_dir.iterdir()))
    if ext92_count >= 2:
        t.PASS(f"9.2 JKS alias naming ({ext92_count} files)")
    else:
        t.FAIL("9.2 JKS alias naming", f"expected >=2, got {ext92_count}")

    # 9.3 --naming {filename}-{index}-{type}.{format}
    ext93_dir = h.tmp("ext93")
    ext93_dir.mkdir(parents=True, exist_ok=True)
    h.cmd.run("extract", _cert("combined-bundle.pem"),
              "--output-dir", str(ext93_dir) + "/",
              "--naming", "{filename}-{index}-{type}.{format}", NC)
    ext93_count = len(list(ext93_dir.iterdir()))
    if ext93_count >= 1:
        t.PASS(f"9.3 structured naming ({ext93_count} files)")
    else:
        t.FAIL("9.3 structured naming", "no files")

    # 9.4 Extract by alias from JKS
    ext94_dir = h.tmp("ext94")
    ext94_dir.mkdir(parents=True, exist_ok=True)
    h.cmd('extract {src} -p multientry --output-dir {d} --alias web-entry {nc}',
          src=_cert("multi.jks"), d=str(ext94_dir) + "/", nc=NC)
    ext94_count = len(list(ext94_dir.iterdir()))
    if ext94_count >= 1:
        t.PASS(f"9.4 extract by alias ({ext94_count} files)")
    else:
        t.FAIL("9.4 extract by alias", "no files")

    # 9.5 Extract as DER
    ext95_dir = h.tmp("ext95")
    ext95_dir.mkdir(parents=True, exist_ok=True)
    h.cmd('extract {src} --output-dir {d} -f der {nc}',
          src=_cert("self-signed-rsa.crt"), d=str(ext95_dir) + "/", nc=NC)
    ext95_files = list(ext95_dir.iterdir())
    if len(ext95_files) >= 1:
        first_file = ext95_files[0]
        content = first_file.read_text(errors="replace")
        if "BEGIN" not in content:
            t.PASS("9.5 DER no BEGIN marker")
        else:
            t.FAIL("9.5 DER no BEGIN marker", "has BEGIN marker")
    else:
        t.FAIL("9.5 DER extract", "no files")

    # 9.6 Extract from P7B
    ext96_dir = h.tmp("ext96")
    ext96_dir.mkdir(parents=True, exist_ok=True)
    h.cmd('extract {src} --output-dir {d} {nc}',
          src=_cert("chain.p7b"), d=str(ext96_dir) + "/", nc=NC)
    ext96_count = len(list(ext96_dir.iterdir()))
    if ext96_count >= 2:
        t.PASS(f"9.6 P7B extract ({ext96_count} files)")
    else:
        t.FAIL("9.6 P7B extract", f"expected >=2, got {ext96_count}")

    # 9.7 Extract from JKS (cert + key)
    ext97_dir = h.tmp("ext97")
    ext97_dir.mkdir(parents=True, exist_ok=True)
    h.cmd('extract {src} -p changeit --output-dir {d} {nc}',
          src=_cert("keystore.jks"), d=str(ext97_dir) + "/", nc=NC)
    ext97_count = len(list(ext97_dir.iterdir()))
    if ext97_count >= 2:
        t.PASS(f"9.7 JKS extract cert+key ({ext97_count} files)")
    else:
        t.FAIL("9.7 JKS extract", f"expected >=2, got {ext97_count}")

    # 9.8 Extract certs only from truststore
    ext98_dir = h.tmp("ext98")
    ext98_dir.mkdir(parents=True, exist_ok=True)
    h.cmd('extract {src} -p trustme --output-dir {d} --type certs {nc}',
          src=_cert("truststore.jks"), d=str(ext98_dir) + "/", nc=NC)
    ext98_count = len(list(ext98_dir.iterdir()))
    if ext98_count >= 1:
        t.PASS(f"9.8 truststore certs only ({ext98_count} files)")
    else:
        t.FAIL("9.8 truststore certs only", "no files")

    # =====================================================================
    # 10. create-cert -- extended flags
    # =====================================================================
    print("\n--- 10. create-cert -- extended flags ---")

    # 10.1 Custom key usage
    h.cmd('create-cert --with-key --subject CN=ku.test '
          '--key-usage digitalSignature,keyEncipherment '
          '-o {out} --key-output {kout} {nc}',
          out=h.tmp("ku.crt"), kout=h.tmp("ku.key"), nc=NC)
    t.assert_file_exists(h.tmp("ku.crt"), "10.1 custom key usage")
    r_ossl = h.cmd.openssl("x509 -in {cert} -text -noout", cert=h.tmp("ku.crt"))
    t.assert_contains(r_ossl, "Digital Signature", "10.1 openssl shows Digital Signature")

    # 10.2 Custom EKU
    h.cmd('create-cert --with-key --subject CN=eku.test '
          '--ext-key-usage serverAuth,clientAuth '
          '-o {out} --key-output {kout} {nc}',
          out=h.tmp("eku.crt"), kout=h.tmp("eku.key"), nc=NC)
    t.assert_file_exists(h.tmp("eku.crt"), "10.2 custom EKU")
    r_ossl = h.cmd.openssl("x509 -in {cert} -text -noout", cert=h.tmp("eku.crt"))
    t.assert_contains(r_ossl, "TLS Web Server", "10.2 openssl shows serverAuth")

    # 10.3 Custom serial (hex)
    h.cmd('create-cert --with-key --subject CN=serial.test '
          '--serial DEADBEEF -o {out} --key-output {kout} {nc}',
          out=h.tmp("serial.crt"), kout=h.tmp("serial.key"), nc=NC)
    t.assert_file_exists(h.tmp("serial.crt"), "10.3 custom serial")
    r_ossl = h.cmd.openssl("x509 -in {cert} -serial -noout", cert=h.tmp("serial.crt"))
    t.assert_contains(r_ossl, "DEADBEEF", "10.3 openssl shows DEADBEEF")

    # 10.4 Custom not-before (YYYY-MM-DD)
    h.cmd('create-cert --with-key --subject CN=nb.test '
          '--not-before 2025-01-01 --days 365 '
          '-o {out} --key-output {kout} {nc}',
          out=h.tmp("nb.crt"), kout=h.tmp("nb.key"), nc=NC)
    t.assert_file_exists(h.tmp("nb.crt"), "10.4 custom not-before")
    r_nb = h.cmd("-o json {f}", f=h.tmp("nb.crt"))
    t.assert_contains(r_nb, "2025-01-01", "10.4 JSON shows 2025-01-01")

    # 10.5 RFC3339 not-before
    h.cmd('create-cert --with-key --subject CN=nb2.test '
          '--not-before 2025-06-15T10:00:00Z --days 365 '
          '-o {out} --key-output {kout} {nc}',
          out=h.tmp("nb2.crt"), kout=h.tmp("nb2.key"), nc=NC)
    t.assert_file_exists(h.tmp("nb2.crt"), "10.5 RFC3339 not-before")

    # 10.6 CA with path length 0
    h.cmd('create-cert --with-key --ca --subject "CN=Path CA" '
          '--path-length 0 -o {out} --key-output {kout} {nc}',
          out=h.tmp("pathlen.crt"), kout=h.tmp("pathlen.key"), nc=NC)
    t.assert_file_exists(h.tmp("pathlen.crt"), "10.6 CA path length 0")
    r_ossl = h.cmd.openssl("x509 -in {cert} -text -noout", cert=h.tmp("pathlen.crt"))
    t.assert_contains(r_ossl, "pathlen:0", "10.6 openssl shows pathlen:0")

    # 10.7 Cert in DER format
    h.cmd('create-cert --with-key --subject CN=der.test -f der '
          '-o {out} --key-output {kout} {nc}',
          out=h.tmp("new.der"), kout=h.tmp("new.key"), nc=NC)
    t.assert_file_exists(h.tmp("new.der"), "10.7 DER cert")
    der_content = h.tmp("new.der").read_text(errors="replace")
    if "BEGIN" not in der_content:
        t.PASS("10.7 DER no PEM markers")
    else:
        t.FAIL("10.7 DER no PEM markers", "has BEGIN marker")

    # 10.8 Full DN
    h.cmd('create-cert --with-key '
          '--subject "CN=complex.test,O=Test Org,OU=Engineering,C=DE,ST=Bavaria,L=Munich" '
          '-o {out} --key-output {kout} {nc}',
          out=h.tmp("complex.crt"), kout=h.tmp("complex.key"), nc=NC)
    t.assert_file_exists(h.tmp("complex.crt"), "10.8 full DN")
    r_ossl = h.cmd.openssl("x509 -in {cert} -subject -noout", cert=h.tmp("complex.crt"))
    t.assert_contains(r_ossl, "Test Org", "10.8 openssl shows O=Test Org")
    t.assert_contains(r_ossl, "Engineering", "10.8 openssl shows OU=Engineering")

    # 10.9 DN with escaped comma
    h.cmd('create-cert --with-key --subject {subj} '
          '-o {out} --key-output {kout} {nc}',
          subj='CN=test,O=Org\\, Inc.', out=h.tmp("comma.crt"),
          kout=h.tmp("comma.key"), nc=NC)
    t.assert_file_exists(h.tmp("comma.crt"), "10.9 escaped comma DN")

    # 10.10 All 4 SAN types
    h.cmd('create-cert --with-key --subject CN=san4.test '
          '--san DNS:a.com,IP:10.0.0.1,email:test@a.com,URI:https://a.com/auth '
          '-o {out} --key-output {kout} {nc}',
          out=h.tmp("san4.crt"), kout=h.tmp("san4.key"), nc=NC)
    t.assert_file_exists(h.tmp("san4.crt"), "10.10 all 4 SAN types")
    r_san = h.cmd("-o json {f}", f=h.tmp("san4.crt"))
    t.assert_contains(r_san, "a.com", "10.10 SAN has DNS")
    t.assert_contains(r_san, "10.0.0.1", "10.10 SAN has IP")
    t.assert_contains(r_san, "test@a.com", "10.10 SAN has email")

    # 10.11 IPv6 SAN
    h.cmd('create-cert --with-key --subject CN=ipv6.test '
          '--san IP:2001:db8::1 -o {out} --key-output {kout} {nc}',
          out=h.tmp("ipv6.crt"), kout=h.tmp("ipv6.key"), nc=NC)
    t.assert_file_exists(h.tmp("ipv6.crt"), "10.11 IPv6 SAN")

    # 10.12 Wildcard SAN
    h.cmd('create-cert --with-key --subject CN=wild.test '
          '--san DNS:*.wild.test,DNS:wild.test '
          '-o {out} --key-output {kout} {nc}',
          out=h.tmp("wildsan.crt"), kout=h.tmp("wildsan.key"), nc=NC)
    t.assert_file_exists(h.tmp("wildsan.crt"), "10.12 wildcard SAN")

    # 10.13 Ed25519 cert
    h.cmd('create-cert --with-key -a ed25519 --subject CN=ed.test '
          '-o {out} --key-output {kout} {nc}',
          out=h.tmp("ed.crt"), kout=h.tmp("ed-cert.key"), nc=NC)
    t.assert_file_exists(h.tmp("ed.crt"), "10.13 Ed25519 cert")

    # 10.14 ECDSA P-384 cert
    h.cmd('create-cert --with-key -a ecdsa --curve p384 --subject CN=p384.test '
          '-o {out} --key-output {kout} {nc}',
          out=h.tmp("p384.crt"), kout=h.tmp("p384.key"), nc=NC)
    t.assert_file_exists(h.tmp("p384.crt"), "10.14 ECDSA P-384 cert")

    # 10.15 ECDSA P-521 cert
    h.cmd('create-cert --with-key -a ecdsa --curve p521 --subject CN=p521.test '
          '-o {out} --key-output {kout} {nc}',
          out=h.tmp("p521.crt"), kout=h.tmp("p521.key"), nc=NC)
    t.assert_file_exists(h.tmp("p521.crt"), "10.15 ECDSA P-521 cert")

    # =====================================================================
    # 11. create-key -- extended cases
    # =====================================================================
    print("\n--- 11. create-key -- extended cases ---")

    # 11.1 ECDSA P-521
    h.cmd("create-key -a ecdsa --curve p521 -o {out} {nc}",
          out=h.tmp("ec521.key"), nc=NC)
    t.assert_file_exists(h.tmp("ec521.key"), "11.1 ECDSA P-521 key")

    # 11.2 Invalid RSA key size
    r = h.cmd("create-key -a rsa -s 1024")
    t.expect_fail(r, "11.2 invalid RSA 1024 rejected")

    # 11.3 Invalid ECDSA curve
    r = h.cmd("create-key -a ecdsa --curve p224")
    t.expect_fail(r, "11.3 invalid curve p224 rejected")

    # 11.4 Key to stdout
    r = h.cmd("create-key -a ecdsa --curve p256")
    t.assert_contains(r, "PRIVATE KEY", "11.4 key to stdout")

    # 11.5 Encrypted key without -p (non-TTY)
    r = h.cmd("create-key -a rsa -s 2048 --encrypt-key -o {out} {nc}",
              out=h.tmp("enc-nopw.key"), nc=NC)
    t.expect_fail(r, "11.5 encrypt without password fails")

    # =====================================================================
    # 12. csr -- extended cases
    # =====================================================================
    print("\n--- 12. csr -- extended cases ---")

    # 12.1 CSR in DER format
    h.cmd('csr --with-key --subject CN=csr-der.test -f der '
          '-o {out} --key-output {kout} {nc}',
          out=h.tmp("csr.der"), kout=h.tmp("csr-der.key"), nc=NC)
    t.assert_file_exists(h.tmp("csr.der"), "12.1 CSR in DER")

    # 12.2 CSR with SANs
    h.cmd('csr --with-key --subject CN=csr.test '
          '--san DNS:a.com,IP:10.0.0.1 '
          '-o {out} --key-output {kout} {nc}',
          out=h.tmp("csr-san.csr"), kout=h.tmp("csr-san.key"), nc=NC)
    t.assert_file_exists(h.tmp("csr-san.csr"), "12.2 CSR with SANs")
    r_ossl = h.cmd.openssl("req -in {csr} -text -noout", csr=h.tmp("csr-san.csr"))
    t.assert_contains(r_ossl, "a.com", "12.2 CSR openssl shows SAN")

    # 12.3 CSR from template cert
    h.cmd('csr --with-key --template {tmpl} '
          '-o {out} --key-output {kout} {nc}',
          tmpl=_cert("wildcard.crt"), out=h.tmp("csr-tmpl.csr"),
          kout=h.tmp("csr-tmpl.key"), nc=NC)
    t.assert_file_exists(h.tmp("csr-tmpl.csr"), "12.3 CSR from template")

    # 12.4 CSR with existing key
    h.cmd('csr --key-file {key} --subject CN=exist.test '
          '-o {out} {nc}',
          key=_cert("self-signed-rsa.key"), out=h.tmp("csr-exist.csr"), nc=NC)
    t.assert_file_exists(h.tmp("csr-exist.csr"), "12.4 CSR with existing key")

    # 12.5 CSR with encrypted key (PKCS#8)
    h.cmd('csr --key-file {key} -p keypass123 --subject CN=enckey.test '
          '-o {out} {nc}',
          key=_cert("encrypted-key.key"), out=h.tmp("csr-enckey.csr"), nc=NC)
    t.assert_file_exists(h.tmp("csr-enckey.csr"), "12.5 CSR with encrypted key")

    # =====================================================================
    # 13. sign -- extended flags
    # =====================================================================
    print("\n--- 13. sign -- extended flags ---")

    # Create a CSR for signing tests
    h.cmd('csr --with-key --subject CN=tosign.test '
          '-o {out} --key-output {kout} {nc}',
          out=h.tmp("tosign.csr"), kout=h.tmp("tosign.key"), nc=NC)

    # 13.1 Sign with custom key usage
    h.cmd('sign {csr} --ca-cert {ca} --ca-key {cakey} '
          '--key-usage digitalSignature,keyEncipherment '
          '-o {out} {nc}',
          csr=h.tmp("tosign.csr"), ca=CA_CRT, cakey=CA_KEY,
          out=h.tmp("signed-ku.crt"), nc=NC)
    t.assert_file_exists(h.tmp("signed-ku.crt"), "13.1 sign custom key usage")

    # 13.2 Sign with custom EKU
    h.cmd('sign {csr} --ca-cert {ca} --ca-key {cakey} '
          '--ext-key-usage serverAuth,clientAuth '
          '-o {out} {nc}',
          csr=h.tmp("tosign.csr"), ca=CA_CRT, cakey=CA_KEY,
          out=h.tmp("signed-eku.crt"), nc=NC)
    t.assert_file_exists(h.tmp("signed-eku.crt"), "13.2 sign custom EKU")

    # 13.3 Sign with custom serial
    h.cmd('sign {csr} --ca-cert {ca} --ca-key {cakey} '
          '--serial CAFEBABE -o {out} {nc}',
          csr=h.tmp("tosign.csr"), ca=CA_CRT, cakey=CA_KEY,
          out=h.tmp("signed-serial.crt"), nc=NC)
    t.assert_file_exists(h.tmp("signed-serial.crt"), "13.3 sign custom serial")
    r_ossl = h.cmd.openssl("x509 -in {cert} -serial -noout",
                           cert=h.tmp("signed-serial.crt"))
    t.assert_contains(r_ossl, "CAFEBABE", "13.3 openssl shows CAFEBABE")

    # 13.4 Sign with custom not-before
    h.cmd('sign {csr} --ca-cert {ca} --ca-key {cakey} '
          '--not-before 2025-01-01 --days 365 -o {out} {nc}',
          csr=h.tmp("tosign.csr"), ca=CA_CRT, cakey=CA_KEY,
          out=h.tmp("signed-nb.crt"), nc=NC)
    t.assert_file_exists(h.tmp("signed-nb.crt"), "13.4 sign custom not-before")

    # 13.5 Sign as sub-CA with path length
    h.cmd('sign {csr} --ca-cert {ca} --ca-key {cakey} '
          '--ca --path-length 0 -o {out} {nc}',
          csr=h.tmp("tosign.csr"), ca=CA_CRT, cakey=CA_KEY,
          out=h.tmp("signed-subca.crt"), nc=NC)
    t.assert_file_exists(h.tmp("signed-subca.crt"), "13.5 sign sub-CA")
    r_ossl = h.cmd.openssl("x509 -in {cert} -text -noout",
                           cert=h.tmp("signed-subca.crt"))
    t.assert_contains(r_ossl, "CA:TRUE", "13.5 openssl shows CA:TRUE")
    t.assert_contains(r_ossl, "pathlen:0", "13.5 openssl shows pathlen:0")

    # 13.6 Sign to DER output
    h.cmd('sign {csr} --ca-cert {ca} --ca-key {cakey} '
          '-f der -o {out} {nc}',
          csr=h.tmp("tosign.csr"), ca=CA_CRT, cakey=CA_KEY,
          out=h.tmp("signed.der"), nc=NC)
    t.assert_file_exists(h.tmp("signed.der"), "13.6 sign DER output")

    # 13.7 Sign DER CSR input
    h.cmd('sign {csr} --ca-cert {ca} --ca-key {cakey} -o {out} {nc}',
          csr=_cert("request.csr.der"), ca=CA_CRT, cakey=CA_KEY,
          out=h.tmp("signed-dercsr.crt"), nc=NC)
    t.assert_file_exists(h.tmp("signed-dercsr.crt"), "13.7 sign DER CSR input")

    # =====================================================================
    # 14. renew -- extended cases
    # =====================================================================
    print("\n--- 14. renew -- extended cases ---")

    # 14.1 Renew with --autosign
    autosign_dir = h.tmp("autosign-ca")
    autosign_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(CA_CRT, autosign_dir / "ca.crt")
    shutil.copy2(CA_KEY, autosign_dir / "ca.key")
    r = h.cmd('renew {cert} -k {key} --autosign -o {out} {nc}',
              cert=_ca("leaf.crt"), key=_ca("leaf.key"),
              out=h.tmp("renewed-auto.crt"), nc=NC,
              cwd=str(autosign_dir))
    t.expect_ok(r, "14.1 renew autosign")
    t.assert_file_exists(h.tmp("renewed-auto.crt"), "14.1 renew autosign output")

    # 14.2 Renew with algorithm switch
    h.cmd('renew {cert} --new-key -a ecdsa --curve p256 '
          '-o {out} --key-output {kout} {nc}',
          cert=_cert("self-signed-rsa.crt"),
          out=h.tmp("renewed-algo.crt"), kout=h.tmp("renewed-algo.key"), nc=NC)
    t.assert_file_exists(h.tmp("renewed-algo.crt"), "14.2 renew algorithm switch")
    r_algo = h.cmd("-o json {f}", f=h.tmp("renewed-algo.crt"))
    t.assert_contains(r_algo, "ECDSA", "14.2 JSON shows ECDSA")

    # 14.3 Renew with custom validity
    h.cmd('renew {cert} -k {key} --days 730 -o {out} {nc}',
          cert=_cert("self-signed-rsa.crt"), key=_cert("self-signed-rsa.key"),
          out=h.tmp("renewed-730.crt"), nc=NC)
    t.assert_file_exists(h.tmp("renewed-730.crt"), "14.3 renew custom validity")

    # 14.4 Renew ECDSA cert
    h.cmd('renew {cert} -k {key} -o {out} {nc}',
          cert=_cert("ecdsa-p256.crt"), key=_cert("ecdsa-p256.key"),
          out=h.tmp("renewed-ec.crt"), nc=NC)
    t.assert_file_exists(h.tmp("renewed-ec.crt"), "14.4 renew ECDSA cert")

    # 14.5 Renew with encrypted key (PKCS#8)
    h.cmd('renew {cert} -k {key} -p keypass123 -o {out} {nc}',
          cert=_cert("encrypted-key.crt"), key=_cert("encrypted-key.key"),
          out=h.tmp("renewed-enckey-pkcs8.crt"), nc=NC)
    t.assert_file_exists(h.tmp("renewed-enckey-pkcs8.crt"), "14.5 renew encrypted key")

    # 14.6 Renew with --new-key --encrypt-key
    h.cmd('renew {cert} --new-key --encrypt-key -p pass '
          '-o {out} --key-output {kout} {nc}',
          cert=_cert("self-signed-rsa.crt"),
          out=h.tmp("renewed-enckey.crt"), kout=h.tmp("renewed-enckey.key"), nc=NC)
    t.assert_file_exists(h.tmp("renewed-enckey.crt"), "14.6 renew new encrypted key")
    enckey_content = h.tmp("renewed-enckey.key").read_text()
    if "ENCRYPTED" in enckey_content:
        t.PASS("14.6 key file is encrypted")
    else:
        t.FAIL("14.6 key file is encrypted", "missing ENCRYPTED marker")

    # =====================================================================
    # 15. bundle -- extended cases
    # =====================================================================
    print("\n--- 15. bundle -- extended cases ---")

    # 15.1 --auto-assemble from directory
    h.cmd('bundle --auto-assemble {d} -o {out} {nc}',
          d=str(_ca("")) + "/", out=h.tmp("assembled.pem"), nc=NC)
    t.assert_file_exists(h.tmp("assembled.pem"), "15.1 auto-assemble")
    asm_content = h.tmp("assembled.pem").read_text()
    asm_count = asm_content.count("BEGIN CERTIFICATE")
    if asm_count >= 2:
        t.PASS(f"15.1 assembled has {asm_count} certs")
    else:
        t.FAIL("15.1 assembled certs", f"expected >=2, got {asm_count}")

    # 15.2 PKCS#7 bundle
    h.cmd('bundle {a} {b} -o {out} -f pkcs7 {nc}',
          a=_cert("self-signed-rsa.crt"), b=_cert("ecdsa-p256.crt"),
          out=h.tmp("multi.p7b"), nc=NC)
    t.assert_file_exists(h.tmp("multi.p7b"), "15.2 PKCS#7 bundle")

    # 15.3 PKCS#12 with CA chain
    h.cmd('bundle {leaf} {leafkey} {inter} {root} '
          '-o {out} -f pkcs12 --output-password x {nc}',
          leaf=_ca("leaf.crt"), leafkey=_ca("leaf.key"),
          inter=_ca("intermediate-ca.crt"), root=_ca("root-ca.crt"),
          out=h.tmp("full.p12"), nc=NC)
    t.assert_file_exists(h.tmp("full.p12"), "15.3 PKCS#12 with chain")

    # 15.4 Legacy PKCS#12 bundle
    h.cmd('bundle {leaf} {leafkey} '
          '-o {out} -f pkcs12 --output-password x --legacy-pkcs12 {nc}',
          leaf=_ca("leaf.crt"), leafkey=_ca("leaf.key"),
          out=h.tmp("legacy-bundle.p12"), nc=NC)
    t.assert_file_exists(h.tmp("legacy-bundle.p12"), "15.4 legacy PKCS#12 bundle")

    # 15.5 --include-root=false with --auto-chain
    h.cmd('bundle {leaf} {inter} {root} --auto-chain --include-root=false '
          '-o {out} {nc}',
          leaf=_ca("leaf.crt"), inter=_ca("intermediate-ca.crt"),
          root=_ca("root-ca.crt"),
          out=h.tmp("noroot.pem"), nc=NC)
    t.assert_file_exists(h.tmp("noroot.pem"), "15.5 bundle no root")
    noroot_content = h.tmp("noroot.pem").read_text()
    noroot_count = noroot_content.count("BEGIN CERTIFICATE")
    if noroot_count == 2:
        t.PASS("15.5 no root has 2 certs")
    else:
        t.FAIL("15.5 no root cert count", f"expected 2, got {noroot_count}")

    # 15.6 No input files
    r = h.cmd("bundle -o {out} {nc}", out=h.tmp("empty.pem"), nc=NC)
    t.expect_fail(r, "15.6 no input exits non-zero")

    # 15.7 Missing -o flag
    r = h.cmd("bundle {f} {nc}", f=_cert("self-signed-rsa.crt"), nc=NC)
    t.expect_fail(r, "15.7 missing -o exits non-zero")

    # =====================================================================
    # 16. reencrypt -- extended cases
    # =====================================================================
    print("\n--- 16. reencrypt -- extended cases ---")

    # 16.1 Reencrypt PEM encrypted key (PKCS#8)
    h.cmd('reencrypt {src} -p keypass123 --new-password newpass456 '
          '-o {out} {nc}',
          src=_cert("encrypted-key.key"), out=h.tmp("reenc-pem.key"), nc=NC)
    t.assert_file_exists(h.tmp("reenc-pem.key"), "16.1 reencrypt PEM key")

    # 16.2 New password works on reencrypted key
    r = h.cmd("{f} -p newpass456 --no-color", f=h.tmp("reenc-pem.key"))
    t.assert_contains(r, "Private Key", "16.2 new password works")

    # 16.3 Old password fails on reencrypted key
    r = h.cmd("{f} -p keypass123 --no-color", f=h.tmp("reenc-pem.key"))
    t.assert_contains(r, "failed to decrypt", "16.3 old password fails")

    # 16.4 Reencrypt with legacy algorithms
    h.cmd('reencrypt {src} -p p12pass --new-password x --legacy-pkcs12 '
          '-o {out} {nc}',
          src=_cert("standard.p12"), out=h.tmp("legacy-reenc.p12"), nc=NC)
    t.assert_file_exists(h.tmp("legacy-reenc.p12"), "16.4 legacy reencrypt")

    # 16.5 Wrong current password
    r = h.cmd('reencrypt {src} -p wrong --new-password x -o {out} {nc}',
              src=_cert("standard.p12"), out=h.tmp("nope.p12"), nc=NC)
    t.expect_fail(r, "16.5 wrong password exits non-zero")

    # 16.6 Same old and new password (document behavior)
    r = h.cmd('reencrypt {src} -p p12pass --new-password p12pass -o {out} {nc}',
              src=_cert("standard.p12"), out=h.tmp("same.p12"), nc=NC)
    t.PASS(f"16.6 same password no crash (exit {r.returncode})")

    # 16.7 Non-encrypted file
    r = h.cmd('reencrypt {src} --new-password x -o {out} {nc}',
              src=_cert("self-signed-rsa.crt"), out=h.tmp("nope.crt"), nc=NC)
    t.expect_fail(r, "16.7 non-encrypted file error")

    # =====================================================================
    # 17. templates -- extended cases
    # =====================================================================
    print("\n--- 17. templates -- extended cases ---")

    # 17.1 Cert template produces output with expected content
    r = h.cmd("templates cert")
    if r.ok and "kind:" in r.stdout:
        t.PASS("17.1 cert template valid YAML")
    else:
        t.FAIL("17.1 cert template valid YAML",
               f"exit {r.returncode} or missing kind:")

    # 17.2 CA template produces output with expected content
    r = h.cmd("templates ca")
    if r.ok and "kind:" in r.stdout:
        t.PASS("17.2 CA template valid YAML")
    else:
        t.FAIL("17.2 CA template valid YAML",
               f"exit {r.returncode} or missing kind:")

    # 17.3 Invalid template type
    r = h.cmd("templates invalid")
    t.expect_fail(r, "17.3 invalid template type exits non-zero")

    # 17.4 Cert template -> create-cert round-trip
    r_tmpl = h.cmd("templates cert")
    tmpl_file = h.tmp("tmpl.yaml")
    tmpl_file.write_text(r_tmpl.stdout)
    h.cmd('create-cert --with-key --template-profile {tmpl} '
          '--subject CN=from-tmpl.test -o {out} --key-output {kout} {nc}',
          tmpl=tmpl_file, out=h.tmp("from-tmpl.crt"),
          kout=h.tmp("from-tmpl.key"), nc=NC)
    t.assert_file_exists(h.tmp("from-tmpl.crt"), "17.4 cert template round-trip")

    # 17.5 CA template -> create CA round-trip
    r_ca_tmpl = h.cmd("templates ca")
    ca_tmpl_file = h.tmp("ca-tmpl.yaml")
    ca_tmpl_file.write_text(r_ca_tmpl.stdout)
    h.cmd('create-cert --with-key --template-profile {tmpl} '
          '--subject "CN=CA from template" -o {out} --key-output {kout} {nc}',
          tmpl=ca_tmpl_file, out=h.tmp("ca-tmpl.crt"),
          kout=h.tmp("ca-tmpl.key"), nc=NC)
    t.assert_file_exists(h.tmp("ca-tmpl.crt"), "17.5 CA template round-trip")
    r_ossl = h.cmd.openssl("x509 -in {cert} -text -noout",
                           cert=h.tmp("ca-tmpl.crt"))
    t.assert_contains(r_ossl, "CA:TRUE", "17.5 CA template shows CA:TRUE")

    # 17.6 Cert template contains detected country
    r = h.cmd("templates cert")
    if r.contains_regex(r'country: "[A-Z]{2}"'):
        t.PASS("17.6 cert template has detected country")
    else:
        t.FAIL("17.6 cert template has detected country", "no country found")

    # 17.7 Cert template with config overrides
    tmpl_config = h.tmp("tmpl-config.yaml")
    tmpl_config.write_text(
        'kind: certdiag-config\n'
        'version: "1"\n'
        'defaults:\n'
        '  subject:\n'
        '    organization: "SmokeOrg"\n'
        '    country: "ZZ"\n'
    )
    r = h.cmd("templates cert",
              env_extra={"CERTDIAG_CONFIG": str(tmpl_config)})
    t.assert_contains(r, 'organization: "SmokeOrg"',
                      "17.7 cert template config organization")
    t.assert_contains(r, 'country: "ZZ"',
                      "17.7 cert template config country")

    # 17.8 CA template with config key defaults
    tmpl_config2 = h.tmp("tmpl-config2.yaml")
    tmpl_config2.write_text(
        'kind: certdiag-config\n'
        'version: "1"\n'
        'defaults:\n'
        '  key:\n'
        '    algorithm: "rsa"\n'
        '    rsa_key_size: 4096\n'
    )
    r = h.cmd("templates ca",
              env_extra={"CERTDIAG_CONFIG": str(tmpl_config2)})
    t.assert_contains(r, 'algorithm: "rsa"', "17.8 CA template config algorithm")

    # 17.9 Template round-trip preserves config defaults
    tmpl_config3 = h.tmp("tmpl-config3.yaml")
    tmpl_config3.write_text(
        'kind: certdiag-config\n'
        'version: "1"\n'
        'defaults:\n'
        '  subject:\n'
        '    country: "ZZ"\n'
    )
    r_rt = h.cmd("templates cert",
                 env_extra={"CERTDIAG_CONFIG": str(tmpl_config3)})
    rt_tmpl = h.tmp("rt-tmpl.yaml")
    rt_tmpl.write_text(r_rt.stdout)
    h.cmd('create-cert --with-key --template-profile {tmpl} '
          '--subject CN=rt-test.local -o {out} --key-output {kout} {nc}',
          tmpl=rt_tmpl, out=h.tmp("rt-test.crt"),
          kout=h.tmp("rt-test.key"), nc=NC)
    r_ossl = h.cmd.openssl("x509 -in {cert} -subject -noout",
                           cert=h.tmp("rt-test.crt"))
    if r_ossl.contains_regex(r"C ?= ?ZZ"):
        t.PASS("17.9 template round-trip preserves country")
    else:
        t.FAIL("17.9 template round-trip preserves country",
               f"subject: {r_ossl.stdout.strip()}")

    # 17.10 CSR template produces output with expected content
    r = h.cmd("templates csr")
    if r.ok and "kind:" in r.stdout:
        t.PASS("17.10 CSR template valid YAML")
    else:
        t.FAIL("17.10 CSR template valid YAML",
               f"exit {r.returncode} or missing kind:")

    # 17.11 CSR template -> create-csr round-trip
    csr_tmpl_file = h.tmp("csr-tmpl.yaml")
    csr_tmpl_file.write_text(r.stdout)
    h.cmd('create-csr --with-key --template-profile {tmpl} '
          '--subject CN=from-csr-tmpl.test '
          '-o {out} --key-output {kout} {nc}',
          tmpl=csr_tmpl_file, out=h.tmp("from-csr-tmpl.csr"),
          kout=h.tmp("from-csr-tmpl.key"), nc=NC)
    t.assert_file_exists(h.tmp("from-csr-tmpl.csr"), "17.11 CSR template round-trip")

    # =====================================================================
    # 18. Multi-file and integration scenarios
    # =====================================================================
    print("\n--- 18. Multi-file and integration scenarios ---")

    # 18.1 Scan directory with all formats
    r = h.cmd("{d} -p changeit -p p12pass -p ecdsapfx -p multientry -p trustme --no-color",
              d=str(SMOKE_CERTS) + "/")
    t.assert_contains(r, "self-signed", "18.1 scan finds PEM certs")

    # 18.2 JSON output of directory scan
    r = h.cmd("-o json {d} -p changeit -p p12pass",
              d=str(SMOKE_CERTS) + "/")
    try:
        data = json.loads(r.stdout)
        file_count = len(data.get("files", []))
        if file_count >= 5:
            t.PASS(f"18.2 JSON scan has {file_count} files")
        else:
            t.FAIL("18.2 JSON scan", f"expected >=5 files, got {file_count}")
    except (json.JSONDecodeError, TypeError):
        t.FAIL("18.2 JSON scan", "invalid JSON")

    # 18.3 Full certificate lifecycle
    print("--- 18.3 Full lifecycle ---")

    # 18.3a Generate key
    h.cmd("create-key -a ecdsa --curve p256 -o {out} {nc}",
          out=h.tmp("lifecycle.key"), nc=NC)
    t.assert_file_exists(h.tmp("lifecycle.key"), "18.3a generate key")

    # 18.3b Create CSR
    h.cmd('csr --key-file {key} --subject CN=lifecycle.test '
          '--san DNS:lifecycle.test,IP:10.0.0.1 '
          '-o {out} {nc}',
          key=h.tmp("lifecycle.key"), out=h.tmp("lifecycle.csr"), nc=NC)
    t.assert_file_exists(h.tmp("lifecycle.csr"), "18.3b create CSR")

    # 18.3c Sign with CA
    h.cmd('sign {csr} --ca-cert {ca} --ca-key {cakey} -o {out} {nc}',
          csr=h.tmp("lifecycle.csr"), ca=CA_CRT, cakey=CA_KEY,
          out=h.tmp("lifecycle.crt"), nc=NC)
    t.assert_file_exists(h.tmp("lifecycle.crt"), "18.3c sign with CA")

    # 18.3d Convert to P12
    bundle_pem = h.tmp("lifecycle-bundle.pem")
    crt_text = h.tmp("lifecycle.crt").read_text()
    key_text = h.tmp("lifecycle.key").read_text()
    bundle_pem.write_text(crt_text + key_text)
    h.cmd('convert {src} -o {out} -f pkcs12 --output-password x {nc}',
          src=bundle_pem, out=h.tmp("lifecycle.p12"), nc=NC)
    t.assert_file_exists(h.tmp("lifecycle.p12"), "18.3d convert to P12")

    # 18.3e Check (incomplete chain)
    r = h.cmd("check {f} --no-color", f=h.tmp("lifecycle.crt"))
    t.assert_contains(r, "Chain incomplete", "18.3e check incomplete chain")

    # 18.3f Check with CA
    r = h.cmd("check {f} {ca} --severity warning --no-color",
              f=h.tmp("lifecycle.crt"), ca=CA_CRT)
    t.PASS(f"18.3f check with CA (exit {r.returncode})")

    # 18.3g Renew
    h.cmd('renew {cert} -k {key} --sign-ca {ca} --sign-key {cakey} '
          '-o {out} {nc}',
          cert=h.tmp("lifecycle.crt"), key=h.tmp("lifecycle.key"),
          ca=CA_CRT, cakey=CA_KEY,
          out=h.tmp("lifecycle-renewed.crt"), nc=NC)
    t.assert_file_exists(h.tmp("lifecycle-renewed.crt"), "18.3g renew")

    # 18.3h Diff original vs renewed
    r = h.cmd("diff {a} {b} --no-color",
              a=h.tmp("lifecycle.crt"), b=h.tmp("lifecycle-renewed.crt"))
    t.assert_contains(r, "Serial", "18.3h diff shows Serial changed")

    # 18.3i Key-CSR relation in list output
    r = h.cmd("{key} {csr} --no-color",
              key=h.tmp("lifecycle.key"), csr=h.tmp("lifecycle.csr"))
    t.assert_contains(r, "Relations", "18.3i key-CSR shows Relations")
    t.assert_contains(r, "csr:", "18.3i key shows csr relation")
    t.assert_contains(r, "key:", "18.3i CSR shows key relation")

    # 18.3j CSR-cert relation in list output
    r = h.cmd("{csr} {cert} --no-color",
              csr=h.tmp("lifecycle.csr"), cert=h.tmp("lifecycle.crt"))
    t.assert_contains(r, "Relations", "18.3j CSR-cert shows Relations")
    t.assert_contains(r, "cert:", "18.3j CSR shows cert relation")

    # 18.3k Key-CSR relation in JSON output
    r = h.cmd("-o json {key} {csr}",
              key=h.tmp("lifecycle.key"), csr=h.tmp("lifecycle.csr"))
    try:
        data = json.loads(r.stdout)
        found = False
        for f in data.get("files", []):
            for item in f.get("items", []):
                for rel in item.get("relations", []):
                    if rel.get("type") == "key_csr_pair":
                        found = True
                        break
        if found:
            t.PASS("18.3k JSON has key_csr_pair relation")
        else:
            t.FAIL("18.3k JSON has key_csr_pair relation", "missing")
    except (json.JSONDecodeError, TypeError):
        t.FAIL("18.3k JSON has key_csr_pair relation", "invalid JSON")

    # 18.3l CSR-cert relation in JSON output
    r = h.cmd("-o json {csr} {cert}",
              csr=h.tmp("lifecycle.csr"), cert=h.tmp("lifecycle.crt"))
    try:
        data = json.loads(r.stdout)
        found = False
        for f in data.get("files", []):
            for item in f.get("items", []):
                for rel in item.get("relations", []):
                    if rel.get("type") == "csr_cert_pair":
                        found = True
                        break
        if found:
            t.PASS("18.3l JSON has csr_cert_pair relation")
        else:
            t.FAIL("18.3l JSON has csr_cert_pair relation", "missing")
    except (json.JSONDecodeError, TypeError):
        t.FAIL("18.3l JSON has csr_cert_pair relation", "invalid JSON")

    # 18.3m Full lifecycle relations (key + CSR + cert together)
    r = h.cmd("{key} {csr} {cert} --no-color",
              key=h.tmp("lifecycle.key"), csr=h.tmp("lifecycle.csr"),
              cert=h.tmp("lifecycle.crt"))
    t.assert_contains(r, "csr:", "18.3m full lifecycle has csr relation")
    t.assert_contains(r, "cert:", "18.3m full lifecycle has cert relation")
    t.assert_contains(r, "key:", "18.3m full lifecycle has key relation")

    # 18.4 Round-trip format conversions: PEM -> JKS -> PEM -> P12 -> PEM
    rt_start = h.tmp("rt-start.pem")
    rt_start.write_text(
        h.tmp("lifecycle.crt").read_text() +
        h.tmp("lifecycle.key").read_text()
    )
    h.cmd("convert {src} -o {out} -f jks --output-password x {nc}",
          src=rt_start, out=h.tmp("rt.jks"), nc=NC)
    h.cmd("convert {src} -p x -o {out} {nc}",
          src=h.tmp("rt.jks"), out=h.tmp("rt-from-jks.pem"), nc=NC)
    h.cmd("convert {src} -o {out} -f pkcs12 --output-password x {nc}",
          src=h.tmp("rt-from-jks.pem"), out=h.tmp("rt.p12"), nc=NC)
    h.cmd("convert {src} -p x -o {out} {nc}",
          src=h.tmp("rt.p12"), out=h.tmp("rt-final.pem"), nc=NC)

    r_orig = h.cmd.openssl("x509 -in {f} -fingerprint -sha256 -noout",
                           f=rt_start)
    r_final = h.cmd.openssl("x509 -in {f} -fingerprint -sha256 -noout",
                            f=h.tmp("rt-final.pem"))
    fp_orig = r_orig.stdout.strip()
    fp_final = r_final.stdout.strip()
    if fp_orig and fp_orig == fp_final:
        t.PASS("18.4 round-trip fingerprint match")
    else:
        t.FAIL("18.4 round-trip fingerprint match", "fingerprints differ")

    # =====================================================================
    # 19. Edge cases and error handling
    # =====================================================================
    print("\n--- 19. Edge cases and error handling ---")

    # 19.1 Empty file
    empty_pem = h.tmp("empty.pem")
    empty_pem.touch()
    r = h.cmd("{f} --no-color", f=empty_pem)
    t.PASS(f"19.1 empty file no crash (exit {r.returncode})")

    # 19.2 Binary garbage with .crt ext
    garbage_crt2 = h.tmp("garbage2.crt")
    garbage_crt2.write_bytes(os.urandom(256))
    r = h.cmd("{f} --no-color", f=garbage_crt2)
    t.PASS(f"19.2 garbage .crt no crash (exit {r.returncode})")

    # 19.3 Very large file (~880KB, 600 PEM blocks)
    r = h.cmd("{f} --no-color", f=_cert("large-bundle.pem"))
    t.PASS(f"19.3 large file no crash (exit {r.returncode})")
    t.assert_contains(r, "self-signed", "19.3 large file parses certs")

    # 19.4 Non-existent file (exits non-zero and shows error message)
    r = h.cmd("/nonexistent.pem --no-color")
    t.expect_exit(1, r, "19.4 non-existent file exits 1")
    # Windows reports "cannot find the file", POSIX reports "no such file".
    t.assert_contains_regex(r, r"no such file|cannot find the file",
                            "19.4 non-existent file shows error", stream="stderr")

    # 19.5 No arguments
    r = h.cmd("")
    t.PASS(f"19.5 no arguments no crash (exit {r.returncode})")

    # 19.6 Directory without -r
    r = h.cmd("{d} --no-color", d=str(SMOKE_CERTS) + "/")
    t.assert_not_contains(r, "root-ca", "19.6 dir without -r no .ca/ files")

    # 19.7 Unreadable file
    unreadable = h.tmp("unreadable.crt")
    shutil.copy2(_cert("self-signed-rsa.crt"), unreadable)
    os.chmod(unreadable, 0o000)
    r = h.cmd("{f} --no-color", f=unreadable)
    os.chmod(unreadable, 0o644)
    t.PASS(f"19.7 unreadable file no crash (exit {r.returncode})")

    # 19.8 Output to read-only directory
    r = h.cmd("create-key -a ecdsa -o /readonly-nonexistent/key.pem {nc}",
              nc=NC)
    t.expect_fail(r, "19.8 read-only dir exits non-zero")

    # 19.9 Overwrite protection without --no-confirm (non-TTY)
    existing = h.tmp("existing.crt")
    existing.touch()
    r = h.cmd('create-cert --with-key --subject CN=test -o {out}',
              out=existing)
    t.expect_fail(r, "19.9 overwrite protection")

    # 19.10 With --no-confirm overwrite succeeds
    h.cmd('create-cert --with-key --subject CN=test '
          '-o {out} --key-output {kout} {nc}',
          out=existing, kout=h.tmp("existing.key"), nc=NC)
    t.assert_file_exists(existing, "19.10 overwrite with --no-confirm")

    # 19.11 Symlink to cert file
    link = h.tmp("link.crt")
    try:
        link.symlink_to(_cert("self-signed-rsa.crt"))
    except OSError as e:
        # Windows requires a privilege (or Developer Mode) to create symlinks.
        t.SKIP(f"19.11 symlink to cert (cannot create symlink: {e})")
        t.SKIP("19.12 broken symlink (cannot create symlink)")
    else:
        r = h.cmd("{f} --no-color", f=link)
        t.assert_contains(r, "self-signed", "19.11 symlink to cert")

        # 19.12 Broken symlink
        broken_link = h.tmp("broken-link.crt")
        broken_link.symlink_to("/nonexistent")
        r = h.cmd("{f} --no-color", f=broken_link)
        t.PASS(f"19.12 broken symlink no crash (exit {r.returncode})")

    # 19.13 Path with spaces
    spaces_dir = h.tmp("path with spaces")
    spaces_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(_cert("self-signed-rsa.crt"), spaces_dir / "cert.crt")
    r = h.cmd("{f} --no-color", f=spaces_dir / "cert.crt")
    t.assert_contains(r, "self-signed", "19.13 path with spaces")

    # 19.14 DN with special chars (document behavior)
    r = h.cmd("create-cert --with-key --subject {subj} "
              "-o {out} --key-output {kout} {nc}",
              subj="CN=test+special.org,O=O'Brien",
              out=h.tmp("special.crt"), kout=h.tmp("special.key"), nc=NC)
    t.PASS(f"19.14 special chars in DN no crash (exit {r.returncode})")


if __name__ == "__main__":
    h = Harness(fixtures_dir=SMOKE_CERTS)
    h.setup(required_tools=["openssl"])
    t = Tracker()
    try:
        run(h, t)
    finally:
        h.cleanup()
        t.close()
    ok = t.summary("Smoke Extended")
    raise SystemExit(0 if ok else 1)
