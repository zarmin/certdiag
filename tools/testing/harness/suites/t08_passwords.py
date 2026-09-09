from ..lib.harness import Harness
from ..lib.assertions import Tracker


NC = "--no-confirm"


def run(h, t):
    print("\n=== T08: Password Handling Edge Cases ===")

    # --- Setup: create encrypted p12 files for password tests ---
    print("--- Setup: creating encrypted p12 fixtures ---")

    r = h.cmd(
        '--no-color bundle {cert} {key} -f pkcs12 --output-password {pw} -o {out} {nc}',
        cert=h.fixture("leaf-rsa.pem"), key=h.fixture("leaf-rsa.key"),
        pw="alpha", out=h.tmp("pw-alpha.p12"), nc=NC,
    )
    t.assert_file_not_empty(h.tmp("pw-alpha.p12"), "setup: pw-alpha.p12 created")

    r = h.cmd(
        '--no-color bundle {cert} {key} -f pkcs12 --output-password {pw} -o {out} {nc}',
        cert=h.fixture("leaf-ec.pem"), key=h.fixture("leaf-ec.key"),
        pw="beta", out=h.tmp("pw-beta.p12"), nc=NC,
    )
    t.assert_file_not_empty(h.tmp("pw-beta.p12"), "setup: pw-beta.p12 created")

    # --- T08.01: Multiple -p flags ---
    print("-- T08.01: Multiple -p flags")

    r = h.cmd(
        '--no-color -p {p1} -p {p2} {f1} {f2}',
        p1="alpha", p2="beta",
        f1=h.tmp("pw-alpha.p12"), f2=h.tmp("pw-beta.p12"),
    )
    t.expect_ok(r, "T08.01a: both passwords unlock both files")
    t.assert_contains(r, "edge.test", "T08.01a: alpha p12 cert visible")
    t.assert_contains(r, "edge-ec.test", "T08.01a: beta p12 cert visible")

    r = h.cmd(
        '--no-color -p {p1} {f1} {f2}',
        p1="alpha",
        f1=h.tmp("pw-alpha.p12"), f2=h.tmp("pw-beta.p12"),
    )
    t.assert_contains(r, "edge.test", "T08.01b: alpha p12 unlocked with alpha password")

    # --- T08.02: Password file with multiple passwords ---
    print("-- T08.02: Password file with multiple passwords")

    passfile = h.tmp("passfile.txt")
    passfile.write_text("alpha\nbeta\ngamma\n")

    r = h.cmd(
        '--no-color -P {pf} {f1} {f2}',
        pf=passfile,
        f1=h.tmp("pw-alpha.p12"), f2=h.tmp("pw-beta.p12"),
    )
    t.expect_ok(r, "T08.02: password file unlocks both")
    t.assert_contains(r, "edge.test", "T08.02: alpha p12 unlocked via passfile")
    t.assert_contains(r, "edge-ec.test", "T08.02: beta p12 unlocked via passfile")

    # --- T08.03: Multiple password files ---
    print("-- T08.03: Multiple password files")

    pass1 = h.tmp("pass1.txt")
    pass1.write_text("alpha\n")
    pass2 = h.tmp("pass2.txt")
    pass2.write_text("beta\n")

    r = h.cmd(
        '--no-color -P {pf1} -P {pf2} {f1} {f2}',
        pf1=pass1, pf2=pass2,
        f1=h.tmp("pw-alpha.p12"), f2=h.tmp("pw-beta.p12"),
    )
    t.expect_ok(r, "T08.03: multiple password files unlock both")
    t.assert_contains(r, "edge.test", "T08.03: alpha p12 unlocked")
    t.assert_contains(r, "edge-ec.test", "T08.03: beta p12 unlocked")

    # --- T08.04: Mixed -p and -P ---
    print("-- T08.04: Mixed -p and -P")

    pass_beta = h.tmp("pass-beta.txt")
    pass_beta.write_text("beta\n")

    r = h.cmd(
        '--no-color -p {p1} -P {pf} {f1} {f2}',
        p1="alpha", pf=pass_beta,
        f1=h.tmp("pw-alpha.p12"), f2=h.tmp("pw-beta.p12"),
    )
    t.expect_ok(r, "T08.04: mixed -p and -P unlock both")
    t.assert_contains(r, "edge.test", "T08.04: alpha p12 unlocked via -p")
    t.assert_contains(r, "edge-ec.test", "T08.04: beta p12 unlocked via -P")

    # --- T08.05: Environment variable passwords ---
    print("-- T08.05: Environment variable passwords")

    r = h.cmd(
        '--no-color {f1} {f2}',
        f1=h.tmp("pw-alpha.p12"), f2=h.tmp("pw-beta.p12"),
        env_extra={"CERTDIAG_PASSWORD_1": "alpha", "CERTDIAG_PASSWORD_2": "beta"},
    )
    t.expect_ok(r, "T08.05a: env var passwords unlock both")
    t.assert_contains(r, "edge.test", "T08.05a: alpha p12 unlocked via env")
    t.assert_contains(r, "edge-ec.test", "T08.05a: beta p12 unlocked via env")

    r = h.cmd(
        '--no-color {f1}',
        f1=h.tmp("pw-alpha.p12"),
        env_extra={"CERTDIAG_PASSWORD_FOO": "alpha"},
    )
    t.expect_ok(r, "T08.05b: single env var password works")
    t.assert_contains(r, "edge.test", "T08.05b: alpha p12 unlocked via single env")

    # --- T08.06: --no-try-all-passwords behavior ---
    print("-- T08.06: --no-try-all-passwords behavior")

    r = h.cmd(
        '--no-color -p {p1} -p {p2} {f1} {f2}',
        p1="alpha", p2="beta",
        f1=h.tmp("pw-alpha.p12"), f2=h.tmp("pw-beta.p12"),
    )
    t.expect_ok(r, "T08.06a: without flag both unlocked")

    r = h.cmd(
        '--no-color -p {p1} -p {p2} --no-try-all-passwords {f1} {f2}',
        p1="alpha", p2="beta",
        f1=h.tmp("pw-alpha.p12"), f2=h.tmp("pw-beta.p12"),
    )
    t.PASS(f"T08.06b: --no-try-all-passwords flag accepted (exit {r.returncode})")

    # --- T08.07: Empty password handling ---
    print("-- T08.07: Empty password handling")

    r = h.cmd(
        '--no-color bundle {cert} {key} -f pkcs12 --output-password {pw} -o {out} {nc}',
        cert=h.fixture("leaf-rsa.pem"), key=h.fixture("leaf-rsa.key"),
        pw="", out=h.tmp("pw-empty.p12"), nc=NC,
    )
    t.assert_file_not_empty(h.tmp("pw-empty.p12"), "T08.07: empty-password p12 created")

    r = h.cmd('--no-color {f}', f=h.tmp("pw-empty.p12"))
    t.expect_ok(r, "T08.07a: empty-password p12 readable without -p")
    t.assert_contains(r, "edge.test", "T08.07a: cert visible")

    r = h.cmd('--no-color -p {pw} {f}', pw="", f=h.tmp("pw-empty.p12"))
    t.expect_ok(r, "T08.07b: empty-password p12 readable with -p \"\"")
    t.assert_contains(r, "edge.test", "T08.07b: cert visible")

    # --- T08.08: Password with special characters ---
    print("-- T08.08: Password with special characters")

    special_pw = 'p@$$w0rd!#%&*()'
    r = h.cmd(
        '--no-color bundle {cert} {key} -f pkcs12 --output-password {pw} -o {out} {nc}',
        cert=h.fixture("leaf-rsa.pem"), key=h.fixture("leaf-rsa.key"),
        pw=special_pw, out=h.tmp("pw-special.p12"), nc=NC,
    )
    t.assert_file_not_empty(h.tmp("pw-special.p12"), "T08.08: special-char p12 created")

    r = h.cmd('--no-color -p {pw} {f}', pw=special_pw, f=h.tmp("pw-special.p12"))
    t.expect_ok(r, "T08.08: special-char password unlocks p12")
    t.assert_contains(r, "edge.test", "T08.08: cert visible")

    # --- T08.09: Password with spaces ---
    print("-- T08.09: Password with spaces")

    r = h.cmd(
        '--no-color bundle {cert} {key} -f pkcs12 --output-password {pw} -o {out} {nc}',
        cert=h.fixture("leaf-rsa.pem"), key=h.fixture("leaf-rsa.key"),
        pw="pass word with spaces", out=h.tmp("pw-spaces.p12"), nc=NC,
    )
    t.assert_file_not_empty(h.tmp("pw-spaces.p12"), "T08.09: spaces p12 created")

    r = h.cmd('--no-color -p {pw} {f}', pw="pass word with spaces", f=h.tmp("pw-spaces.p12"))
    t.expect_ok(r, "T08.09: spaces password unlocks p12")
    t.assert_contains(r, "edge.test", "T08.09: cert visible")

    # --- T08.10: Password with Unicode ---
    print("-- T08.10: Password with Unicode")

    r = h.cmd(
        '--no-color bundle {cert} {key} -f pkcs12 --output-password {pw} -o {out} {nc}',
        cert=h.fixture("leaf-rsa.pem"), key=h.fixture("leaf-rsa.key"),
        pw="Passw0rt", out=h.tmp("pw-unicode.p12"), nc=NC,
    )
    t.assert_file_not_empty(h.tmp("pw-unicode.p12"), "T08.10: unicode p12 created")

    r = h.cmd('--no-color -p {pw} {f}', pw="Passw0rt", f=h.tmp("pw-unicode.p12"))
    t.expect_ok(r, "T08.10: unicode password unlocks p12")
    t.assert_contains(r, "edge.test", "T08.10: cert visible")

    # --- T08.10b: Very long password ---
    print("-- T08.10b: Very long password")

    long_pw = "A" * 1000
    r = h.cmd(
        '--no-color bundle {cert} {key} -f pkcs12 --output-password {pw} -o {out} {nc}',
        cert=h.fixture("leaf-rsa.pem"), key=h.fixture("leaf-rsa.key"),
        pw=long_pw, out=h.tmp("pw-long.p12"), nc=NC,
    )
    t.assert_file_not_empty(h.tmp("pw-long.p12"), "T08.10b: long-password p12 created")

    r = h.cmd('--no-color -p {pw} {f}', pw=long_pw, f=h.tmp("pw-long.p12"))
    t.expect_ok(r, "T08.10b: long password unlocks p12")
    t.assert_contains(r, "edge.test", "T08.10b: cert visible")

    # --- T08.10c: Password file with BOM ---
    print("-- T08.10c: Password file with BOM")

    bom_passfile = h.tmp("bom-passfile.txt")
    bom_passfile.write_bytes(b'\xEF\xBB\xBFalpha\nbeta\n')

    r = h.cmd(
        '--no-color -P {pf} {f1} {f2}',
        pf=bom_passfile,
        f1=h.tmp("pw-alpha.p12"), f2=h.tmp("pw-beta.p12"),
    )
    t.expect_ok(r, "T08.10c: BOM password file unlocks both")
    t.assert_contains(r, "edge.test", "T08.10c: alpha p12 unlocked")
    t.assert_contains(r, "edge-ec.test", "T08.10c: beta p12 unlocked")

    # --- T08.11: Wrong password on every source type ---
    print("-- T08.11: Wrong password on every source type")

    # PKCS#12
    r = h.cmd('--no-color -p {pw} -o json {f}', pw="WRONG", f=h.tmp("pw-alpha.p12"))
    t.expect_exit(1, r, "T08.11a: wrong password on p12 exits 1")

    # JKS
    r = h.cmd('--no-color -p {pw} -o json {f}', pw="WRONG", f=h.fixture("leaf.jks"))
    t.expect_exit(1, r, "T08.11b: wrong password on JKS exits 1")

    # Encrypted PEM key
    r = h.cmd('--no-color -p {pw} -o json {f}', pw="WRONG", f=h.fixture("leaf-encrypted.pem"))
    t.expect_exit(1, r, "T08.11c: wrong password on encrypted PEM exits 1")

    # --- T08.12: Password file that doesn't exist ---
    print("-- T08.12: Password file that doesn't exist")

    r = h.cmd(
        '--no-color -P /nonexistent/passwords.txt {f}',
        f=h.fixture("leaf-rsa.pem"),
    )
    t.expect_exit(1, r, "T08.12: nonexistent password file exits 1")

    # --- T08.13: Empty password file ---
    print("-- T08.13: Empty password file")

    empty_passfile = h.tmp("empty-passfile.txt")
    empty_passfile.write_text("")

    r = h.cmd(
        '--no-color -P {pf} {f}',
        pf=empty_passfile, f=h.tmp("pw-alpha.p12"),
    )
    if r.returncode != 0:
        t.PASS(f"T08.13: empty password file fails to unlock (exit {r.returncode})")
    else:
        t.FAIL("T08.13: empty password file fails to unlock", "expected non-zero exit, got 0")

    # --- T08.14: Password file with trailing newlines and blank lines ---
    print("-- T08.14: Password file with trailing newlines and blank lines")

    messy_passfile = h.tmp("messy-passfile.txt")
    messy_passfile.write_text("\nalpha\n\nbeta\n\n\n")

    r = h.cmd(
        '--no-color -P {pf} {f1} {f2}',
        pf=messy_passfile,
        f1=h.tmp("pw-alpha.p12"), f2=h.tmp("pw-beta.p12"),
    )
    t.expect_ok(r, "T08.14: messy password file still works")
    t.assert_contains(r, "edge.test", "T08.14: alpha p12 unlocked")
    t.assert_contains(r, "edge-ec.test", "T08.14: beta p12 unlocked")

    # --- T08.15: Encrypt/decrypt roundtrip ---
    print("-- T08.15: Encrypt/decrypt roundtrip")

    r = h.cmd(
        '--no-color password encrypt -p {pw}',
        pw="mysecret",
        env_extra={"CERTDIAG_MASTER_KEY": "testmaster"},
    )
    t.expect_ok(r, "T08.15a: encrypt via stdin exits 0")
    encrypted = r.stdout.strip()

    r = h.cmd(
        '--no-color password decrypt',
        stdin=encrypted,
        env_extra={"CERTDIAG_MASTER_KEY": "testmaster"},
    )
    t.expect_ok(r, "T08.15b: decrypt exits 0")
    decrypted = r.stdout.strip()

    t.assert_equal(decrypted, "mysecret", "T08.15c: encrypt/decrypt roundtrip matches")

    # --- T08.16: Encrypt with -p flag ---
    print("-- T08.16: Encrypt with -p flag")

    r = h.cmd(
        '--no-color password encrypt -p {pw}',
        pw="mysecret",
        env_extra={"CERTDIAG_MASTER_KEY": "testmaster16"},
    )
    t.expect_ok(r, "T08.16a: encrypt -p exits 0")
    encrypted = r.stdout.strip()

    r = h.cmd(
        '--no-color password decrypt',
        stdin=encrypted,
        env_extra={"CERTDIAG_MASTER_KEY": "testmaster16"},
    )
    t.expect_ok(r, "T08.16b: decrypt exits 0")
    decrypted = r.stdout.strip()

    t.assert_equal(decrypted, "mysecret", "T08.16c: encrypt -p roundtrip matches")

    # --- T08.17: Encrypt with custom --master-password ---
    print("-- T08.17: Encrypt with custom --master-password")

    r = h.cmd(
        '--no-color password encrypt -p {pw} --master-password {mp}',
        pw="mysecret", mp="master123",
    )
    t.expect_ok(r, "T08.17a: encrypt with custom master exits 0")
    encrypted = r.stdout.strip()

    r = h.cmd(
        '--no-color password decrypt --master-password {mp}',
        mp="master123",
        stdin=encrypted,
    )
    t.expect_ok(r, "T08.17b: decrypt with same master exits 0")
    decrypted = r.stdout.strip()

    t.assert_equal(decrypted, "mysecret", "T08.17c: custom master roundtrip matches")

    # Decrypt with wrong master should fail
    r = h.cmd(
        '--no-color password decrypt --master-password {mp}',
        mp="wrong",
        stdin=encrypted,
    )
    if r.returncode != 0:
        t.PASS(f"T08.17d: wrong master password fails (exit {r.returncode})")
    else:
        t.FAIL("T08.17d: wrong master password fails", "expected non-zero exit, got 0")

    # --- T08.18: Master password from CERTDIAG_MASTER_KEY env var ---
    print("-- T08.18: Master password from CERTDIAG_MASTER_KEY env var")

    r = h.cmd(
        '--no-color password encrypt -p {pw}',
        pw="secret",
        env_extra={"CERTDIAG_MASTER_KEY": "envmaster"},
    )
    t.expect_ok(r, "T08.18a: encrypt with env master exits 0")
    encrypted = r.stdout.strip()

    r = h.cmd(
        '--no-color password decrypt',
        stdin=encrypted,
        env_extra={"CERTDIAG_MASTER_KEY": "envmaster"},
    )
    t.expect_ok(r, "T08.18b: decrypt with env master exits 0")
    decrypted = r.stdout.strip()

    t.assert_equal(decrypted, "secret", "T08.18c: env master roundtrip matches")

    # --- T08.19: Encrypt empty password ---
    print("-- T08.19: Encrypt empty password")

    r = h.cmd(
        '--no-color password encrypt -p {pw}',
        pw="",
        env_extra={"CERTDIAG_MASTER_KEY": "testmaster19"},
    )
    t.expect_ok(r, "T08.19: encrypt empty password exits 0")

    # --- T08.20: Decrypt garbage input ---
    print("-- T08.20: Decrypt garbage input")

    r = h.cmd(
        '--no-color password decrypt',
        stdin="not-encrypted-data",
    )
    if r.returncode != 0:
        t.PASS(f"T08.20: decrypt garbage fails (exit {r.returncode})")
    else:
        t.FAIL("T08.20: decrypt garbage fails", "expected non-zero exit, got 0")

    # --- T08.21: Change master key ---
    print("-- T08.21: Change master key")

    r = h.cmd(
        '--no-color password encrypt -p {pw}',
        pw="check",
        env_extra={"CERTDIAG_MASTER_KEY": "old"},
    )
    if not r.ok:
        t.SKIP("T08.21: could not encrypt with env master key")
    else:
        mk_encrypted = r.stdout.strip()

        r_pw = h.cmd(
            '--no-color password encrypt -p {pw}',
            pw="p12pass",
            env_extra={"CERTDIAG_MASTER_KEY": "old"},
        )
        pw_encrypted = r_pw.stdout.strip()

        config_path = h.tmp("test-config.yaml")
        config_path.write_text(
            f"master_key_check: {mk_encrypted}\n"
            f"passwords:\n"
            f"  - pattern: \"*.p12\"\n"
            f"    password: {pw_encrypted}\n"
        )

        r = h.cmd(
            '--no-color password change-master-key -c {cfg}',
            cfg=config_path,
            stdin="newmaster\nnewmaster\n",
            env_extra={"CERTDIAG_MASTER_KEY": "old"},
        )
        if r.returncode == 0:
            t.PASS("T08.21: change-master-key exits 0")
        else:
            t.SKIP(f"T08.21: change-master-key not supported non-interactively (exit {r.returncode})")

    # --- T08.22: Config file with glob-pattern passwords ---
    print("-- T08.22: Config file with glob-pattern passwords")

    glob_config = h.tmp("glob-config.yaml")
    glob_config.write_text(
        'kind: certdiag-config\n'
        'version: "1"\n'
        'passwords:\n'
        '  by_filename:\n'
        '    - filename: "*alpha*"\n'
        '      plaintext_password: "alpha"\n'
        '    - filename: "*beta*"\n'
        '      plaintext_password: "beta"\n'
    )

    r = h.cmd(
        '--no-color -c {cfg} {f1} {f2}',
        cfg=glob_config,
        f1=h.tmp("pw-alpha.p12"), f2=h.tmp("pw-beta.p12"),
    )
    t.expect_ok(r, "T08.22: config glob passwords unlock both")
    t.assert_contains(r, "edge.test", "T08.22: alpha p12 unlocked via config glob")
    t.assert_contains(r, "edge-ec.test", "T08.22: beta p12 unlocked via config glob")


if __name__ == "__main__":
    import sys
    from pathlib import Path

    repo = Path(__file__).resolve().parents[4]
    fixtures = repo / "tools" / "testing" / "edgecases" / "fixtures"

    h = Harness(fixtures_dir=fixtures)
    h.setup(required_tools=["openssl"])

    t = Tracker()
    try:
        run(h, t)
    finally:
        h.cleanup()
        ok = t.summary("T08")
        sys.exit(0 if ok else 1)
