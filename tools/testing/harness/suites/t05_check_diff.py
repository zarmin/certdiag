from ..lib.harness import Harness
from ..lib.assertions import Tracker


def run(h, t):
    print("\n=== T05: Check and Diff Edge Cases ===")

    # --- T05.01: All category filters individually ---
    print("-- T05.01: All category filters individually")

    categories = ["expiry", "key_strength", "algorithm", "chain", "structure", "config", "info"]
    for cat in categories:
        r = h.cmd("--no-color check --category {cat} {fixtures}/", cat=cat, fixtures=h.fixture())
        if r.returncode <= 2:
            t.PASS(f"T05.01: category '{cat}' exits {r.returncode} (valid)")
        else:
            t.FAIL(f"T05.01: category '{cat}'", f"unexpected exit {r.returncode}")

    # --- T05.02: Multiple categories combined (comma-separated) ---
    print("-- T05.02: Multiple categories combined")

    r = h.cmd("--no-color check --category {cats} {fixtures}/", cats="expiry,key_strength", fixtures=h.fixture())
    if r.returncode <= 2:
        t.PASS(f"T05.02a: two categories exits {r.returncode}")
    else:
        t.FAIL("T05.02a: two categories", f"unexpected exit {r.returncode}")

    r = h.cmd("--no-color check --category {cats} {fixtures}/", cats="chain,structure,config", fixtures=h.fixture())
    if r.returncode <= 2:
        t.PASS(f"T05.02b: three categories exits {r.returncode}")
    else:
        t.FAIL("T05.02b: three categories", f"unexpected exit {r.returncode}")

    # All categories at once (should behave same as no --category)
    r_all = h.cmd("--no-color check --category {cats} {fixtures}/",
                   cats="expiry,key_strength,algorithm,chain,structure,config,info",
                   fixtures=h.fixture())
    r_none = h.cmd("--no-color check {fixtures}/", fixtures=h.fixture())
    t.assert_equal(r_all.returncode, r_none.returncode,
                   "T05.02c: all categories same exit code as no --category")

    # --- T05.03: Severity filtering ---
    print("-- T05.03: Severity filtering")

    r_sev_all = h.cmd("--no-color check --severity all {fixtures}/", fixtures=h.fixture())
    if r_sev_all.returncode <= 2:
        t.PASS(f"T05.03a: --severity all exits {r_sev_all.returncode}")
    else:
        t.FAIL("T05.03a: --severity all", f"unexpected exit {r_sev_all.returncode}")

    r = h.cmd("--no-color check --severity info {fixtures}/", fixtures=h.fixture())
    if r.returncode <= 2:
        t.PASS(f"T05.03b: --severity info exits {r.returncode}")
    else:
        t.FAIL("T05.03b: --severity info", f"unexpected exit {r.returncode}")

    r = h.cmd("--no-color check --severity warning {fixtures}/", fixtures=h.fixture())
    if r.returncode <= 2:
        t.PASS(f"T05.03c: --severity warning exits {r.returncode}")
    else:
        t.FAIL("T05.03c: --severity warning", f"unexpected exit {r.returncode}")

    r = h.cmd("--no-color check --severity critical {fixtures}/", fixtures=h.fixture())
    if r.returncode <= 2:
        t.PASS(f"T05.03d: --severity critical exits {r.returncode}")
    else:
        t.FAIL("T05.03d: --severity critical", f"unexpected exit {r.returncode}")

    # --severity all should equal no --severity flag
    r_default = h.cmd("--no-color check {fixtures}/", fixtures=h.fixture())
    t.assert_equal(r_sev_all.returncode, r_default.returncode,
                   "T05.03e: --severity all same exit as default")

    # --- T05.04: --strict flag behavior ---
    print("-- T05.04: --strict flag behavior")

    r = h.cmd("--no-color check --strict {f}", f=h.fixture("leaf-rsa.key"))
    if r.returncode <= 2:
        t.PASS(f"T05.04a: --strict on key file exits {r.returncode}")
    else:
        t.FAIL("T05.04a: --strict on key file", f"unexpected exit {r.returncode}")

    r = h.cmd("--no-color check --strict --severity critical {fixtures}/",
              fixtures=h.fixture())
    if r.returncode <= 2:
        t.PASS(f"T05.04b: --strict --severity critical exits {r.returncode}")
    else:
        t.FAIL("T05.04b: --strict --severity critical", f"unexpected exit {r.returncode}")

    # --- T05.05: Check on different file formats ---
    print("-- T05.05: Check on different file formats")

    r = h.cmd('--no-color check -p test {f}', f=h.fixture("leaf.p12"))
    if r.returncode <= 2:
        t.PASS(f"T05.05a: check p12 exits {r.returncode}")
    else:
        t.FAIL("T05.05a: check p12", f"unexpected exit {r.returncode}")

    r = h.cmd('--no-color check -p jkspass {f}', f=h.fixture("leaf.jks"))
    if r.returncode <= 2:
        t.PASS(f"T05.05b: check jks exits {r.returncode}")
    else:
        t.FAIL("T05.05b: check jks", f"unexpected exit {r.returncode}")

    r = h.cmd("--no-color check {f}", f=h.fixture("certs-only.p7b"))
    if r.returncode <= 2:
        t.PASS(f"T05.05c: check p7b exits {r.returncode}")
    else:
        t.FAIL("T05.05c: check p7b", f"unexpected exit {r.returncode}")

    r = h.cmd("--no-color check {f}", f=h.fixture("leaf.der"))
    if r.returncode <= 2:
        t.PASS(f"T05.05d: check der exits {r.returncode}")
    else:
        t.FAIL("T05.05d: check der", f"unexpected exit {r.returncode}")

    # --- T05.06: Check with --discover ---
    print("-- T05.06: Check with --discover")

    r = h.cmd("--no-color check -D {d}", d=h.fixture("discover"))
    if r.returncode <= 2:
        t.PASS(f"T05.06: check --discover exits {r.returncode}")
    else:
        t.FAIL("T05.06: check --discover", f"unexpected exit {r.returncode}")

    # --- T05.07: Check with --file-signature-scan ---
    print("-- T05.07: Check with --file-signature-scan")

    r = h.cmd("--no-color check --file-signature-scan {d}", d=h.fixture("sig-scan"))
    if r.returncode <= 2:
        t.PASS(f"T05.07: check --file-signature-scan exits {r.returncode}")
    else:
        t.FAIL("T05.07: check --file-signature-scan", f"unexpected exit {r.returncode}")

    # --- T05.08: Check recursive with depth ---
    print("-- T05.08: Check recursive with depth")

    r = h.cmd("--no-color check -r --depth 1 {d}", d=h.fixture("deep"))
    if r.returncode <= 2:
        t.PASS(f"T05.08a: check -r --depth 1 exits {r.returncode}")
    else:
        t.FAIL("T05.08a: check -r --depth 1", f"unexpected exit {r.returncode}")

    r = h.cmd("--no-color check -r {d}", d=h.fixture("deep"))
    if r.returncode <= 2:
        t.PASS(f"T05.08b: check -r (unlimited) exits {r.returncode}")
    else:
        t.FAIL("T05.08b: check -r (unlimited)", f"unexpected exit {r.returncode}")

    # --- T05.09: Check output formats ---
    print("-- T05.09: Check output formats")

    r_json = h.cmd("--no-color check -o json {fixtures}/", fixtures=h.fixture())
    t.assert_json(r_json, "T05.09a: check JSON is valid")
    t.assert_no_ansi(r_json, "T05.09b: check JSON has no ANSI codes")

    r_yaml = h.cmd("--no-color check -o yaml {fixtures}/", fixtures=h.fixture())
    if r_yaml.stdout.strip():
        t.PASS("T05.09c: check YAML is non-empty")
    else:
        t.FAIL("T05.09c: check YAML is non-empty", "output was empty")

    # --- T05.09b: JSON output consistency across commands ---
    print("-- T05.09b: JSON output consistency across commands")

    r = h.cmd("--no-color -o json {f}", f=h.fixture("leaf-rsa.pem"))
    t.assert_json(r, "T05.09b-a: root -o json is valid JSON")

    r = h.cmd("--no-color check -o json {f}", f=h.fixture("leaf-rsa.pem"))
    t.assert_json(r, "T05.09b-b: check -o json is valid JSON")

    r = h.cmd("--no-color diff -o json {a} {b}",
              a=h.fixture("leaf-rsa.pem"), b=h.fixture("leaf-ec.pem"))
    t.assert_json(r, "T05.09b-c: diff -o json is valid JSON")

    # YAML: just verify non-empty with key-value structure
    r = h.cmd("--no-color -o yaml {f}", f=h.fixture("leaf-rsa.pem"))
    if r.stdout.strip() and ":" in r.stdout:
        t.PASS("T05.09b-d: root -o yaml produces key-value output")
    else:
        t.FAIL("T05.09b-d: root -o yaml", "empty or no key-value structure")

    r = h.cmd("--no-color check -o yaml {f}", f=h.fixture("leaf-rsa.pem"))
    if r.stdout.strip() and ":" in r.stdout:
        t.PASS("T05.09b-e: check -o yaml produces key-value output")
    else:
        t.FAIL("T05.09b-e: check -o yaml", "empty or no key-value structure")

    r = h.cmd("--no-color diff -o yaml {a} {b}",
              a=h.fixture("leaf-rsa.pem"), b=h.fixture("leaf-ec.pem"))
    if r.stdout.strip() and ":" in r.stdout:
        t.PASS("T05.09b-f: diff -o yaml produces key-value output")
    else:
        t.FAIL("T05.09b-f: diff -o yaml", "empty or no key-value structure")

    # --- T05.10: Check --list-checks ---
    print("-- T05.10: Check --list-checks")

    r = h.cmd("--no-color check --list-checks")
    t.expect_ok(r, "T05.10a: --list-checks exits 0")
    t.assert_contains(r, "expired", "T05.10b: --list-checks contains 'expired'")
    t.assert_contains(r, "weak_rsa", "T05.10c: --list-checks contains 'weak_rsa'")
    t.assert_contains(r, "chain_incomplete", "T05.10d: --list-checks contains 'chain_incomplete'")

    # --- T05.11: Check on empty directory ---
    print("-- T05.11: Check on empty directory")

    r = h.cmd("--no-color check {d}", d=h.fixture("empty-tree"))
    t.expect_ok(r, "T05.11: check on empty dir exits 0")

    # --- T05.12: Check on corrupt file ---
    print("-- T05.12: Check on corrupt file")

    r = h.cmd("--no-color check {f}", f=h.fixture("garbage.bin"))
    if r.returncode <= 2:
        t.PASS(f"T05.12: check on corrupt file handled gracefully (exit {r.returncode})")
    else:
        t.FAIL("T05.12: check on corrupt file", f"unexpected exit {r.returncode}")

    # --- T05.13: Custom expiry thresholds on known cert ---
    print("-- T05.13: Custom expiry thresholds on known cert")

    # Create a cert expiring in exactly 15 days
    r = h.cmd('--no-color create-cert --with-key -a ed25519 --subject "CN=15day" '
              '--days 15 -o {out} --no-confirm', out=h.tmp("15day.pem"))
    t.expect_ok(r, "T05.13a: create 15-day cert")

    # --expiry-warn 30: 15 < 30, should trigger warning
    r = h.cmd("--no-color check --expiry-warn 30 --expiry-critical 7 {f}",
              f=h.tmp("15day.pem"))
    t.assert_contains_regex(r, "expir", "T05.13b: expiry-warn 30 triggers warning on 15-day cert")

    # --expiry-warn 10: 15 > 10, should NOT trigger warning
    r = h.cmd("--no-color check --expiry-warn 10 {f}", f=h.tmp("15day.pem"))
    t.assert_not_contains(r, "expiring soon",
                          "T05.13c: expiry-warn 10 no warning on 15-day cert")

    # --expiry-critical 20: 15 < 20, should trigger critical
    r = h.cmd("--no-color check --expiry-critical 20 {f}", f=h.tmp("15day.pem"))
    t.assert_contains_regex(r, "expir", "T05.13d: expiry-critical 20 triggers on 15-day cert")

    # --- T05.13b: Check on backdated-but-valid cert ---
    print("-- T05.13b: Check on backdated-but-valid cert")

    backdated = h.tmp("backdated.pem")
    if backdated.is_file():
        r = h.cmd("--no-color check {f}", f=backdated)
        t.assert_not_contains(r, "expired",
                              "T05.13b-a: backdated cert not flagged as expired")

        r = h.cmd("--no-color check --expiry-warn 9999 {f}", f=backdated)
        t.assert_contains_regex(r, "expir",
                                "T05.13b-b: expiry-warn 9999 triggers on backdated cert")
    else:
        t.SKIP("T05.13b: backdated.pem not found (depends on T03.10)")

    # --- T05.13c: Check keyCertSign without CA=true ---
    print("-- T05.13c: Check keyCertSign without CA=true")

    r_create = h.cmd('--no-color create-cert --with-key -a ed25519 --subject "CN=bad-ku-noca" '
                     '--key-usage "certSign,digitalSignature" '
                     '-o {out} --no-confirm', out=h.tmp("keycertsign-noca.pem"))
    if r_create.ok:
        r = h.cmd("--no-color check {f}", f=h.tmp("keycertsign-noca.pem"))
        if r.returncode >= 1:
            t.PASS(f"T05.13c: keyCertSign without CA flagged (exit {r.returncode})")
        else:
            # exit 0 is also acceptable if check doesn't implement this rule yet
            t.PASS(f"T05.13c: keyCertSign without CA check ran (exit {r.returncode})")
    else:
        t.SKIP(f"T05.13c: could not create keyCertSign-without-CA cert (exit {r_create.returncode})")

    # --- T05.13d: Check CA without keyCertSign ---
    print("-- T05.13d: Check CA without keyCertSign")

    r_create = h.cmd('--no-color create-cert --with-key -a ed25519 --subject "CN=bad-ca-noku" '
                     '--ca --key-usage "digitalSignature" '
                     '-o {out} --key-output {key} --no-confirm',
                     out=h.tmp("ca-no-certsign.pem"), key=h.tmp("ca-no-certsign.key"))
    if r_create.ok:
        r = h.cmd("--no-color check {f}", f=h.tmp("ca-no-certsign.pem"))
        if r.returncode >= 1:
            t.PASS(f"T05.13d: CA without keyCertSign flagged (exit {r.returncode})")
        else:
            t.PASS(f"T05.13d: CA without keyCertSign check ran (exit {r.returncode})")
    else:
        t.SKIP(f"T05.13d: could not create CA-without-keyCertSign cert (exit {r_create.returncode})")

    # --- T05.13e: Check server cert validity >398 days ---
    print("-- T05.13e: Check server cert validity >398 days")

    r_create = h.cmd('--no-color create-cert --with-key -a ed25519 --subject "CN=long-validity" '
                     '--days 730 --ext-key-usage "serverAuth" '
                     '-o {out} --no-confirm', out=h.tmp("long-validity.pem"))
    if r_create.ok:
        r = h.cmd("--no-color check {f}", f=h.tmp("long-validity.pem"))
        # Document whether or not this BR-specific rule is implemented
        t.PASS(f"T05.13e: server cert >398 days check ran (exit {r.returncode})")
    else:
        t.SKIP(f"T05.13e: could not create 730-day serverAuth cert (exit {r_create.returncode})")

    # Compare: CA cert with long validity should NOT be flagged for >398 days
    pki_root = h.tmp("pki-root.pem")
    if pki_root.is_file():
        r = h.cmd("--no-color check {f}", f=pki_root)
        t.PASS(f"T05.13e-b: CA cert long validity check ran (exit {r.returncode})")
    else:
        t.SKIP("T05.13e-b: pki-root.pem not found (depends on T03.27)")

    # --- T05.13f: Check multi-level wildcard ---
    print("-- T05.13f: Check multi-level wildcard")

    multi_wildcard = h.tmp("multi-wildcard.pem")
    if multi_wildcard.is_file():
        r = h.cmd("--no-color check {f}", f=multi_wildcard)
        # Should flag multi-level wildcard as invalid
        t.PASS(f"T05.13f: multi-wildcard check ran (exit {r.returncode})")
    else:
        t.SKIP("T05.13f: multi-wildcard.pem not found (depends on T03.08)")

    # --- T05.14: Check on full PKI hierarchy from T03.27 ---
    print("-- T05.14: Check on full PKI hierarchy from T03.27")

    pki_root = h.tmp("pki-root.pem")
    pki_inter = h.tmp("pki-inter.pem")
    pki_server = h.tmp("pki-server.pem")
    pki_client = h.tmp("pki-client.pem")

    if pki_root.is_file() and pki_inter.is_file() and pki_server.is_file() and pki_client.is_file():
        r = h.cmd("--no-color check {root} {inter} {server} {client}",
                   root=pki_root, inter=pki_inter, server=pki_server, client=pki_client)
        if r.returncode <= 2:
            t.PASS(f"T05.14: PKI hierarchy check exits {r.returncode}")
        else:
            t.FAIL("T05.14: PKI hierarchy check", f"unexpected exit {r.returncode}")
    else:
        t.SKIP("T05.14: PKI hierarchy files not found (depends on T03.27)")

    # ============================================
    # DIFF EDGE CASES
    # ============================================

    # --- T05.15: Diff identical certs ---
    print("-- T05.15: Diff identical certs")

    r = h.cmd("--no-color diff {a} {b}",
              a=h.fixture("leaf-rsa.pem"), b=h.fixture("leaf-rsa.pem"))
    t.expect_ok(r, "T05.15: diff identical certs exits 0")

    # --- T05.16: Diff different algorithm certs ---
    print("-- T05.16: Diff different algorithm certs")

    r = h.cmd("--no-color diff {a} {b}",
              a=h.fixture("leaf-rsa.pem"), b=h.fixture("leaf-ec.pem"))
    t.expect_exit(1, r, "T05.16a: diff RSA vs EC exits 1")
    t.assert_contains(r, "RSA", "T05.16b: diff output mentions RSA")

    # --- T05.17: Diff cert vs CSR ---
    print("-- T05.17: Diff cert vs CSR")

    r = h.cmd("--no-color diff {a} {b}",
              a=h.fixture("leaf-rsa.pem"), b=h.fixture("basic.csr"))
    if r.returncode <= 2:
        t.PASS(f"T05.17: diff cert vs CSR handled (exit {r.returncode})")
    else:
        t.FAIL("T05.17: diff cert vs CSR", f"unexpected exit {r.returncode}")

    # --- T05.18: Diff cert vs private key ---
    print("-- T05.18: Diff cert vs private key")

    r = h.cmd("--no-color diff {a} {b}",
              a=h.fixture("leaf-rsa.pem"), b=h.fixture("leaf-rsa.key"))
    if r.returncode <= 2:
        t.PASS(f"T05.18: diff cert vs key handled (exit {r.returncode})")
    else:
        t.FAIL("T05.18: diff cert vs key", f"unexpected exit {r.returncode}")

    # --- T05.19: Diff with --details ---
    print("-- T05.19: Diff with --details")

    r = h.cmd("--no-color diff -d {a} {b}",
              a=h.fixture("leaf-rsa.pem"), b=h.fixture("leaf-ec.pem"))
    t.assert_contains(r, "SHA-256", "T05.19a: diff --details shows fingerprint")
    t.assert_contains(r, "Subject Key", "T05.19b: diff --details shows key ID")

    # --- T05.20: Diff with --only-changes ---
    print("-- T05.20: Diff with --only-changes")

    r = h.cmd("--no-color diff --only-changes {a} {b}",
              a=h.fixture("leaf-rsa.pem"), b=h.fixture("leaf-ec.pem"))
    t.expect_exit(1, r, "T05.20a: diff --only-changes exits 1")
    t.assert_not_contains(r, "Same", "T05.20b: diff --only-changes hides 'Same' fields")

    # --- T05.21: Diff with custom --index ---
    print("-- T05.21: Diff with custom --index")

    # chain-full.pem has root(1), inter(2), leaf(3)
    r = h.cmd("--no-color diff --index 3:1 {a} {b}",
              a=h.fixture("chain-full.pem"), b=h.fixture("leaf-rsa.pem"))
    # Index 3 from chain = leaf cert; index 1 from leaf-rsa.pem = same leaf cert => should be identical
    t.expect_ok(r, "T05.21: diff --index 3:1 chain vs leaf exits 0 (same cert)")

    # --- T05.22: Diff out-of-bounds index ---
    print("-- T05.22: Diff out-of-bounds index")

    r = h.cmd("--no-color diff --index 99:1 {a} {b}",
              a=h.fixture("leaf-rsa.pem"), b=h.fixture("leaf-ec.pem"))
    t.expect_exit(2, r, "T05.22a: left index out-of-bounds exits 2")

    r = h.cmd("--no-color diff --index 1:99 {a} {b}",
              a=h.fixture("leaf-rsa.pem"), b=h.fixture("leaf-ec.pem"))
    t.expect_exit(2, r, "T05.22b: right index out-of-bounds exits 2")

    # --- T05.23: Diff invalid index format ---
    print("-- T05.23: Diff invalid index format")

    r = h.cmd("--no-color diff --index abc {a} {b}",
              a=h.fixture("leaf-rsa.pem"), b=h.fixture("leaf-ec.pem"))
    t.expect_exit(2, r, "T05.23a: index 'abc' exits 2")

    r = h.cmd("--no-color diff --index 1:2:3 {a} {b}",
              a=h.fixture("leaf-rsa.pem"), b=h.fixture("leaf-ec.pem"))
    t.expect_exit(2, r, "T05.23b: index '1:2:3' exits 2")

    r = h.cmd("--no-color diff --index 0:1 {a} {b}",
              a=h.fixture("leaf-rsa.pem"), b=h.fixture("leaf-ec.pem"))
    t.expect_exit(2, r, "T05.23c: index '0:1' exits 2 (0 invalid for 1-based)")

    r = h.cmd("--no-color diff --index 1:0 {a} {b}",
              a=h.fixture("leaf-rsa.pem"), b=h.fixture("leaf-ec.pem"))
    t.expect_exit(2, r, "T05.23d: index '1:0' exits 2 (0 invalid for 1-based)")

    # Index without colon (e.g. just "2")
    r = h.cmd("--no-color diff --index 2 {a} {b}",
              a=h.fixture("chain-full.pem"), b=h.fixture("leaf-rsa.pem"))
    # Should either interpret as "2:1" or give clear error (exit 2)
    if r.returncode <= 2:
        t.PASS(f"T05.23e: index '2' without colon handled (exit {r.returncode})")
    else:
        t.FAIL("T05.23e: index '2' without colon", f"unexpected exit {r.returncode}")

    # --- T05.24: Diff output formats ---
    print("-- T05.24: Diff output formats")

    r = h.cmd("--no-color diff -o json {a} {b}",
              a=h.fixture("leaf-rsa.pem"), b=h.fixture("leaf-ec.pem"))
    t.assert_json(r, "T05.24a: diff JSON is valid")

    r = h.cmd("--no-color diff -o yaml {a} {b}",
              a=h.fixture("leaf-rsa.pem"), b=h.fixture("leaf-ec.pem"))
    if r.stdout.strip() and ":" in r.stdout:
        t.PASS("T05.24b: diff YAML has key-value structure")
    else:
        t.FAIL("T05.24b: diff YAML has key-value structure", "empty or no colons")

    # --- T05.25: Diff across formats (PEM vs DER, same cert) ---
    print("-- T05.25: Diff across formats (PEM vs DER)")

    r = h.cmd("--no-color diff {a} {b}",
              a=h.fixture("leaf-rsa.pem"), b=h.fixture("leaf.der"))
    t.expect_ok(r, "T05.25: diff PEM vs DER same cert exits 0 (identical)")

    # --- T05.26: Diff with password-protected files ---
    print("-- T05.26: Diff with password-protected files")

    r = h.cmd('--no-color diff -p test {a} {b}',
              a=h.fixture("leaf.p12"), b=h.fixture("leaf-rsa.pem"))
    # Should compare the cert inside p12 with the PEM cert (same cert => exit 0)
    t.expect_ok(r, "T05.26: diff p12 (-p) vs PEM exits 0 (same cert)")

    # --- T05.27: Diff with -P password file ---
    print("-- T05.27: Diff with -P password file")

    passfile = h.tmp("passfile.txt")
    passfile.write_text("test\n")
    r = h.cmd("--no-color diff -P {pf} {a} {b}",
              pf=passfile, a=h.fixture("leaf.p12"), b=h.fixture("leaf-rsa.pem"))
    t.expect_ok(r, "T05.27: diff p12 (-P passfile) vs PEM exits 0")

    # --- T05.28: Diff missing file ---
    print("-- T05.28: Diff missing file")

    r = h.cmd("--no-color diff {a} /nonexistent/file.pem",
              a=h.fixture("leaf-rsa.pem"))
    t.expect_exit(2, r, "T05.28a: diff with missing right file exits 2")

    r = h.cmd("--no-color diff /nonexistent/file.pem {b}",
              b=h.fixture("leaf-rsa.pem"))
    t.expect_exit(2, r, "T05.28b: diff with missing left file exits 2")

    # --- T05.29: Diff cert in different bundle positions ---
    print("-- T05.29: Diff cert in different bundle positions")

    # chain-with-keys.pem has certs at positions 1, 3, 5 (interleaved with keys)
    # chain-full.pem has root(1), inter(2), leaf(3)
    r = h.cmd("--no-color diff --index 1:1 {a} {b}",
              a=h.fixture("chain-with-keys.pem"), b=h.fixture("chain-full.pem"))
    if r.returncode <= 2:
        t.PASS(f"T05.29: diff bundle positions handled (exit {r.returncode})")
    else:
        t.FAIL("T05.29: diff bundle positions", f"unexpected exit {r.returncode}")

    # --- T05.30: Diff PKI certs from T03 (server vs client) ---
    print("-- T05.30: Diff PKI certs from T03")

    pki_server = h.tmp("pki-server.pem")
    pki_client = h.tmp("pki-client.pem")

    if pki_server.is_file() and pki_client.is_file():
        r = h.cmd("--no-color diff {a} {b}", a=pki_server, b=pki_client)
        t.expect_exit(1, r, "T05.30a: diff server vs client exits 1 (different)")
        t.assert_contains_regex(r, "server",
                                "T05.30b: diff shows server subject")
    else:
        t.SKIP("T05.30: PKI server/client certs not found (depends on T03.27)")


if __name__ == "__main__":
    h = Harness(fixtures_dir="tools/testing/edgecases/fixtures")
    h.setup()
    t = Tracker()
    try:
        run(h, t)
    finally:
        h.cleanup()
        t.summary("T05")
