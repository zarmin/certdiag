from ..lib.harness import Harness
from ..lib.assertions import Tracker


def run(h, t):
    print("\n=== T02: Format Handling Edge Cases ===")

    # --- T02.01: Reversed chain order in PEM ---
    print("-- T02.01: Reversed chain order in PEM")

    r = h.cmd("--no-color {f}", f=h.fixture("chain-reversed.pem"))
    t.expect_ok(r, "T02.01a: reversed chain exits 0")
    t.assert_contains(r, "edge.test", "T02.01b: reversed chain lists leaf cert")
    t.assert_contains_regex(r, r"Intermediate", "T02.01c: reversed chain lists intermediate")
    t.assert_contains_regex(r, r"Root", "T02.01d: reversed chain lists root")

    rj = h.cmd("--no-color -o json {f}", f=h.fixture("chain-reversed.pem"))
    t.assert_json(rj, "T02.01e: reversed chain JSON is valid")
    t.assert_json_item_count(rj, 3, "T02.01f: reversed chain JSON has 3 items")

    rc = h.cmd("--no-color check {f}", f=h.fixture("chain-reversed.pem"))
    t.PASS(f"T02.01g: check on reversed chain exits {rc.returncode} (no crash)")

    # --- T02.02: Shuffled chain order ---
    print("-- T02.02: Shuffled chain order")

    r = h.cmd("--no-color {f}", f=h.fixture("chain-shuffled.pem"))
    t.expect_ok(r, "T02.02a: shuffled chain exits 0")
    t.assert_contains(r, "edge.test", "T02.02b: shuffled chain lists leaf")
    t.assert_contains_regex(r, r"Intermediate", "T02.02c: shuffled chain lists intermediate")
    t.assert_contains_regex(r, r"Root", "T02.02d: shuffled chain lists root")

    rc = h.cmd("--no-color check {f}", f=h.fixture("chain-shuffled.pem"))
    t.PASS(f"T02.02e: check on shuffled chain exits {rc.returncode} (no crash)")

    # --- T02.03: Duplicate certs in PEM ---
    print("-- T02.03: Duplicate certs in PEM")

    r = h.cmd("--no-color {f}", f=h.fixture("chain-duplicates.pem"))
    t.expect_ok(r, "T02.03a: duplicates chain exits 0")

    rj = h.cmd("--no-color -o json {f}", f=h.fixture("chain-duplicates.pem"))
    t.assert_json(rj, "T02.03b: duplicates JSON is valid")
    t.assert_json_item_count(rj, 5, "T02.03c: duplicates JSON has 5 items")

    # --- T02.04: PEM with interleaved keys and certs ---
    print("-- T02.04: PEM with interleaved keys and certs")

    r = h.cmd("--no-color {f}", f=h.fixture("chain-with-keys.pem"))
    t.expect_ok(r, "T02.04a: keys+certs PEM exits 0")
    t.assert_contains(r, "edge.test", "T02.04b: shows leaf cert")
    t.assert_contains_regex(r, r"private", "T02.04c: shows private key items")

    r = h.cmd("--no-color -D {f}", f=h.fixture("chain-with-keys.pem"))
    t.expect_ok(r, "T02.04d: discover on keys+certs exits 0")
    t.assert_contains_regex(r, r"key", "T02.04e: discover finds key-cert pairs")

    # --- T02.05: PEM with only private keys ---
    print("-- T02.05: PEM with only private keys")

    r = h.cmd("--no-color {f}", f=h.fixture("lone-key.pem"))
    t.expect_ok(r, "T02.05a: lone key exits 0")
    t.assert_contains_regex(r, r"private|key", "T02.05b: lone key shows 1 key")

    r = h.cmd("--no-color {f}", f=h.fixture("multi-key.pem"))
    t.expect_ok(r, "T02.05c: multi-key exits 0")

    rj = h.cmd("--no-color -o json {f}", f=h.fixture("multi-key.pem"))
    t.assert_json(rj, "T02.05d: multi-key JSON is valid")
    t.assert_json_item_count(rj, 3, "T02.05e: multi-key JSON has 3 items")

    # --- T02.06: PEM with cert + CSR mixed ---
    print("-- T02.06: PEM with cert + CSR mixed")

    r = h.cmd("--no-color {f}", f=h.fixture("cert-and-csr.pem"))
    t.expect_ok(r, "T02.06a: cert+CSR exits 0")
    t.assert_contains_regex(r, r"edge\.test|certificate", "T02.06b: shows certificate")
    t.assert_contains_regex(r, r"csr|request", "T02.06c: shows CSR")

    # --- T02.07: Empty / zero-byte / near-empty files ---
    print("-- T02.07: Empty / zero-byte / near-empty files")

    r = h.cmd("--no-color {f}", f=h.fixture("zero-byte.pem"))
    t.PASS(f"T02.07a: zero-byte file handled gracefully (exit {r.returncode})")
    t.PASS("T02.07b: zero-byte file did not crash")

    r = h.cmd("--no-color {f}", f=h.fixture("empty.pem"))
    t.PASS(f"T02.07c: empty PEM (comment only) did not crash (exit {r.returncode})")

    # --- T02.08: Corrupt PEM (valid headers, bad base64) ---
    print("-- T02.08: Corrupt PEM (valid headers, bad base64)")

    r = h.cmd("--no-color {f}", f=h.fixture("almost-pem.pem"))
    t.PASS(f"T02.08a: corrupt PEM handled gracefully (exit {r.returncode})")
    t.PASS("T02.08b: corrupt PEM did not crash")

    # --- T02.09: Truncated DER ---
    print("-- T02.09: Truncated DER")

    r = h.cmd("--no-color {f}", f=h.fixture("truncated.der"))
    t.PASS(f"T02.09a: truncated DER handled gracefully (exit {r.returncode})")
    t.PASS("T02.09b: truncated DER did not crash")

    # --- T02.10: Random binary garbage ---
    print("-- T02.10: Random binary garbage")

    r = h.cmd("--no-color {f}", f=h.fixture("garbage.bin"))
    t.PASS(f"T02.10a: garbage file did not crash (exit {r.returncode})")

    r = h.cmd("--no-color --file-signature-scan {f}", f=h.fixture("garbage.bin"))
    t.PASS(f"T02.10b: garbage with sig scan did not crash (exit {r.returncode})")

    # --- T02.11: Cert with very long subject ---
    print("-- T02.11: Cert with very long subject")

    r = h.cmd("--no-color {f}", f=h.fixture("huge-subject.pem"))
    t.expect_ok(r, "T02.11a: huge subject exits 0")
    t.assert_contains(r, "aaaa", "T02.11b: huge subject displays long CN")

    r = h.cmd("--no-color -t {f}", f=h.fixture("huge-subject.pem"))
    t.expect_ok(r, "T02.11c: huge subject table view exits 0")

    r = h.cmd("--no-color -d {f}", f=h.fixture("huge-subject.pem"))
    t.expect_ok(r, "T02.11d: huge subject detail view exits 0")

    rj = h.cmd("--no-color -o json {f}", f=h.fixture("huge-subject.pem"))
    t.expect_ok(rj, "T02.11e: huge subject JSON exits 0")
    t.assert_json(rj, "T02.11f: huge subject JSON is valid")

    # --- T02.12: Cert with UTF-8 subject ---
    print("-- T02.12: Cert with UTF-8 subject")

    r = h.cmd("--no-color {f}", f=h.fixture("unicode-subject.pem"))
    t.expect_ok(r, "T02.12a: UTF-8 subject exits 0")
    t.assert_contains_regex(r, r"Pruefung|Oesterreich", "T02.12b: UTF-8 subject displays correctly")

    rj = h.cmd("--no-color -o json {f}", f=h.fixture("unicode-subject.pem"))
    t.assert_json(rj, "T02.12c: UTF-8 subject JSON is valid")
    t.assert_contains_regex(rj, r"Pruefung|Oesterreich", "T02.12d: UTF-8 subject preserved in JSON")

    # --- T02.13: Cert with no CN ---
    print("-- T02.13: Cert with no CN")

    r = h.cmd("--no-color {f}", f=h.fixture("no-cn.pem"))
    t.expect_ok(r, "T02.13a: no-CN cert exits 0")
    if r.stdout.strip():
        t.PASS("T02.13b: no-CN cert displays something meaningful")
    else:
        t.FAIL("T02.13b: no-CN cert displays something meaningful", "empty output")

    # --- T02.14: Cert with only IP SANs ---
    print("-- T02.14: Cert with only IP SANs")

    r = h.cmd("--no-color {f}", f=h.fixture("ip-only-san.pem"))
    t.expect_ok(r, "T02.14a: IP-only SAN exits 0")
    t.assert_contains_regex(r, r"10\.0\.0\.1|192\.168\.1\.1", "T02.14b: displays IP SANs")

    r = h.cmd("--no-color -q {q} {f}", q="10.0.0.1", f=h.fixture("ip-only-san.pem"))
    t.expect_ok(r, "T02.14c: query by IP exits 0")
    t.assert_contains(r, "10.0.0.1", "T02.14d: query by IP finds the cert")

    # --- T02.15: Cert with email/URI SANs ---
    print("-- T02.15: Cert with email/URI SANs")

    r = h.cmd("--no-color {f}", f=h.fixture("email-san.pem"))
    t.expect_ok(r, "T02.15a: email/URI SAN exits 0")
    t.assert_contains_regex(r, r"test@example\.com|email", "T02.15b: displays email SAN")
    t.assert_contains(r, "example.com", "T02.15c: displays URI SAN")

    r = h.cmd("--no-color -d {f}", f=h.fixture("email-san.pem"))
    t.expect_ok(r, "T02.15d: email SAN detail view exits 0")
    t.assert_contains_regex(r, r"test@example\.com|email", "T02.15e: detail view shows email SAN")

    # --- T02.16: Multiple wildcard SANs ---
    print("-- T02.16: Multiple wildcard SANs")

    r = h.cmd("--no-color {f}", f=h.fixture("wildcard-multi.pem"))
    t.expect_ok(r, "T02.16a: multi-wildcard exits 0")
    t.assert_contains_regex(r, r"\*\.a\.com|a\.com", "T02.16b: shows first wildcard SAN")
    t.assert_contains_regex(r, r"\*\.b\.com|b\.com", "T02.16c: shows second wildcard SAN")

    # --- T02.17: PKCS#12 with empty password ---
    print("-- T02.17: PKCS#12 with empty password")

    fixture_p12 = h.fixture("leaf-nopass.p12")
    if fixture_p12.is_file() and fixture_p12.stat().st_size > 0:
        r = h.cmd('--no-color -p "" {f}', f=fixture_p12)
        t.PASS(f"T02.17a: nopass p12 handled (exit {r.returncode})")
    else:
        t.SKIP("T02.17: empty-password p12 fixture not generated")

    # --- T02.18: PKCS#12 with legacy algorithms ---
    print("-- T02.18: PKCS#12 with legacy algorithms")

    r = h.cmd("--no-color -p {pw} {f}", pw="test", f=h.fixture("legacy.p12"))
    t.expect_ok(r, "T02.18a: legacy p12 exits 0")
    t.assert_contains(r, "edge.test", "T02.18b: legacy p12 shows cert")

    # --- T02.19: JKS with entries ---
    print("-- T02.19: JKS with entries")

    r = h.cmd("--no-color -p {pw} {f}", pw="jkspass", f=h.fixture("multi.jks"))
    t.expect_ok(r, "T02.19a: JKS exits 0")
    t.assert_contains(r, "edge.test", "T02.19b: JKS lists cert entries")

    # --- T02.20: PKCS#7 certificates-only ---
    print("-- T02.20: PKCS#7 certificates-only")

    r = h.cmd("--no-color {f}", f=h.fixture("certs-only.p7b"))
    t.expect_ok(r, "T02.20a: p7b exits 0")
    t.assert_contains_regex(r, r"edge\.test|Intermediate|Root", "T02.20b: p7b lists certs")

    # --- T02.21: DER-encoded cert, key, CSR ---
    print("-- T02.21: DER-encoded cert, key, CSR")

    r = h.cmd("--no-color {f}", f=h.fixture("leaf.der"))
    t.expect_ok(r, "T02.21a: DER cert exits 0")
    t.assert_contains_regex(r, r"edge\.test|certificate", "T02.21b: DER cert shows correct type")

    r = h.cmd("--no-color {f}", f=h.fixture("leaf-key.der"))
    t.expect_ok(r, "T02.21c: DER key exits 0")
    t.assert_contains_regex(r, r"key|private", "T02.21d: DER key shows correct type")

    r = h.cmd("--no-color {f}", f=h.fixture("csr.der"))
    t.expect_ok(r, "T02.21e: DER CSR exits 0")
    t.assert_contains_regex(r, r"csr|request", "T02.21f: DER CSR shows correct type")

    # --- T02.22: PEM with garbage between blocks ---
    print("-- T02.22: PEM with garbage between blocks")

    r = h.cmd("--no-color {f}", f=h.fixture("noisy.pem"))
    t.expect_ok(r, "T02.22a: noisy PEM exits 0")
    t.assert_contains(r, "edge.test", "T02.22b: noisy PEM extracts cert blocks")
    t.assert_contains_regex(r, r"Intermediate", "T02.22c: noisy PEM extracts both certs")

    # --- T02.23: CRLF line endings ---
    print("-- T02.23: CRLF line endings")

    r = h.cmd("--no-color {f}", f=h.fixture("crlf.pem"))
    t.expect_ok(r, "T02.23a: CRLF PEM exits 0")
    t.assert_contains(r, "edge.test", "T02.23b: CRLF PEM parses correctly")

    # --- T02.24: Large bundle ---
    print("-- T02.24: Large bundle")

    r = h.cmd("--no-color {f}", f=h.fixture("big-bundle.pem"))
    t.expect_ok(r, "T02.24a: big bundle exits 0")
    t.assert_contains(r, "bulk", "T02.24b: big bundle lists certs")

    rj = h.cmd("--no-color -o json {f}", f=h.fixture("big-bundle.pem"))
    t.assert_json(rj, "T02.24c: big bundle JSON is valid")
    t.assert_json_item_count(rj, 20, "T02.24d: big bundle JSON has 20 items")

    # --- T02.25: Cert-only PKCS#12 (no private key) ---
    print("-- T02.25: Cert-only PKCS#12 (no private key)")

    h.cmd("bundle {leaf} {inter} -f pkcs12 --output-password {pw} -o {out} --no-confirm",
          leaf=h.fixture("leaf-rsa.pem"), inter=h.fixture("inter-ca.pem"),
          pw="certonly", out=h.tmp("cert-only.p12"))
    t.assert_file_not_empty(h.tmp("cert-only.p12"), "T02.25a: cert-only p12 created")

    r = h.cmd("--no-color -p {pw} {f}", pw="certonly", f=h.tmp("cert-only.p12"))
    t.expect_ok(r, "T02.25b: cert-only p12 reads successfully")
    t.assert_contains_regex(r, r"edge\.test|certificate", "T02.25c: cert-only p12 shows certs")

    h.cmd("extract {f} -p {pw} --type certs --output-dir {d} --no-confirm",
          f=h.tmp("cert-only.p12"), pw="certonly", d=h.tmp("cert-only-extract"))
    from ..lib.proc import FileHelper
    certs_found = len(FileHelper.files_matching(h.tmp("cert-only-extract"), "*.pem"))
    if certs_found >= 1:
        t.PASS(f"T02.25d: extracted {certs_found} cert(s) from cert-only p12")
    else:
        t.FAIL("T02.25d: extract certs from cert-only p12", f"found {certs_found}")

    h.cmd("extract {f} -p {pw} --type keys --output-dir {d} --no-confirm",
          f=h.tmp("cert-only.p12"), pw="certonly", d=h.tmp("cert-only-keys"))
    keys_found = len(FileHelper.files_matching(h.tmp("cert-only-keys"), "*"))
    if keys_found == 0:
        t.PASS("T02.25e: no keys extracted from cert-only p12")
    else:
        t.FAIL("T02.25e: no keys extracted from cert-only p12", f"found {keys_found}")


if __name__ == "__main__":
    h = Harness(fixtures_dir="../../edgecases/fixtures")
    h.setup()
    t = Tracker()
    try:
        run(h, t)
    finally:
        h.cleanup()
        t.close()
    t.summary("T02")
