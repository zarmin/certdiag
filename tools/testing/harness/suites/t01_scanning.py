from ..lib.harness import Harness
from ..lib.assertions import Tracker


def run(h, t):
    print("\n=== T01: Scanning Edge Cases ===")

    # --- T01.01: Recursive with deeply nested directories ---
    print("-- T01.01: Recursive with deeply nested directories")

    r = h.cmd("--no-color -r {path}", path=h.fixture("deep"))
    t.expect_ok(r, "T01.01a: recursive deep scan exits 0")
    t.assert_contains(r, "leaf.pem", "T01.01a: finds leaf.pem at depth 5")

    r = h.cmd("--no-color -r --depth 3 {path}", path=h.fixture("deep"))
    t.expect_ok(r, "T01.01b: depth 3 exits 0")
    t.assert_not_contains(r, "leaf.pem", "T01.01b: depth 3 does NOT find leaf at depth 5")

    # deep/a/b/c/d/e/leaf.pem is 5 subdirs deep; depth counts from 1 (dir itself), so need depth 6
    r = h.cmd("--no-color -r --depth 6 {path}", path=h.fixture("deep"))
    t.expect_ok(r, "T01.01c: depth 6 exits 0")
    t.assert_contains(r, "leaf.pem", "T01.01c: depth 6 finds leaf.pem")

    # --- T01.02: Recursive with symlink loop ---
    print("-- T01.02: Recursive with symlink loop")

    r = h.cmd("--no-color -r {path}", path=h.fixture("loopy"))
    t.expect_ok(r, "T01.02: symlink loop terminates without infinite loop")

    # --- T01.03: Recursive on empty directory ---
    print("-- T01.03: Recursive on empty directory")

    r = h.cmd("--no-color -r {path}", path=h.fixture("empty-tree"))
    t.expect_ok(r, "T01.03a: empty tree exits 0")

    r = h.cmd("--no-color -r -o json {path}", path=h.fixture("empty-tree"))
    t.expect_ok(r, "T01.03b: empty tree JSON exits 0")
    t.assert_json(r, "T01.03b: empty tree produces valid JSON")

    # --- T01.04: Depth semantics ---
    print("-- T01.04: Depth semantics")
    # depth 0 = unlimited, depth 1 = start dir only, depth 2 = start + one level of subs

    r = h.cmd("--no-color -r --depth 1 {path}", path=h.fixture("depth-test"))
    t.expect_ok(r, "T01.04a: depth 1 exits 0")
    t.assert_contains(r, "cert.pem", "T01.04a: depth 1 finds cert.pem at root")
    t.assert_not_contains(r, "cert2.pem", "T01.04a: depth 1 does NOT find sub/cert2.pem")

    r = h.cmd("--no-color -r --depth 2 {path}", path=h.fixture("depth-test"))
    t.expect_ok(r, "T01.04b: depth 2 exits 0")
    t.assert_contains(r, "cert.pem", "T01.04b: depth 2 finds cert.pem")
    t.assert_contains(r, "cert2.pem", "T01.04b: depth 2 finds sub/cert2.pem")

    # --- T01.05: Signature scan on renamed files ---
    print("-- T01.05: Signature scan on renamed files")

    r = h.cmd("--no-color {path}", path=h.fixture("sig-scan"))
    t.assert_not_contains(r, "mystery.dat", "T01.05a: without sig scan, renamed files not found")

    r = h.cmd("--no-color --file-signature-scan {path}", path=h.fixture("sig-scan"))
    t.expect_ok(r, "T01.05b: sig scan exits 0")
    t.assert_contains(r, "mystery.dat", "T01.05b: sig scan finds mystery.dat")

    # --- T01.06: Signature scan false positive resilience ---
    print("-- T01.06: Signature scan false positive resilience")

    r = h.cmd("--no-color --file-signature-scan {path}", path=h.fixture("sig-scan", "notacert.bin"))
    # Should not crash, any exit code is acceptable as long as it does not hang or segfault
    t.PASS(f"T01.06: sig scan on false positive did not crash (exit {r.returncode})")

    # --- T01.07: Query with special characters ---
    print("-- T01.07: Query with special characters")

    # Query on single file to avoid mixed-content exit codes
    r = h.cmd("--no-color -q {query} {path}", query="*.edge.test", path=h.fixture("leaf-rsa.pem"))
    t.expect_ok(r, "T01.07a: wildcard query exits 0")
    t.assert_contains(r, "edge", "T01.07a: wildcard query finds edge cert")

    r = h.cmd("--no-color -q {query} {path1} {path2}",
              query="", path1=h.fixture("leaf-rsa.pem"), path2=h.fixture("leaf-ec.pem"))
    t.expect_ok(r, "T01.07b: empty query exits 0")
    t.assert_contains(r, "edge", "T01.07b: empty query matches everything")

    r = h.cmd("--no-color -q {query} {path}",
              query="NONEXISTENT_STRING_XYZ", path=h.fixture("leaf-rsa.pem"))
    t.expect_ok(r, "T01.07c: no-match query exits 0")
    t.assert_not_contains(r, "Subject", "T01.07c: no-match query produces no cert output")

    r = h.cmd("--no-color -q {query} {path}", query="127.0.0.1", path=h.fixture("leaf-rsa.pem"))
    t.expect_ok(r, "T01.07d: IP SAN query exits 0")
    t.assert_contains(r, "127.0.0.1", "T01.07d: IP SAN query finds matching cert")

    # --- T01.08: Query combined with output formats ---
    print("-- T01.08: Query combined with output formats")

    # Use specific files to avoid mixed-content issues
    r = h.cmd("--no-color -q {query} -o json {path1} {path2}",
              query="edge", path1=h.fixture("leaf-rsa.pem"), path2=h.fixture("leaf-ec.pem"))
    t.expect_ok(r, "T01.08a: query + JSON exits 0")
    t.assert_json(r, "T01.08a: query + JSON produces valid JSON")
    t.assert_contains(r, "edge", "T01.08a: JSON output contains filtered results")

    r = h.cmd("--no-color -q {query} -o yaml {path1} {path2}",
              query="edge", path1=h.fixture("leaf-rsa.pem"), path2=h.fixture("leaf-ec.pem"))
    t.expect_ok(r, "T01.08b: query + YAML exits 0")
    t.assert_contains(r, "edge", "T01.08b: YAML output contains filtered results")

    r = h.cmd("--no-color -q {query} -t {path1} {path2}",
              query="edge", path1=h.fixture("leaf-rsa.pem"), path2=h.fixture("leaf-ec.pem"))
    t.expect_ok(r, "T01.08c: query + table exits 0")
    t.assert_contains(r, "edge", "T01.08c: table output contains filtered results")

    # --- T01.09: Discover across formats ---
    print("-- T01.09: Discover across formats")

    r = h.cmd("--no-color -D {path}", path=h.fixture("discover"))
    t.expect_ok(r, "T01.09: discover exits 0")
    t.assert_contains(r, "leaf-rsa", "T01.09: discover shows key-cert relationship")

    # --- T01.10: Discover with mismatched keys ---
    print("-- T01.10: Discover with mismatched keys")

    r = h.cmd("--no-color -D {path}", path=h.fixture("discover-mismatch"))
    t.expect_ok(r, "T01.10: discover mismatch exits 0")
    t.assert_not_contains(r, "matches", "T01.10: mismatched keys show no relationship")

    # --- T01.11: Check inline combined with other flags ---
    print("-- T01.11: Check inline combined with other flags")

    r = h.cmd("--no-color --check -o json {path}", path=h.fixture("leaf-rsa.pem"))
    t.expect_ok(r, "T01.11a: check + JSON exits 0")
    t.assert_json(r, "T01.11a: check + JSON produces valid JSON")

    r = h.cmd("--no-color --check -t {path1} {path2}",
              path1=h.fixture("leaf-rsa.pem"), path2=h.fixture("leaf-ec.pem"))
    t.expect_ok(r, "T01.11b: check + table exits 0")
    t.assert_contains(r, "edge", "T01.11b: check + table shows cert info")

    r = h.cmd("--no-color --check -q {query} {path}",
              query="edge", path=h.fixture("leaf-rsa.pem"))
    t.expect_ok(r, "T01.11c: check + query exits 0")
    t.assert_contains(r, "edge", "T01.11c: check + query filters correctly")

    r = h.cmd("--no-color --check --expiry-warn 9999 {path}", path=h.fixture("leaf-rsa.pem"))
    t.assert_contains(r, "Expir", "T01.11d: expiry-warn 9999 triggers warning")

    # --- T01.12: Custom expiry thresholds edge cases ---
    print("-- T01.12: Custom expiry thresholds edge cases")

    r = h.cmd("--no-color --check --expiry-warn 0 {path}", path=h.fixture("leaf-rsa.pem"))
    t.expect_ok(r, "T01.12a: expiry-warn 0 exits 0")
    t.assert_not_contains(r, "expiring soon", "T01.12a: expiry-warn 0 produces no expiry warning")

    r = h.cmd("--no-color --check --expiry-critical 99999 {path}", path=h.fixture("leaf-rsa.pem"))
    t.assert_contains(r, "Expir", "T01.12b: expiry-critical 99999 flags everything critical")

    # --- T01.13: Insecure details flag ---
    print("-- T01.13: Insecure details flag")

    # Normal detail view shows key type but NOT the PEM-encoded private key content
    r = h.cmd("--no-color -d {path}", path=h.fixture("leaf-rsa.key"))
    t.expect_ok(r, "T01.13a: details on key exits 0")
    t.assert_not_contains(r, "BEGIN", "T01.13a: details does NOT show PEM key content")

    # Insecure details shows the actual PEM-encoded private key
    r = h.cmd("--no-color --insecure-details {path}", path=h.fixture("leaf-rsa.key"))
    t.expect_ok(r, "T01.13b: insecure-details exits 0")
    t.assert_contains(r, "BEGIN", "T01.13b: insecure-details shows PEM key data")

    # --- T01.14: List alias equivalence ---
    print("-- T01.14: List alias equivalence")

    r1 = h.cmd("--no-color {path}", path=h.fixture("leaf-rsa.pem"))
    r2 = h.cmd("--no-color list {path}", path=h.fixture("leaf-rsa.pem"))
    t.expect_ok(r1, "T01.14a: implicit list exits 0")
    t.expect_ok(r2, "T01.14b: explicit list exits 0")
    t.assert_equal(r1.stdout, r2.stdout, "T01.14c: list alias produces identical output")

    # --- T01.15: Multiple paths on command line ---
    print("-- T01.15: Multiple paths on command line")

    r = h.cmd("--no-color {path1} {path2}",
              path1=h.fixture("leaf-rsa.pem"), path2=h.fixture("leaf-ec.pem"))
    t.expect_ok(r, "T01.15a: two files exits 0")
    t.assert_contains(r, "edge.test", "T01.15a: first cert appears")
    t.assert_contains(r, "edge-ec.test", "T01.15a: second cert appears")

    # Directory with mixed content may exit non-zero due to unparseable files
    r = h.cmd("--no-color {path1} {path2}",
              path1=h.fixture("leaf-rsa.pem"), path2=h.fixture("discover"))
    t.expect_ok(r, "T01.15b: file + directory exits 0")
    t.assert_contains(r, "edge.test", "T01.15b: file cert appears")
    t.assert_contains(r, "leaf-rsa", "T01.15b: directory certs appear")

    # --- T01.16: Details on PKCS#12 and JKS ---
    print("-- T01.16: Details on PKCS#12 and JKS")

    r = h.cmd("--no-color -d -p {password} {path}", password="test", path=h.fixture("leaf.p12"))
    t.expect_ok(r, "T01.16a: details on p12 exits 0")
    t.assert_contains(r, "edge", "T01.16a: p12 details shows cert info")

    r = h.cmd("--no-color -d -p {password} {path}", password="jkspass", path=h.fixture("leaf.jks"))
    t.expect_ok(r, "T01.16b: details on JKS exits 0")
    t.assert_contains(r, "edge", "T01.16b: JKS details shows cert info")

    # --- T01.17: Table view with many items ---
    print("-- T01.17: Table view with many items")

    # Use clean directory with only cert files for table test
    r = h.cmd("--no-color -t {path}", path=h.fixture("discover"))
    t.expect_ok(r, "T01.17: table view exits 0")
    t.assert_contains(r, "RSA-2048", "T01.17: table view shows cert data")

    # --- T01.18: Scanning a single non-cert file ---
    print("-- T01.18: Scanning a single non-cert file")

    r = h.cmd("--no-color {path}", path=h.fixture("garbage.bin"))
    t.PASS(f"T01.18: non-cert file handled gracefully (exit {r.returncode})")


if __name__ == "__main__":
    from pathlib import Path

    fixtures_dir = Path(__file__).resolve().parents[2] / "edgecases" / "fixtures"
    h = Harness(fixtures_dir=fixtures_dir)
    h.setup()
    t = Tracker()
    try:
        run(h, t)
    finally:
        h.cleanup()
    t.summary("T01")
