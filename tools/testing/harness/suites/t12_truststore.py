"""T12: Trust stores -- `store`, `store discover`, `verify`, `tui store`.

Hermeticity rule for this suite: the OS, Java and OpenSSL stores differ per
machine and per CI runner, so assertions against the *real* stores are
shape-only (exit code, valid JSON, required keys, no panic). Content assertions
are made only against the fixtures under edgecases/fixtures/truststore, which
are identical everywhere.
"""

import json


def _ts(h, *parts):
    return h.fixture("truststore", *parts)


def run(h, t):
    print("\n=== T12: Trust Stores ===")

    fake_jdk = _ts(h, "fake-java-home")
    fake_jdk_jsse = _ts(h, "fake-java-home-jsse")
    fake_jdk_badpw = _ts(h, "fake-java-home-badpw")
    bundle3 = _ts(h, "ca-bundle-3roots.pem")
    bundle_empty = _ts(h, "ca-bundle-empty.pem")
    bundle_corrupt = _ts(h, "ca-bundle-corrupt.pem")

    chain_root = _ts(h, "verify-chain", "root.pem")
    chain_leaf = _ts(h, "verify-chain", "leaf.pem")
    chain_leaf_inter = _ts(h, "verify-chain", "leaf-with-inter.pem")
    chain_expired = _ts(h, "verify-chain", "leaf-expired.pem")

    # --- T12.01: store discover (shape only) ---
    print("-- T12.01: store discover")

    r = h.cmd("--no-color store discover")
    t.expect_ok(r, "T12.01a: store discover exits 0")

    r = h.cmd("--no-color store discover -o json")
    t.expect_ok(r, "T12.01b: store discover -o json exits 0")
    t.assert_json(r, "T12.01b: store discover emits valid JSON")

    r = h.cmd("--no-color store discover -o yaml")
    t.expect_ok(r, "T12.01c: store discover -o yaml exits 0")

    r = h.cmd("--no-color store discover -o bogus")
    t.expect_fail(r, "T12.01d: invalid output format rejected")

    # --- T12.02: store, OS default (shape only) ---
    print("-- T12.02: store (OS default)")

    for fmt in ["list", "table", "json", "yaml"]:
        r = h.cmd("--no-color store -o {fmt}", fmt=fmt)
        t.expect_ok(r, f"T12.02: store -o {fmt} exits 0")
    r = h.cmd("--no-color store -o json")
    t.assert_json(r, "T12.02: store -o json is well-formed")

    r = h.cmd("--no-color store -o bogus")
    t.expect_fail(r, "T12.02: invalid output format rejected")

    r = h.cmd("--no-color store -d")
    t.expect_ok(r, "T12.02: store --details exits 0")
    t.assert_no_ansi(r, "T12.02: --no-color strips ANSI")

    # --- T12.03: store --java-home (fixture, deterministic) ---
    print("-- T12.03: store --java-home with a fixture JDK")

    r = h.cmd("--no-color store --java-home {p}", p=fake_jdk)
    t.expect_ok(r, "T12.03a: fixture JDK exits 0")
    t.assert_contains(r, "TrustStore Root One", "T12.03a: reads the fixture roots")
    t.assert_contains(r, "3 certs", "T12.03a: reports the exact count")

    r = h.cmd("--no-color store --java-home {p} -o json", p=fake_jdk)
    t.expect_ok(r, "T12.03b: fixture JDK JSON exits 0")
    t.assert_json(r, "T12.03b: fixture JDK emits valid JSON")
    try:
        rows = json.loads(r.stdout)
        if isinstance(rows, list) and len(rows) == 3:
            t.PASS("T12.03b: JSON holds exactly 3 certificates")
        else:
            t.FAIL("T12.03b: JSON holds exactly 3 certificates",
                   f"got {len(rows) if isinstance(rows, list) else type(rows)}")
    except (ValueError, TypeError) as e:
        t.FAIL("T12.03b: JSON holds exactly 3 certificates", str(e))

    r = h.cmd("--no-color store --java-home {p} -q \"Root Two\"", p=fake_jdk)
    t.expect_ok(r, "T12.03c: query filter exits 0")
    t.assert_contains(r, "TrustStore Root Two", "T12.03c: keeps the match")
    t.assert_not_contains(r, "TrustStore Root One", "T12.03c: drops non-matches")

    r = h.cmd("--no-color store --java-home {p} -q zzz-no-such-ca", p=fake_jdk)
    t.expect_ok(r, "T12.03d: a query with no matches still exits 0")

    # --- T12.04: jssecacerts override ---
    print("-- T12.04: jssecacerts override")

    r = h.cmd("--no-color store --java-home {p}", p=fake_jdk_jsse)
    t.expect_ok(r, "T12.04a: jssecacerts JDK exits 0")
    t.assert_contains(r, "jssecacerts", "T12.04a: warns about the override",
                      stream="stderr")
    # jssecacerts holds 2 roots, cacerts only 1 -- proves the right file was read.
    t.assert_contains(r, "2 certs", "T12.04b: reads jssecacerts, not cacerts")

    # --- T12.05: store --java-home error paths ---
    print("-- T12.05: --java-home error paths")

    r = h.cmd("--no-color store --java-home {p}", p=h.tmp("no-such-jdk"))
    t.expect_fail(r, "T12.05a: nonexistent JAVA_HOME exits non-zero")
    t.assert_not_timed_out(r, "T12.05a: no hang")

    empty_home = h.tmp("empty-jdk")
    empty_home.mkdir(parents=True, exist_ok=True)
    r = h.cmd("--no-color store --java-home {p}", p=empty_home)
    t.expect_fail(r, "T12.05b: JAVA_HOME without cacerts exits non-zero")

    # A cacerts whose password is not "changeit" yields an empty store rather
    # than an error: the JKS reader returns no entries instead of failing.
    # Documented here as the current behaviour -- the output must at least make
    # the emptiness visible rather than implying the store is genuinely bare.
    r = h.cmd("--no-color store --java-home {p}", p=fake_jdk_badpw)
    t.assert_not_timed_out(r, "T12.05c: a non-default cacerts password does not hang")
    t.assert_contains(r, "0 certs", "T12.05c: an unreadable cacerts reports zero certs")

    # --- T12.06: store --trust-file ---
    print("-- T12.06: store --trust-file")

    r = h.cmd("--no-color store --trust-file {p}", p=bundle3)
    t.expect_ok(r, "T12.06a: PEM bundle exits 0")
    t.assert_contains(r, "3 certs", "T12.06a: reads all 3 roots")

    r = h.cmd("--no-color store --trust-file {p} -o json", p=bundle3)
    t.assert_json(r, "T12.06b: bundle JSON is well-formed")

    r = h.cmd("--no-color store --trust-file {p}", p=h.tmp("no-such-bundle.pem"))
    t.expect_fail(r, "T12.06c: missing bundle exits non-zero")

    # Same shape as T12.05c: undecodable PEM blocks are skipped, leaving an
    # empty store rather than an error.
    r = h.cmd("--no-color store --trust-file {p}", p=bundle_corrupt)
    t.assert_not_timed_out(r, "T12.06d: corrupt bundle does not hang")
    t.assert_contains(r, "0 certs", "T12.06d: corrupt bundle reports zero certs")

    r = h.cmd("--no-color store --trust-file {p}", p=bundle_empty)
    t.assert_not_timed_out(r, "T12.06e: empty bundle does not hang")

    r = h.cmd("--no-color store --trust-file {p} -p changeit",
              p=_ts(h, "fake-java-home", "lib", "security", "cacerts"))
    t.expect_ok(r, "T12.06f: JKS bundle via --trust-file with -p exits 0")
    t.assert_contains(r, "TrustStore Root One", "T12.06f: reads the JKS entries")

    # --- T12.07: store --java / --openssl (shape only) ---
    print("-- T12.07: store --java / --openssl")

    r = h.cmd("--no-color store --java")
    t.assert_not_timed_out(r, "T12.07a: --java does not hang")
    if r.returncode == 0:
        t.PASS("T12.07a: --java succeeded (JDKs present on this host)")
    else:
        t.assert_contains_regex(r, r"(?i)java|jdk|cacerts",
                                "T12.07a: --java failure names Java",
                                stream="stderr")

    r = h.cmd("--no-color store --openssl")
    t.assert_not_timed_out(r, "T12.07b: --openssl does not hang")
    if r.returncode != 0:
        t.assert_contains_regex(r, r"(?i)openssl",
                                "T12.07b: --openssl failure names OpenSSL",
                                stream="stderr")
    else:
        t.PASS("T12.07b: --openssl succeeded")

    # --- T12.08: verify against a fixture store ---
    print("-- T12.08: verify")

    r = h.cmd("--no-color verify {leaf} --trust-file {ca}",
              leaf=chain_leaf_inter, ca=chain_root)
    t.expect_ok(r, "T12.08a: full chain against its root exits 0")
    t.assert_contains(r, "TRUSTED", "T12.08a: reports TRUSTED")

    r = h.cmd("--no-color verify {leaf} --trust-file {ca}",
              leaf=chain_leaf_inter, ca=bundle3)
    t.assert_contains(r, "NOT TRUSTED", "T12.08b: unrelated CA is not trusted")

    r = h.cmd("--no-color verify {leaf} --trust-file {ca}",
              leaf=chain_leaf, ca=chain_root)
    t.assert_contains(r, "NOT TRUSTED",
                      "T12.08c: leaf without its intermediate is not trusted")

    r = h.cmd("--no-color verify {leaf} --trust-file {ca}",
              leaf=chain_expired, ca=chain_root)
    t.assert_contains(r, "NOT TRUSTED", "T12.08d: expired leaf is not trusted")
    t.assert_contains_regex(r, r"(?i)expir", "T12.08d: reason mentions expiry")

    for fmt in ["json", "yaml"]:
        r = h.cmd("--no-color verify {leaf} --trust-file {ca} -o {fmt}",
                  leaf=chain_leaf_inter, ca=chain_root, fmt=fmt)
        t.expect_ok(r, f"T12.08e: verify -o {fmt} exits 0")
    r = h.cmd("--no-color verify {leaf} --trust-file {ca} -o json",
              leaf=chain_leaf_inter, ca=chain_root)
    t.assert_json(r, "T12.08e: verify JSON is well-formed")

    r = h.cmd("--no-color verify {leaf} --java-home {p}",
              leaf=chain_leaf_inter, p=fake_jdk)
    t.assert_not_timed_out(r, "T12.08f: verify against a fixture JDK does not hang")
    t.assert_contains(r, "NOT TRUSTED",
                      "T12.08f: the fixture JDK does not trust this chain")

    # --- T12.09: verify error paths ---
    print("-- T12.09: verify error paths")

    r = h.cmd("--no-color verify {p} --trust-file {ca}",
              p=h.tmp("no-such-cert.pem"), ca=chain_root)
    # A missing path is treated as a hostname, so this attempts a connection.
    t.assert_not_timed_out(r, "T12.09a: a missing file does not hang")
    t.expect_fail(r, "T12.09a: unresolvable target exits non-zero")

    r = h.cmd("--no-color verify {leaf} --trust-file {ca}",
              leaf=chain_leaf, ca=h.tmp("no-such-ca.pem"))
    t.expect_fail(r, "T12.09b: a missing --trust-file CA exits non-zero")

    r = h.cmd("--no-color verify {leaf} -o bogus", leaf=chain_leaf)
    t.expect_fail(r, "T12.09c: invalid output format rejected")

    # --- T12.10: tui store guard ---
    print("-- T12.10: tui store")

    r = h.cmd("tui store --group bogus")
    t.expect_fail(r, "T12.10a: an invalid --group value is rejected")
    t.assert_contains_regex(r, r"(?i)instance|kind",
                            "T12.10a: the error names the valid values",
                            stream="stderr")

    r = h.cmd("tui store", env_extra={"CERTDIAG_SHELL": "1"})
    t.expect_fail(r, "T12.10b: tui store refuses to nest inside a certdiag shell")

    r = h.cmd("tui store --help")
    t.expect_ok(r, "T12.10c: tui store --help exits 0")
    t.assert_contains(r, "--group", "T12.10c: help documents --group")
    t.assert_contains(r, "--trust-file", "T12.10c: help documents --trust-file")
