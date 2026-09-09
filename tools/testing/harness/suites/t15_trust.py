"""T15: Trust status -- `--trust`, the TRUST/STORES columns and the trust checks.

Hermeticity rule, inherited from T12: the real OS, Java, NSS and bundle stores
differ per machine, so assertions against them are shape-only (exit code, valid
JSON, no panic). Content assertions are made only against fixture certificates,
which are signed by a private test root and are therefore `untrusted` on every
machine, every time.

No case here reaches the network.
"""

import json


def _fx(h, *parts):
    return h.fixture(*parts)


def _certs(result):
    """Flatten every certificate object out of a -o json scan."""
    data = json.loads(result.stdout)
    out = []
    for f in data.get("files", []):
        for item in f.get("items", []):
            if item.get("certificate"):
                out.append(item["certificate"])
    return out


def run(h, t):
    print("\n=== T15: Trust Status ===")

    chain_full = _fx(h, "chain-full.pem")
    self_signed = _fx(h, "self-signed.pem")
    leaf = _fx(h, "leaf-rsa.pem")
    expired = _fx(h, "expired.pem")

    # --- T15.01: shape across every output format ---
    print("-- T15.01: --trust shape")

    for fmt in ["list", "table", "json", "yaml"]:
        r = h.cmd("--no-color --trust -o {fmt} {f}", fmt=fmt, f=chain_full)
        t.expect_ok(r, f"T15.01a: --trust -o {fmt} exits 0")

    r = h.cmd("--no-color --trust -o json {f}", f=chain_full)
    t.assert_json(r, "T15.01b: --trust -o json is well-formed")

    r = h.cmd("--no-color --trust -t {f}", f=chain_full)
    t.expect_ok(r, "T15.01c: --trust with the table view exits 0")
    t.assert_contains(r, "TRUST", "T15.01d: the table gains a TRUST column")

    r = h.cmd("--no-color --trust -d {f}", f=chain_full)
    t.expect_ok(r, "T15.01e: --trust with details exits 0")

    # --- T15.02: a private chain is untrusted everywhere ---
    print("-- T15.02: fixture chain verdicts")

    r = h.cmd("--no-color --trust -o json {f}", f=chain_full)
    certs = _certs(r)
    if not certs:
        t.FAIL("T15.02a: the fixture chain produced certificates", "no certificates in output")
    else:
        t.PASS(f"T15.02a: the fixture chain produced certificates ({len(certs)})")

        # Every certificate carries a verdict, and it is one of the five.
        valid = {"anchor", "trusted", "expired", "untrusted", "denied"}
        bad = [c.get("trust") for c in certs if c.get("trust") not in valid]
        if bad:
            t.FAIL("T15.02b: every verdict is part of the vocabulary", f"unexpected: {bad}")
        else:
            t.PASS("T15.02b: every verdict is part of the vocabulary")

        # The fixture root is private, so nothing in the chain can be trusted
        # by this machine. This is the assertion that is stable everywhere.
        trusted = [c["subject"] for c in certs if c.get("trust") in ("anchor", "trusted")]
        if trusted:
            t.FAIL("T15.02c: a privately-signed fixture chain is untrusted",
                   f"unexpectedly trusted: {trusted}")
        else:
            t.PASS("T15.02c: a privately-signed fixture chain is untrusted")

    r = h.cmd("--no-color --trust -o json {f}", f=self_signed)
    certs = _certs(r)
    if certs and certs[0].get("trust") == "untrusted":
        t.PASS("T15.02d: an unknown self-signed certificate is untrusted")
    else:
        t.FAIL("T15.02d: an unknown self-signed certificate is untrusted",
               f"got {certs[0].get('trust') if certs else 'no certificates'}")

    # --- T15.03: the JSON contract ---
    print("-- T15.03: JSON contract")

    r = h.cmd("--no-color --trust -o json {f}", f=leaf)
    certs = _certs(r)
    if certs:
        verdict = certs[0].get("trust", "")
        if verdict and verdict == verdict.lower():
            t.PASS("T15.03a: the trust value is canonical lowercase")
        else:
            t.FAIL("T15.03a: the trust value is canonical lowercase", f"got {verdict!r}")

    # Without --trust the fields must be absent entirely, not empty.
    r = h.cmd("--no-color -o json {f}", f=leaf)
    t.assert_not_contains(r, '"trust"', "T15.03b: no trust field without --trust")
    t.assert_not_contains(r, '"trust_anchor"', "T15.03c: no trust_anchor field without --trust")
    t.assert_not_contains(r, '"stores"', "T15.03d: no stores field without --trust")

    r = h.cmd("schema")
    t.assert_contains(r, '"trust"', "T15.03e: the published schema documents trust")
    t.assert_contains(r, "trust_anchor", "T15.03f: the published schema documents trust_anchor")

    # --- T15.04: piped output stays clean ---
    print("-- T15.04: machine-readable output is not polluted")

    r = h.cmd("--no-color --trust -o json {f}", f=chain_full)
    t.assert_json(r, "T15.04a: --trust -o json parses despite store warnings")
    for noise in ["SNAPSHOT", "libnssckbi", "certdiag:"]:
        t.assert_not_contains(r, noise, f"T15.04b: {noise!r} does not leak into stdout")

    r = h.cmd("--no-color --trust -o yaml {f}", f=chain_full)
    t.expect_ok(r, "T15.04c: --trust -o yaml exits 0")

    # --- T15.05: the trust check category ---
    print("-- T15.05: trust checks")

    r = h.cmd("--no-color check --trust {f}", f=chain_full)
    t.assert_contains_regex(r, r"untrusted_chain|No path to a trust anchor",
                            "T15.05a: untrusted_chain fires on a private chain")

    # Without --trust neither trust check may fire.
    r = h.cmd("--no-color check {f}", f=chain_full)
    t.assert_not_contains(r, "untrusted_chain", "T15.05b: untrusted_chain is silent without --trust")
    t.assert_not_contains(r, "distrusted_root", "T15.05c: distrusted_root is silent without --trust")

    r = h.cmd("--no-color check --trust -o json {f}", f=chain_full)
    t.assert_json(r, "T15.05d: check --trust -o json is well-formed")

    # --- T15.06: config default ---
    print("-- T15.06: defaults.output.trust")

    cfg = h.tmp("trust-config", "certdiag.yaml")
    cfg.write_text(
        "kind: certdiag-config\n"
        'version: "1"\n'
        "defaults:\n"
        "  output:\n"
        "    trust: true\n"
        "passwords:\n"
        "  common_plaintext: []\n"
        "  common_encrypted: []\n"
        "  by_filename: []\n"
    )

    r = h.cmd("--no-color -c {c} -o json {f}", c=cfg, f=leaf)
    t.expect_ok(r, "T15.06a: the config default exits 0")
    t.assert_contains(r, '"trust"', "T15.06b: defaults.output.trust turns evaluation on")

    # --- T15.07: chain_incomplete keeps its file-level meaning ---
    print("-- T15.07: chain_incomplete is unaffected by trust")

    # A leaf whose issuer is not in the scan is an incomplete bundle whether or
    # not the machine happens to trust the chain.
    r_plain = h.cmd("--no-color check {f}", f=leaf)
    r_trust = h.cmd("--no-color check --trust {f}", f=leaf)

    plain_has = "chain_incomplete" in r_plain.stdout or "Chain incomplete" in r_plain.stdout
    trust_has = "chain_incomplete" in r_trust.stdout or "Chain incomplete" in r_trust.stdout
    if plain_has == trust_has:
        t.PASS("T15.07a: --trust does not change whether chain_incomplete fires")
    else:
        t.FAIL("T15.07a: --trust does not change whether chain_incomplete fires",
               f"without --trust: {plain_has}, with: {trust_has}")

    # --- T15.08: relations still render ---
    print("-- T15.08: relations with trust")

    r = h.cmd("--no-color --trust {f}", f=chain_full)
    t.expect_ok(r, "T15.08a: --trust with relations exits 0")
    t.assert_contains_regex(r, r"chain:|signed.by",
                            "T15.08b: relations still render with trust enabled")

    # --- T15.09: expired certificates ---
    print("-- T15.09: expired input")

    r = h.cmd("--no-color --trust -o json {f}", f=expired)
    t.expect_ok(r, "T15.09a: --trust on an expired certificate exits 0")
    certs = _certs(r)
    if certs and certs[0].get("trust") in ("untrusted", "expired"):
        t.PASS("T15.09b: an expired private certificate is untrusted or expired")
    else:
        t.FAIL("T15.09b: an expired private certificate is untrusted or expired",
               f"got {certs[0].get('trust') if certs else 'no certificates'}")

    # --- T15.10: negatives ---
    print("-- T15.10: negatives")

    r = h.cmd("--no-color --trust -o bogus {f}", f=leaf)
    t.expect_fail(r, "T15.10a: an invalid output format is still rejected with --trust")

    r = h.cmd("--no-color --trust {f}", f=h.tmp("does-not-exist.pem"))
    t.expect_fail(r, "T15.10b: a missing path still fails with --trust")
