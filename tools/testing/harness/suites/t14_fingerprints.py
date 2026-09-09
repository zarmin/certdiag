"""T14: multi-algorithm certificate fingerprints and the display format.

The load-bearing assertion here is T14.04: the --fingerprint-format setting is
display-only, so `-o json` must be byte-identical whichever format is selected.
That is what keeps the published `certdiag schema` contract and any jq/jsonpath
consumer independent of a user's config.
"""

import json

from ..lib.harness import Harness
from ..lib.assertions import Tracker


def _ts(h, *parts):
    return h.fixture("truststore", *parts)

def run(h, t):
    print("\n=== T14: Certificate Fingerprints ===")

    cert = _ts(h, "verify-chain", "leaf.pem")
    bundle = _ts(h, "ca-bundle-3roots.pem")

    # --- T14.01: every algorithm appears in detailed output ---
    print("-- T14.01: all five algorithms")

    r = h.cmd("--no-color -d {p}", p=cert)
    t.expect_ok(r, "T14.01a: detailed listing exits 0")
    for label in ["MD5:", "SHA-1:", "SHA-256:", "SHA-384:", "SHA-512:"]:
        t.assert_contains(r, label, f"T14.01b: detailed output shows {label.rstrip(':')}")

    # Without --details there are no fingerprints at all.
    r = h.cmd("--no-color {p}", p=cert)
    t.assert_not_contains(r, "SHA-512:", "T14.01c: fingerprints stay behind --details")

    # --- T14.02: display formats ---
    print("-- T14.02: display formats")

    r = h.cmd("--no-color -d {p}", p=cert)
    t.assert_contains_regex(r, r"SHA-256:\s+[0-9a-f]{64}\b",
                            "T14.02a: default is lowercase hex")

    r = h.cmd("--no-color --fingerprint-format hex-colon -d {p}", p=cert)
    t.assert_contains_regex(r, r"SHA-256:\s+([0-9a-f]{2}:){31}[0-9a-f]{2}\b",
                            "T14.02b: hex-colon is colon-separated pairs")

    r = h.cmd("--no-color --fingerprint-format base64 -d {p}", p=cert)
    t.assert_contains_regex(r, r"SHA-256:\s+[A-Za-z0-9+/]{43}=",
                            "T14.02c: base64 is standard padded base64")

    r = h.cmd("--no-color --fingerprint-format hex -d {p}", p=cert)
    t.assert_contains_regex(r, r"SHA-256:\s+[0-9a-f]{64}\b",
                            "T14.02d: explicit hex matches the default")

    # --- T14.03: invalid value is a usage error ---
    print("-- T14.03: invalid format")

    r = h.cmd("--no-color --fingerprint-format bogus -d {p}", p=cert)
    t.expect_fail(r, "T14.03a: invalid --fingerprint-format exits non-zero")
    t.assert_contains_regex(r, r"(?i)hex-colon|base64",
                            "T14.03b: the error names the valid values", stream="stderr")

    # --- T14.04: THE CONTRACT -- machine output never changes ---
    print("-- T14.04: JSON/YAML stay canonical")

    baseline = None
    for fmt in ["hex", "hex-colon", "base64"]:
        r = h.cmd("--no-color --fingerprint-format {fmt} -o json {p}", fmt=fmt, p=cert)
        t.expect_ok(r, f"T14.04a: -o json with {fmt} exits 0")
        t.assert_json(r, f"T14.04a: -o json with {fmt} is valid")
        if baseline is None:
            baseline = r.stdout
        elif r.stdout != baseline:
            t.FAIL("T14.04b: JSON is identical across formats",
                   f"{fmt} produced different output")
            break
    else:
        t.PASS("T14.04b: JSON is identical across formats")

    r = h.cmd("--no-color --fingerprint-format hex-colon -o json {p}", p=cert)
    try:
        cert_obj = json.loads(r.stdout)["files"][0]["items"][0]["certificate"]
        missing = [k for k in ("md5", "sha1", "sha256", "sha384", "sha512") if k not in cert_obj]
        if missing:
            t.FAIL("T14.04c: JSON carries all five digests", f"missing {missing}")
        elif any(":" in cert_obj[k] for k in ("md5", "sha1", "sha256", "sha384", "sha512")):
            t.FAIL("T14.04c: JSON digests are canonical hex", "found a separator")
        else:
            t.PASS("T14.04c: JSON carries all five digests in canonical hex")
    except (ValueError, KeyError, IndexError, TypeError) as e:
        t.FAIL("T14.04c: JSON carries all five digests", str(e))

    # --- T14.05: other commands honour the format ---
    print("-- T14.05: diff and store")

    r = h.cmd("--no-color --fingerprint-format hex-colon diff {a} {b} -d",
              a=cert, b=_ts(h, "verify-chain", "root.pem"))
    t.assert_contains_regex(r, r"SHA-256:\s+([0-9a-f]{2}:){31}",
                            "T14.05a: diff -d honours the format")
    t.assert_contains(r, "MD5", "T14.05b: diff -d compares all five digests")

    # The diff JSON contract is canonical too.
    r = h.cmd("--no-color --fingerprint-format hex-colon diff {a} {b} -d -o json",
              a=cert, b=_ts(h, "verify-chain", "root.pem"))
    t.assert_json(r, "T14.05c: diff -o json is valid")
    try:
        fields = {f["name"]: f for f in json.loads(r.stdout)["fields"]}
        if ":" in fields.get("SHA-256", {}).get("left", ""):
            t.FAIL("T14.05d: diff JSON stays canonical", "found a separator")
        else:
            t.PASS("T14.05d: diff JSON stays canonical")
    except (ValueError, KeyError, TypeError) as e:
        t.FAIL("T14.05d: diff JSON stays canonical", str(e))

    r = h.cmd("--no-color --fingerprint-format hex-colon store --trust-file {p} -d", p=bundle)
    t.assert_contains(r, "SHA-256:", "T14.05e: store -d shows fingerprints")

    # --- T14.06: config file drives the default, flag overrides it ---
    print("-- T14.06: config precedence")

    cfg = h.tmp("fp-config.yaml")
    cfg.write_text(
        'kind: certdiag-config\nversion: "1"\n'
        'defaults:\n  output:\n    fingerprint_format: "base64"\n'
        'passwords: {}\n'
    )

    r = h.cmd("--no-color -c {cfg} -d {p}", cfg=cfg, p=cert)
    t.assert_contains_regex(r, r"SHA-256:\s+[A-Za-z0-9+/]{43}=",
                            "T14.06a: config sets the default format")

    r = h.cmd("--no-color -c {cfg} --fingerprint-format hex-colon -d {p}", cfg=cfg, p=cert)
    t.assert_contains_regex(r, r"SHA-256:\s+([0-9a-f]{2}:){31}",
                            "T14.06b: the flag overrides the config")

    bad_cfg = h.tmp("fp-config-bad.yaml")
    bad_cfg.write_text(
        'kind: certdiag-config\nversion: "1"\n'
        'defaults:\n  output:\n    fingerprint_format: "nonsense"\n'
        'passwords: {}\n'
    )
    r = h.cmd("--no-color -c {cfg} -d {p}", cfg=bad_cfg, p=cert)
    t.expect_ok(r, "T14.06c: an invalid config value degrades instead of failing")
    t.assert_contains_regex(r, r"SHA-256:\s+[0-9a-f]{64}\b",
                            "T14.06d: invalid config falls back to hex")


if __name__ == "__main__":
    h = Harness()
    h.setup()
    t = Tracker()
    try:
        run(h, t)
    finally:
        h.cleanup()
