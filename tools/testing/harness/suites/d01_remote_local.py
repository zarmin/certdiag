"""D01: Remote commands against the local test infrastructure.

Runs in the docker phase, where tools/testinfra is up. Everything here needs a
real TLS peer; it used to point at example.com from the cli phase, which made
the suite flaky (network stalls surfaced as exit 3) and slow (`remote probe`
against a public host takes 25-35s versus 0.15s locally).

Ports come from tools/testinfra/docker-compose.yml and match the constants in
internal/certops/dockertest_helpers_test.go.
"""

import json

from ..lib.harness import Harness
from ..lib.assertions import Tracker


MODERN = "localhost:14430"
EXPIRED = "localhost:14433"
SELFSIGNED = "localhost:14434"
WRONGHOST = "localhost:14435"
INCOMPLETE = "localhost:14436"
MTLS = "localhost:14437"
REDIRECT = "localhost:14438"


def _certs_dir(h):
    # tools/testing/edgecases/fixtures -> tools/testinfra/certs
    return h.fixtures_dir.parents[2] / "testinfra" / "certs"


def run(h, t):
    print("\n=== D01: Remote Commands vs Local TLS Infrastructure ===")

    certs = _certs_dir(h)
    client_crt = certs / "client.crt"
    client_key = certs / "client.key"

    # --- D01.00: remote without subcommand defaults to fetch ---
    r_fetch = h.cmd("--no-color remote fetch {tgt} -o json", tgt=MODERN)
    r_default = h.cmd("--no-color remote {tgt} -o json", tgt=MODERN)
    t.assert_equal(r_fetch.returncode, r_default.returncode,
                   "D01.00a: remote default same exit as remote fetch")
    if r_fetch.stdout and r_default.stdout:
        t.PASS("D01.00b: both produce output")
    else:
        t.FAIL("D01.00b: both produce output", "one or both outputs empty")

    # --- D01.01: target formats ---
    r = h.cmd("--no-color remote fetch {tgt}", tgt=MODERN)
    t.expect_ok(r, "D01.01a: host:port exits 0")
    t.assert_contains(r, "Subject:", "D01.01a: output shows a certificate subject")

    r = h.cmd("--no-color remote fetch tls://{tgt}", tgt=MODERN)
    t.expect_ok(r, "D01.01b: tls:// URL exits 0")

    r = h.cmd("--no-color remote fetch https://{tgt}", tgt=MODERN)
    t.expect_ok(r, "D01.01c: https:// URL exits 0")

    r = h.cmd("--no-color remote fetch 127.0.0.1:14430")
    t.expect_ok(r, "D01.01d: IPv4 literal exits 0")

    # --- D01.02: --hostname SNI override ---
    # The wronghost server presents a cert for a different name; overriding the
    # SNI/verification hostname is the documented way to inspect it.
    r = h.cmd("--no-color remote fetch --hostname localhost {tgt}", tgt=WRONGHOST)
    t.expect_ok(r, "D01.02a: --hostname override exits 0")
    t.assert_contains(r, "Subject:", "D01.02b: --hostname override returns a cert")

    # --- D01.03: --tls-version ---
    r = h.cmd("--no-color remote fetch --tls-version tls1.2 {tgt}", tgt=MODERN)
    t.expect_ok(r, "D01.03a: --tls-version tls1.2 exits 0")

    r = h.cmd("--no-color remote fetch --tls-version tls1.3 {tgt}", tgt=MODERN)
    t.expect_ok(r, "D01.03b: --tls-version tls1.3 exits 0")

    # --- D01.05: generous --timeout to a working host ---
    r = h.cmd("--no-color remote fetch --timeout 30s {tgt}", tgt=MODERN)
    t.expect_ok(r, "D01.05: --timeout 30s exits 0")

    # --- D01.06: -4 / -6 ---
    r = h.cmd("--no-color remote fetch -4 127.0.0.1:14430")
    t.expect_ok(r, "D01.06a: -4 (IPv4) exits 0")

    r6 = h.cmd("--no-color remote fetch -6 --timeout 5s {tgt}", tgt=MODERN)
    if r6.ok:
        t.PASS("D01.06b: -6 (IPv6) exits 0")
    else:
        t.SKIP("D01.06b: -6 (IPv6) -- no IPv6 loopback connectivity")

    # --- D01.07: --single-ip ---
    r = h.cmd("--no-color remote fetch --single-ip {tgt}", tgt=MODERN)
    t.expect_ok(r, "D01.07: --single-ip exits 0")

    # --- D01.08: save modes ---
    for mode, label in [("--save-chain", "a"), ("--save-leaf", "b"), ("--save-all", "c")]:
        outdir = h.tmp(f"d01-save-{label}")
        outdir.mkdir(parents=True, exist_ok=True)
        r = h.cmd("--no-color remote fetch {mode} -O {outdir} {tgt} --overwrite",
                  mode=mode, outdir=outdir, tgt=MODERN)
        t.expect_ok(r, f"D01.08{label}: {mode} exits 0")
        files = [f for f in outdir.rglob("*") if f.is_file()]
        if files:
            t.PASS(f"D01.08{label}: {mode} created {len(files)} file(s)")
        else:
            t.FAIL(f"D01.08{label}: {mode}", "no files created")

    # --- D01.09: --save-to specific path ---
    specific = h.tmp("d01-specific-chain.pem")
    r = h.cmd("--no-color remote fetch --save-chain --save-to {path} {tgt} --overwrite",
              path=specific, tgt=MODERN)
    t.expect_ok(r, "D01.09a: --save-to exits 0")
    t.assert_file_not_empty(specific, "D01.09b: saved chain file is non-empty")

    # --- D01.10: --save-format ---
    sf_dir = h.tmp("d01-sf")
    for fmt in ["pem", "der", "p7b"]:
        r = h.cmd("--no-color remote fetch --save-chain --save-format {fmt} -O {outdir} {tgt} --overwrite",
                  fmt=fmt, outdir=sf_dir, tgt=MODERN)
        t.expect_ok(r, f"D01.10: --save-format {fmt} exits 0")

    multi_dir = h.tmp("d01-save-multi")
    r = h.cmd("--no-color remote fetch --save-chain --save-leaf --save-all -O {outdir} {tgt} --overwrite",
              outdir=multi_dir, tgt=MODERN)
    if r.returncode <= 2:
        t.PASS(f"D01.10d: multiple save modes handled (exit {r.returncode})")
    else:
        t.FAIL("D01.10d: multiple save modes", f"unexpected exit {r.returncode}")

    p12_dir = h.tmp("d01-save-p12")
    r = h.cmd("--no-color remote fetch --save-chain --save-format p12 -O {outdir} {tgt} --overwrite",
              outdir=p12_dir, tgt=MODERN)
    if r.returncode <= 2:
        t.PASS(f"D01.10e: save as p12 without password handled (exit {r.returncode})")
    else:
        t.FAIL("D01.10e: save as p12 without password", f"unexpected exit {r.returncode}")

    # --- D01.11: -d details ---
    r = h.cmd("--no-color remote fetch -d {tgt}", tgt=MODERN)
    t.expect_ok(r, "D01.11a: fetch -d exits 0")
    t.assert_contains(r, "SHA-256", "D01.11b: details shows SHA-256 fingerprint")

    # --- D01.12: output formats ---
    r = h.cmd("--no-color remote fetch -o json {tgt}", tgt=MODERN)
    t.expect_ok(r, "D01.12a: -o json exits 0")
    t.assert_json(r, "D01.12b: JSON output is valid")

    r = h.cmd("--no-color remote fetch -o yaml {tgt}", tgt=MODERN)
    t.expect_ok(r, "D01.12c: -o yaml exits 0")
    if r.stdout:
        t.PASS("D01.12d: YAML output is non-empty")
    else:
        t.FAIL("D01.12d: YAML output is non-empty", "output was empty")

    # --- D01.13: client certificate (mTLS) ---
    # Without a client cert the mTLS server rejects the request at HTTP level;
    # with one it returns 200. That difference is the assertion.
    r = h.cmd("--no-color remote http --headers-only {tgt}", tgt=MTLS)
    t.assert_contains(r, "400", "D01.13a: mTLS without client cert is rejected")

    r = h.cmd("--no-color remote http --headers-only --client-cert {crt} --client-key {key} {tgt}",
              crt=client_crt, key=client_key, tgt=MTLS)
    t.expect_ok(r, "D01.13b: --client-cert/--client-key exits 0")
    t.assert_contains(r, "200 OK", "D01.13c: mTLS with client cert is accepted")

    # --- D01.14: client cert as PKCS#12 and JKS ---
    # Built here with certdiag itself rather than shipped as a fixture, so the
    # bundle always matches the CA the infra is running with.
    p12 = h.tmp("d01-client.p12")
    r = h.cmd("bundle {crt} {key} -f pkcs12 --output-password clientpw -o {out} --no-confirm",
              crt=client_crt, key=client_key, out=p12)
    if r.ok:
        t.PASS("D01.14a: built client p12 bundle")
        r = h.cmd("--no-color remote http --headers-only --client-p12 {p12} --client-password clientpw {tgt}",
                  p12=p12, tgt=MTLS)
        t.expect_ok(r, "D01.14b: --client-p12 exits 0")
        t.assert_contains(r, "200 OK", "D01.14c: --client-p12 accepted by mTLS server")
    else:
        t.FAIL("D01.14a: built client p12 bundle", r.stderr.strip()[:200])

    jks = h.tmp("d01-client.jks")
    r = h.cmd("bundle {crt} {key} -f jks --output-password clientpw -o {out} --no-confirm",
              crt=client_crt, key=client_key, out=jks)
    if r.ok:
        t.PASS("D01.14d: built client jks bundle")
        r = h.cmd("--no-color remote http --headers-only --client-jks {jks} --client-password clientpw {tgt}",
                  jks=jks, tgt=MTLS)
        t.expect_ok(r, "D01.14e: --client-jks exits 0")
        t.assert_contains(r, "200 OK", "D01.14f: --client-jks accepted by mTLS server")
    else:
        t.FAIL("D01.14d: built client jks bundle", r.stderr.strip()[:200])

    # --- D01.16: --parallel with multiple targets ---
    r = h.cmd("--no-color remote fetch --parallel 5 {a} {b} {c}",
              a=MODERN, b=SELFSIGNED, c=EXPIRED)
    if r.returncode <= 2:
        t.PASS(f"D01.16a: --parallel multi-target handled (exit {r.returncode})")
    else:
        t.FAIL("D01.16a: --parallel multi-target", f"unexpected exit {r.returncode}")
    t.assert_contains(r, "14430", "D01.16b: --parallel includes the modern target")
    t.assert_contains(r, "14434", "D01.16c: --parallel includes the selfsigned target")

    # --- D01.17: check --severity / --category ---
    for args, label in [
        ("--severity critical", "D01.17a: check --severity critical"),
        ("--category expiry", "D01.17b: check --category expiry"),
        ("--category expiry,chain --severity warning", "D01.17c: check combo"),
        ("--strict", "D01.18: check --strict"),
        ("--aia", "D01.19: check --aia"),
    ]:
        r = h.cmd("--no-color remote check {args} {tgt}", args=args, tgt=MODERN)
        if r.returncode <= 2:
            t.PASS(f"{label} exits {r.returncode}")
        else:
            t.FAIL(label, f"unexpected exit {r.returncode}")

    # --- D01.19b: custom expiry thresholds ---
    r = h.cmd("--no-color remote check --expiry-warn 9999 --expiry-critical 5000 {tgt}", tgt=MODERN)
    t.assert_contains(r, "expir", "D01.19b-a: high thresholds trigger expiry findings")

    r = h.cmd("--no-color remote check --expiry-warn 1 --expiry-critical 0 {tgt}", tgt=MODERN)
    t.assert_not_contains(r, "expiring soon", "D01.19b-b: low thresholds suppress expiry warnings")

    # --- D01.20: check output formats ---
    r = h.cmd("--no-color remote check -o json {tgt}", tgt=MODERN)
    t.assert_json(r, "D01.20a: check -o json is valid JSON")

    r = h.cmd("--no-color remote check -o yaml {tgt}", tgt=MODERN)
    if r.stdout:
        t.PASS("D01.20b: check -o yaml is non-empty")
    else:
        t.FAIL("D01.20b: check -o yaml is non-empty", "output was empty")

    # --- D01.21: probe ---
    r = h.cmd("--no-color remote probe {tgt}", tgt=MODERN)
    t.expect_ok(r, "D01.21a: probe exits 0")
    t.assert_contains(r, "TLS", "D01.21b: probe output contains 'TLS'")
    t.assert_contains_regex(r, r"(?i)cipher", "D01.21c: probe output contains 'cipher'")

    r = h.cmd("--no-color remote probe --tls-version tls1.2 {tgt}", tgt=MODERN)
    t.expect_ok(r, "D01.22: probe --tls-version tls1.2 exits 0")

    # --- D01.24: http --header ---
    r = h.cmd('--no-color remote http --header "User-Agent: certdiag-test" {tgt}', tgt=MODERN)
    t.expect_ok(r, "D01.24a: http single --header exits 0")

    r = h.cmd('--no-color remote http --header "User-Agent: certdiag-test" '
              '--header "Accept: text/html" --header "X-Custom: value" {tgt}', tgt=MODERN)
    t.expect_ok(r, "D01.24b: http multiple --header exits 0")

    # --- D01.25: http --headers-only ---
    r = h.cmd("--no-color remote http --headers-only {tgt}", tgt=MODERN)
    t.expect_ok(r, "D01.25a: http --headers-only exits 0")
    t.assert_contains(r, "HTTP/", "D01.25b: --headers-only output contains 'HTTP/'")

    # --- D01.26: http --follow-redirects ---
    r = h.cmd("--no-color remote http --headers-only {tgt}", tgt=REDIRECT)
    t.assert_contains(r, "301", "D01.26a: redirect server returns a 301 unfollowed")

    r = h.cmd("--no-color remote http --follow-redirects {tgt}", tgt=REDIRECT)
    if r.returncode <= 3:
        t.PASS(f"D01.26b: http --follow-redirects handled (exit {r.returncode})")
    else:
        t.FAIL("D01.26b: http --follow-redirects", f"unexpected exit {r.returncode}")

    r = h.cmd("--no-color remote http --follow-redirects --max-redirects 3 {tgt}", tgt=REDIRECT)
    if r.returncode <= 3:
        t.PASS(f"D01.26c: http --max-redirects 3 handled (exit {r.returncode})")
    else:
        t.FAIL("D01.26c: http --max-redirects 3", f"unexpected exit {r.returncode}")

    r = h.cmd("--no-color remote http --follow-redirects --max-redirects 0 {tgt}", tgt=REDIRECT)
    if r.returncode <= 3:
        t.PASS(f"D01.26d: http --max-redirects 0 handled (exit {r.returncode})")
    else:
        t.FAIL("D01.26d: http --max-redirects 0", f"unexpected exit {r.returncode}")

    # --- D01.29: multiple targets in fetch -o json ---
    r = h.cmd("--no-color remote fetch {a} {b} -o json", a=MODERN, b=SELFSIGNED)
    if r.returncode <= 2:
        t.PASS(f"D01.29a: multi-target -o json handled (exit {r.returncode})")
    else:
        t.FAIL("D01.29a: multi-target -o json", f"unexpected exit {r.returncode}")
    t.assert_json(r, "D01.29b: multi-target JSON is valid")
    try:
        rows = json.loads(r.stdout)
        n = len(rows) if isinstance(rows, list) else len(rows.get("targets", []))
        if n >= 2:
            t.PASS(f"D01.29c: JSON covers both targets ({n})")
        else:
            t.FAIL("D01.29c: JSON covers both targets", f"got {n}")
    except (ValueError, TypeError, AttributeError) as e:
        t.FAIL("D01.29c: JSON covers both targets", str(e))

    # --- D01.31: --expiry-warn with details ---
    r = h.cmd("--no-color remote fetch --expiry-warn 9999 -d {tgt}", tgt=MODERN)
    t.assert_contains(r, "expir", "D01.31: --expiry-warn 9999 -d shows expiry warning")

    # --- D01.32: problem servers are diagnosed, not crashed on ---
    for tgt, name in [
        (EXPIRED, "expired"),
        (SELFSIGNED, "self-signed"),
        (WRONGHOST, "wrong hostname"),
        (INCOMPLETE, "incomplete chain"),
    ]:
        r = h.cmd("--no-color remote check {tgt}", tgt=tgt)
        if r.returncode <= 2:
            t.PASS(f"D01.32: check against {name} server exits {r.returncode}")
        else:
            t.FAIL(f"D01.32: check against {name} server", f"unexpected exit {r.returncode}")


if __name__ == "__main__":
    h = Harness()
    h.setup()
    t = Tracker()
    try:
        run(h, t)
    finally:
        h.cleanup()
