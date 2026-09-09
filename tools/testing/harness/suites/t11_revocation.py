import subprocess

from ..lib.harness import Harness
from ..lib.assertions import Tracker


def _openssl(args, cwd=None):
    return subprocess.run(["openssl"] + args, cwd=cwd, capture_output=True, text=True)


def _setup_crl_fixtures(h):
    """Build a CA, a revoked leaf (serial listed in a CRL), and a good leaf,
    entirely offline with openssl. Returns a dict of paths, or None on failure."""
    d = h.tmp("revocation")
    d.mkdir(parents=True, exist_ok=True)
    ds = str(d)

    def run(*args):
        r = _openssl(list(args), cwd=ds)
        return r.returncode == 0

    ok = True
    ok &= run("genrsa", "-out", "ca.key", "2048")
    ok &= run("req", "-x509", "-new", "-key", "ca.key", "-out", "ca.crt", "-days", "3650",
              "-subj", "/CN=RevTestCA", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    if not ok:
        return None

    # Minimal CA database + config for `openssl ca`.
    (d / "index.txt").write_text("")
    (d / "serial").write_text("1000\n")
    (d / "crlnumber").write_text("1000\n")
    (d / "openssl.cnf").write_text(f"""
[ca]
default_ca = CA_default
[CA_default]
dir = {ds}
database = $dir/index.txt
new_certs_dir = $dir
certificate = $dir/ca.crt
private_key = $dir/ca.key
serial = $dir/serial
crlnumber = $dir/crlnumber
default_md = sha256
default_crl_days = 30
default_days = 3650
policy = policy_any
[policy_any]
commonName = supplied
""".lstrip())

    cnf = str(d / "openssl.cnf")
    ok &= run("genrsa", "-out", "leaf.key", "2048")
    ok &= run("req", "-new", "-key", "leaf.key", "-out", "revoked.csr", "-subj", "/CN=revoked.test")
    ok &= run("ca", "-config", cnf, "-batch", "-in", "revoked.csr", "-out", "revoked.crt")
    ok &= run("ca", "-config", cnf, "-revoke", "revoked.crt", "-crl_reason", "keyCompromise")
    ok &= run("ca", "-config", cnf, "-gencrl", "-out", "test.crl")
    ok &= run("req", "-new", "-key", "leaf.key", "-out", "good.csr", "-subj", "/CN=good.test")
    ok &= run("ca", "-config", cnf, "-batch", "-in", "good.csr", "-out", "good.crt")
    if not ok:
        return None

    return {
        "ca": str(d / "ca.crt"),
        "revoked": str(d / "revoked.crt"),
        "good": str(d / "good.crt"),
        "crl": str(d / "test.crl"),
    }


def run(h, t):
    print("\n=== T11: OCSP/CRL Revocation ===")

    # --- T11.08: list-checks advertises the revocation checks (no fixtures) ---
    r = h.cmd("--no-color check --list-checks")
    for cid in ("revocation_revoked", "revocation_undetermined", "revocation_unverified"):
        t.assert_contains(r, cid, f"T11.08: --list-checks shows {cid}")

    # --- T11.07: invalid revocation method is a usage error ---
    r = h.cmd("--no-color check --revocation-method bogus {f}/", f=h.fixture())
    t.expect_exit(1, r, "T11.07: --revocation-method bogus exits 1 (usage error)")

    if not h.has_tool("openssl"):
        t.SKIP("T11: openssl not available -- skipping CRL fixture tests")
        return

    fx = _setup_crl_fixtures(h)
    if fx is None:
        t.SKIP("T11: openssl CRL fixture generation failed -- skipping")
        return

    # --- T11.01: revoked cert against local CRL is critical (exit 2) ---
    r = h.cmd("--no-color check {rev} {ca} --crl-file {crl}", rev=fx["revoked"], ca=fx["ca"], crl=fx["crl"])
    t.expect_exit(2, r, "T11.01: revoked cert via --crl-file exits 2")
    t.assert_contains(r, "REVOKED", "T11.01: output reports REVOKED")
    t.assert_contains(r, "keyCompromise", "T11.01: output reports reason keyCompromise")

    # --- T11.03: JSON revocations array reports status/method ---
    r = h.cmd("--no-color check {rev} {ca} --crl-file {crl} -o json", rev=fx["revoked"], ca=fx["ca"], crl=fx["crl"])
    t.assert_contains(r, '"status": "revoked"', "T11.03: json revocation status revoked")
    t.assert_contains(r, '"method": "crl_file"', "T11.03: json revocation method crl_file")
    t.assert_contains(r, '"verified": true', "T11.03: json revocation verified true (issuer present)")

    # --- T11.02: good cert against the same CRL is not revoked ---
    r = h.cmd("--no-color check {good} {ca} --crl-file {crl} -o json", good=fx["good"], ca=fx["ca"], crl=fx["crl"])
    t.assert_contains(r, '"status": "good"', "T11.02: good cert reports status good")
    if "revocation_revoked" in r.stdout:
        t.FAIL("T11.02: good cert must not be flagged revoked", r.stdout[:200])
    else:
        t.PASS("T11.02: good cert not flagged revoked")

    # --- T11.04: no revocation flags => no revocations array (opt-in respected) ---
    r = h.cmd("--no-color check {rev} -o json", rev=fx["revoked"])
    if '"revocations"' in r.stdout:
        t.FAIL("T11.04: revocation must be opt-in", "revocations array present without --revocation/--crl-file")
    else:
        t.PASS("T11.04: no revocations array without opt-in")

    # --- T11.05/06: undetermined (no reachable OCSP/CRL) warns; --require escalates ---
    r = h.cmd("--no-color check {rev} {ca} --revocation --revocation-method ocsp", rev=fx["revoked"], ca=fx["ca"])
    t.assert_contains(r, "Revocation status", "T11.05: undetermined revocation reported")
    r2 = h.cmd("--no-color check {rev} {ca} --revocation --revocation-method ocsp --revocation-require",
               rev=fx["revoked"], ca=fx["ca"])
    t.expect_exit(2, r2, "T11.06: --revocation-require escalates undetermined to critical (exit 2)")
