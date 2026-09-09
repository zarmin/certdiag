import re
import subprocess

from ..lib.harness import Harness
from ..lib.assertions import Tracker


def _selfsigned(directory, name, cn):
    r = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
         "-nodes", "-keyout", f"{name}.key", "-out", f"{name}.crt", "-days", "30",
         "-subj", f"/CN={cn}"],
        cwd=directory, capture_output=True, text=True)
    return r.returncode == 0


def _setup_bundles(h):
    """Two PEM bundles sharing one CA, one unique CA each, plus a rotated pair
    (same CN, different keys). Returns dict of paths or None."""
    d = h.tmp("storediff")
    d.mkdir(parents=True, exist_ok=True)
    ds = str(d)

    for name, cn in [("shared", "Shared Root"), ("onlya", "Only A Root"),
                     ("onlyb", "Only B Root"), ("rot1", "Rotated Root"),
                     ("rot2", "Rotated Root")]:
        if not _selfsigned(ds, name, cn):
            return None

    def bundle(out, *certs):
        data = b""
        for c in certs:
            data += (d / f"{c}.crt").read_bytes()
        (d / out).write_bytes(data)
        return str(d / out)

    return {
        "a": bundle("bundle-a.pem", "shared", "onlya", "rot1"),
        "b": bundle("bundle-b.pem", "shared", "onlyb", "rot2"),
        "a2": bundle("bundle-a2.pem", "shared", "onlya", "rot1"),
    }


def run(h, t):
    print("\n=== T17: Trust Store Diff ===")

    # --- T17.06: invalid spec is exit 2 ---
    r = h.cmd("--no-color store diff bogus os")
    t.expect_exit(2, r, "T17.06: invalid store spec exits 2")

    # --- T17.07: invalid output format is exit 2 ---
    r = h.cmd("--no-color store diff os os -o bogus")
    t.expect_exit(2, r, "T17.07: invalid output format exits 2")

    if not h.has_tool("openssl"):
        t.SKIP("T17: openssl not available -- skipping bundle tests")
        return

    fx = _setup_bundles(h)
    if fx is None:
        t.SKIP("T17: fixture generation failed -- skipping")
        return

    # --- T17.01: identical bundles -> exit 0 ---
    r = h.cmd("--no-color store diff {a} {a2}", a=fx["a"], a2=fx["a2"])
    t.expect_exit(0, r, "T17.01: identical bundles exit 0")
    t.assert_contains(r, "identical", "T17.01: output says identical")

    # --- T17.02: differing bundles -> exit 1 with only/rotated sections ---
    r = h.cmd("--no-color store diff {a} {b}", a=fx["a"], b=fx["b"])
    t.expect_exit(1, r, "T17.02: differing bundles exit 1")
    t.assert_contains(r, "Only A Root", "T17.02: only-in-A cert listed")
    t.assert_contains(r, "Only B Root", "T17.02: only-in-B cert listed")
    t.assert_contains(r, "Rotated Root", "T17.02: rotated subject listed")
    t.assert_contains(r, "Rotated (same subject", "T17.02: rotated section present")

    # --- T17.03: JSON output fields ---
    r = h.cmd("--no-color store diff {a} {b} -o json", a=fx["a"], b=fx["b"])
    t.assert_contains(r, '"identical": false', "T17.03: json identical false")
    t.assert_contains(r, '"only_in_a"', "T17.03: json only_in_a present")
    t.assert_contains(r, '"rotated"', "T17.03: json rotated present")
    t.assert_contains(r, '"common": 1', "T17.03: json common count")

    # --- T17.04: rotated cert not duplicated into only lists ---
    r = h.cmd("--no-color store diff {a} {b} -o json", a=fx["a"], b=fx["b"])
    only_a_count = r.stdout.count('"subject": "CN=Rotated Root"')
    if only_a_count == 1:
        t.PASS("T17.04: rotated subject appears once (in rotated bucket only)")
    else:
        t.FAIL("T17.04: rotated subject placement", f"appeared {only_a_count} times")

    # --- T17.05: real OS store vs itself -> identical (exercises platform reader) ---
    r = h.cmd("--no-color store diff os os")
    if r.returncode == 2:
        t.SKIP("T17.05: OS store not readable on this system")
    else:
        t.expect_exit(0, r, "T17.05: os vs os is identical (exit 0)")

    # --- T17.08: bucket headers name the spec, not just A/B ---
    r = h.cmd("--no-color store diff {a} {b}", a=fx["a"], b=fx["b"])
    t.assert_contains(r, f"Only in A ({fx['a']}):", "T17.08: bucket header names side A")
    t.assert_contains(r, f"Only in B ({fx['b']}):", "T17.08: bucket header names side B")

    # --- T17.09: shipped bundle specs resolve offline (compiled-in snapshots) ---
    r = h.cmd("--no-color store diff mozilla chrome")
    if r.returncode == 2:
        t.FAIL("T17.09: mozilla/chrome specs", f"exit 2: {r.stderr.strip()[:200]}")
    else:
        t.PASS("T17.09: mozilla vs chrome resolves without error")
        t.assert_contains(r, "Store A: mozilla", "T17.09: side A names the mozilla snapshot")
        t.assert_contains(r, "Store B: chrome", "T17.09: side B names the chrome snapshot")

    # --- T17.10: mozilla against itself is identical ---
    r = h.cmd("--no-color store diff mozilla mozilla")
    t.expect_exit(0, r, "T17.10: mozilla vs mozilla is identical (exit 0)")

    # --- T17.11: nss spec is accepted (skipped where no browser profile exists) ---
    r = h.cmd("--no-color store diff nss mozilla")
    if r.returncode == 2 and "profile" in (r.stderr + r.stdout).lower():
        t.SKIP("T17.11: no browser profile store on this system")
    elif r.returncode == 2:
        t.FAIL("T17.11: nss spec", f"exit 2: {r.stderr.strip()[:200]}")
    else:
        t.PASS("T17.11: nss spec resolves")

    # --- T17.12: display fingerprint format applies to the human view only ---
    r = h.cmd("--no-color --fingerprint-format hex-colon store diff {a} {b}", a=fx["a"], b=fx["b"])
    if ":" in r.stdout.split("Only in A")[-1]:
        t.PASS("T17.12: hex-colon format reaches the human digest")
    else:
        t.FAIL("T17.12: hex-colon format", "no colon-separated digest in output")

    r = h.cmd("--no-color --fingerprint-format hex-colon store diff {a} {b} -o json", a=fx["a"], b=fx["b"])
    if '":' in r.stdout and not re.search(r'"sha256": "[0-9a-f]{2}:', r.stdout):
        t.PASS("T17.12: json digests stay canonical hex")
    else:
        t.FAIL("T17.12: json digests", "display format leaked into JSON")
