import os

from ..lib.harness import Harness
from ..lib.assertions import Tracker


NC = "--no-confirm"


def run(h, t):
    print("\n=== T18: Write paths (generated keys, config errors) ===\n")

    # --- T18.01: create-cert --with-key without --key-output writes <cert>.key ---
    print("--- T18.01: generated key lands next to the certificate ---")
    crt = h.tmp("w1", "site.crt")
    key = h.tmp("w1", "site.key")
    r = h.cmd("--no-color create-cert --with-key --subject CN=w1.test -o {crt} {nc}", crt=crt, nc=NC)
    t.expect_ok(r, "T18.01a: create-cert --with-key exits 0")
    t.assert_file_not_empty(key, "T18.01b: site.key written next to site.crt")
    t.assert_contains(r, "site.key", "T18.01c: summary names the key file", stream="stderr")

    # --- T18.02: an existing derived key path is never overwritten ---
    print("--- T18.02: derived key path refuses to overwrite ---")
    crt2 = h.tmp("w2", "again.crt")
    key2 = h.tmp("w2", "again.key")
    key2.write_text("keep me\n")
    r = h.cmd("--no-color create-cert --with-key --subject CN=w2.test -o {crt} {nc}", crt=crt2, nc=NC)
    t.expect_exit(1, r, "T18.02a: refuses when again.key exists")
    t.assert_contains(r, "--key-output", "T18.02b: error points at --key-output", stream="stderr")
    if key2.read_text() == "keep me\n":
        t.PASS("T18.02c: existing key file untouched")
    else:
        t.FAIL("T18.02c: existing key file was overwritten")
    if not os.path.exists(crt2):
        t.PASS("T18.02d: no certificate written when the key cannot be")
    else:
        t.FAIL("T18.02d: certificate written although the key was refused")

    # --- T18.03: stdout carries both PEM blocks ---
    print("--- T18.03: stdout output carries cert and key ---")
    r = h.cmd("--no-color create-cert --with-key --subject CN=w3.test")
    t.expect_ok(r, "T18.03a: create-cert to stdout exits 0")
    t.assert_contains(r, "BEGIN CERTIFICATE", "T18.03b: stdout has the certificate")
    t.assert_contains(r, "PRIVATE KEY", "T18.03c: stdout has the private key")

    # --- T18.04: create-csr --with-key ---
    print("--- T18.04: create-csr --with-key ---")
    csr = h.tmp("w4", "req.csr")
    r = h.cmd("--no-color create-csr --with-key --subject CN=w4.test -o {csr} {nc}", csr=csr, nc=NC)
    t.expect_ok(r, "T18.04a: create-csr --with-key exits 0")
    t.assert_file_not_empty(h.tmp("w4", "req.key"), "T18.04b: req.key written next to req.csr")

    # --- T18.05: renew --new-key ---
    print("--- T18.05: renew --new-key ---")
    ocrt = h.tmp("w5", "orig.crt")
    okey = h.tmp("w5", "orig.key")
    r = h.cmd("--no-color create-cert --with-key --subject CN=w5.test -o {crt} --key-output {key} {nc}",
              crt=ocrt, key=okey, nc=NC)
    t.expect_ok(r, "T18.05a: setup certificate")
    rcrt = h.tmp("w5", "renewed.crt")
    r = h.cmd("--no-color renew {ocrt} -k {okey} --new-key -o {rcrt} {nc}", ocrt=ocrt, okey=okey, rcrt=rcrt, nc=NC)
    t.expect_ok(r, "T18.05b: renew --new-key exits 0")
    t.assert_file_not_empty(h.tmp("w5", "renewed.key"), "T18.05c: renewed.key written next to renewed.crt")

    # --- T18.06: templates --from reads encrypted containers ---
    print("--- T18.06: templates --from an encrypted PKCS#12 ---")
    p12 = h.tmp("w6", "tpl.p12")
    r = h.cmd("--no-color convert {crt} -o {p12} --output-password tplpass {nc}", crt=ocrt, p12=p12, nc=NC)
    t.expect_ok(r, "T18.06a: convert to PKCS#12")
    r = h.cmd("--no-color templates cert --from {p12} -p tplpass", p12=p12)
    t.expect_ok(r, "T18.06b: templates --from p12 with -p exits 0")
    t.assert_contains(r, "w5.test", "T18.06c: template carries the subject from the p12")
    r = h.cmd("--no-color templates cert --from {p12}", p12=p12)
    t.expect_fail(r, "T18.06d: templates --from p12 without password fails")

    # --- T18.07: a config that cannot be loaded is fatal for every command ---
    print("--- T18.07: config load errors are uniform ---")
    broken = h.tmp("w7", "broken.yaml")
    broken.write_text(": : : [\n")
    cases = [
        ("convert {crt} -o {out}", 1),
        ("bundle {crt} -o {out}", 1),
        ("verify {crt}", 1),
        ("store list", 1),
        ("templates cert", 1),
        ("aia cache list", 1),
        ("diff {crt} {crt}", 2),
    ]
    for i, (argline, want) in enumerate(cases):
        out = h.tmp("w7", f"out{i}.pem")
        r = h.cmd("--no-color -c {cfg} " + argline, cfg=broken, crt=ocrt, out=out)
        t.expect_exit(want, r, f"T18.07{chr(97 + i)}: '{argline.split()[0]}' exits {want} on a broken config")
        t.assert_contains(r, "Error loading config", f"T18.07{chr(97 + i)}: '{argline.split()[0]}' reports the config error", stream="stderr")

    # --- T18.08: a directory scan names what it could not read ---
    print("--- T18.08: skipped files are reported, not hidden ---")
    sd = h.tmp("w8", "scan")
    sd.mkdir(parents=True, exist_ok=True)
    (sd / "garbage.crt").write_text("not a certificate\n")
    (sd / "README.txt").write_text("never a candidate\n")
    r = h.cmd("--no-color create-cert --with-key --subject CN=w8.test -o {crt} {nc}", crt=sd / "good.crt", nc=NC)
    t.expect_ok(r, "T18.08a: setup certificate")
    r = h.cmd("--no-color {d}", d=sd)
    t.expect_ok(r, "T18.08b: a skipped file does not change the exit code")
    t.assert_contains(r, "1 file(s) skipped", "T18.08c: the scan says how many files it skipped", stream="stderr")
    r = h.cmd("--no-color -d {d}", d=sd)
    t.assert_contains(r, "garbage.crt", "T18.08d: -d lists the skipped file", stream="stderr")
    t.assert_not_contains(r, "README.txt", "T18.08e: a non-candidate is not reported", stream="stderr")
    rj = h.cmd("--no-color -o json {d}", d=sd)
    t.assert_contains(rj, '"skipped"', "T18.08f: JSON carries the skipped list")
