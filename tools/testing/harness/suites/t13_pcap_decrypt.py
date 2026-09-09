import subprocess
import tempfile
from pathlib import Path

# Committed fixtures: a real captured TLS 1.3 handshake + the matching NSS keylog
# (generated hermetically from a Go crypto/tls loopback handshake). The cert CN
# is pcap-fixture.local.
TESTDATA = Path(__file__).resolve().parents[2] / "testdata"
PCAP = str(TESTDATA / "tls13_keylog.pcap")
KEYLOG = str(TESTDATA / "tls13.keylog")


def run(h, t):
    print("\n=== T13: pcap TLS 1.3 decryption (SSLKEYLOGFILE) ===")

    if not Path(PCAP).exists() or not Path(KEYLOG).exists():
        t.SKIP("T13: TLS 1.3 fixtures missing")
        return

    # --- T13.01: TLS 1.3 detected; without keys, cert is honestly reported encrypted ---
    r = h.cmd("--no-color pcap sessions -d {pcap}", pcap=PCAP)
    t.expect_ok(r, "T13.01a: pcap sessions exits 0")
    t.assert_contains(r, "TLS 1.3", "T13.01b: session detected as TLS 1.3")
    t.assert_contains(r, "encrypted in TLS 1.3", "T13.01c: honest encrypted-cert message")
    if "pcap-fixture.local" in r.stdout:
        t.FAIL("T13.01d: cert must not leak without keylog", "subject present without --keylog")
    else:
        t.PASS("T13.01d: no cert extracted without keylog")

    # --- T13.02: with the keylog, the server cert is decrypted and shown ---
    r = h.cmd("--no-color pcap sessions -d {pcap} --keylog {kl}", pcap=PCAP, kl=KEYLOG)
    t.expect_ok(r, "T13.02a: pcap sessions --keylog exits 0")
    t.assert_contains(r, "decrypted via keylog", "T13.02b: marks certs as decrypted")
    t.assert_contains(r, "pcap-fixture.local", "T13.02c: recovered cert subject shown")

    # --- T13.03: extract writes the decrypted chain to a PEM file ---
    outdir = tempfile.mkdtemp(prefix="t13_extract_")
    r = h.cmd("--no-color pcap extract {pcap} --keylog {kl} --target-dir {out}",
              pcap=PCAP, kl=KEYLOG, out=outdir)
    t.expect_ok(r, "T13.03a: pcap extract --keylog exits 0")
    pems = list(Path(outdir).glob("*.pem"))
    if pems and "BEGIN CERTIFICATE" in pems[0].read_text():
        t.PASS("T13.03b: extracted PEM contains the decrypted certificate")
    else:
        t.FAIL("T13.03b: extracted PEM", f"no certificate PEM in {outdir}")

    # --- T13.04: SSLKEYLOGFILE env var is honored (same as --keylog) ---
    r = h.cmd("--no-color pcap sessions -d {pcap}", pcap=PCAP, env_extra={"SSLKEYLOGFILE": KEYLOG})
    t.assert_contains(r, "pcap-fixture.local", "T13.04: SSLKEYLOGFILE env decrypts")

    # --- T13.05: a bad/empty keylog degrades gracefully (still exits 0, no cert) ---
    empty = str(h.tmp("empty.keylog"))
    Path(empty).write_text("# no secrets here\n")
    r = h.cmd("--no-color pcap sessions -d {pcap} --keylog {kl}", pcap=PCAP, kl=empty)
    t.expect_ok(r, "T13.05a: empty keylog exits 0")
    t.assert_contains(r, "encrypted in TLS 1.3", "T13.05b: empty keylog -> still reported encrypted")

    # --- T13.06: read a capture stream from stdin ("pcap -"), binary via subprocess ---
    pcap_bytes = Path(PCAP).read_bytes()
    p = subprocess.run(
        [str(h.binary_path), "--no-color", "pcap", "sessions", "-d", "-", "--keylog", KEYLOG],
        input=pcap_bytes, capture_output=True, timeout=30)
    out = p.stdout.decode("utf-8", "replace")
    if p.returncode == 0 and "TLS 1.3" in out:
        t.PASS("T13.06a: pcap - reads capture from stdin")
    else:
        t.FAIL("T13.06a: stdin capture", f"exit={p.returncode}")
    if "pcap-fixture.local" in out:
        t.PASS("T13.06b: stdin + keylog decrypts the cert")
    else:
        t.FAIL("T13.06b: stdin decrypt", "cert not recovered from piped capture")

    # --- T13.07: decrypted application-data summary (D2) ---
    r = h.cmd("--no-color pcap sessions -d {pcap} --keylog {kl}", pcap=PCAP, kl=KEYLOG)
    t.assert_contains(r, "Decrypted application data", "T13.07a: app-data section shown")
    t.assert_contains(r, "GET /secret HTTP/1.1", "T13.07b: client HTTP request summarized")
    t.assert_contains(r, "HTTP/1.1 200 OK", "T13.07c: server HTTP response summarized")

    # --- T13.08: JA3/JA4 client fingerprints (D3), no keylog needed ---
    r = h.cmd("--no-color pcap sessions -d {pcap}", pcap=PCAP)
    t.assert_contains(r, "JA3:", "T13.08a: JA3 fingerprint shown")
    t.assert_contains_regex(r, r"JA3:\s+[0-9a-f]{32}", "T13.08b: JA3 is a 32-hex md5")
    t.assert_contains_regex(r, r"JA4:\s+t\d\d[di]\d{4}", "T13.08c: JA4 has the expected structure")
