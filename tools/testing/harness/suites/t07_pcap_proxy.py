import subprocess
import time

from ..lib.harness import Harness
from ..lib.assertions import Tracker


def _require_pcap(h, t, filename, label):
    path = h.fixture(filename)
    if not path.is_file():
        t.SKIP(f"{label} (fixture not found: {filename})")
        return None
    return path


def run(h, t):
    print("\n=== T07: PCAP and Proxy Edge Cases ===")

    # --- T07.01: Sessions on basic capture ---
    pcap = _require_pcap(h, t, "tls-handshake.pcap", "T07.01")
    if pcap:
        r = h.cmd("--no-color pcap sessions {pcap}", pcap=pcap)
        t.expect_ok(r, "T07.01a: pcap sessions exits 0")
        t.assert_contains_regex(r, "TLS", "T07.01b: pcap sessions output mentions TLS")

    # --- T07.02: Sessions on empty capture ---
    pcap = _require_pcap(h, t, "empty.pcap", "T07.02")
    if pcap:
        r = h.cmd("--no-color pcap sessions {pcap}", pcap=pcap)
        t.expect_ok(r, "T07.02: pcap sessions on empty capture exits 0")

    # --- T07.03: Sessions on non-TLS capture ---
    pcap = _require_pcap(h, t, "no-tls.pcap", "T07.03")
    if pcap:
        r = h.cmd("--no-color pcap sessions {pcap}", pcap=pcap)
        t.expect_ok(r, "T07.03a: pcap sessions on non-TLS capture exits 0")
        t.assert_contains(r, "TLS sessions: 0", "T07.03b: reports 0 TLS sessions")

    # --- T07.04: Sessions with --filter ---
    pcap = _require_pcap(h, t, "multi-session.pcap", "T07.04")
    if pcap:
        r = h.cmd('--no-color pcap sessions -f "example" {pcap}', pcap=pcap)
        t.expect_ok(r, "T07.04a: pcap sessions --filter exits 0")
        t.assert_contains_regex(r, "matched filter", "T07.04b: output mentions filter matching")

    # --- T07.05: Sessions with --aggressive ---
    pcap = _require_pcap(h, t, "tls-handshake.pcap", "T07.05")
    if pcap:
        r = h.cmd("--no-color pcap sessions -a {pcap}", pcap=pcap)
        t.expect_ok(r, "T07.05: pcap sessions --aggressive exits 0")

    # --- T07.06: Sessions with --detail ---
    pcap = _require_pcap(h, t, "tls-handshake.pcap", "T07.06")
    if pcap:
        r = h.cmd("--no-color pcap sessions -d {pcap}", pcap=pcap)
        t.expect_ok(r, "T07.06: pcap sessions --detail exits 0")

    # --- T07.07: Sessions on gzipped pcap ---
    pcap = _require_pcap(h, t, "gzipped.pcap.gz", "T07.07")
    if pcap:
        r = h.cmd("--no-color pcap sessions {pcap}", pcap=pcap)
        t.expect_ok(r, "T07.07: pcap sessions on gzipped pcap exits 0")

    # --- T07.08: Sessions on invalid file ---
    garbage = h.fixture("garbage.bin")
    r = h.cmd("--no-color pcap sessions {f}", f=garbage)
    t.expect_fail(r, "T07.08a: pcap sessions on garbage.bin fails")

    r = h.cmd("--no-color pcap sessions {f}", f="/nonexistent/file.pcap")
    t.expect_fail(r, "T07.08b: pcap sessions on nonexistent file fails")
    t.assert_contains_regex(r, "error", "T07.08c: nonexistent file produces error message", stream="stderr")

    # --- T07.09: Check on capture with certs ---
    pcap = _require_pcap(h, t, "tls-handshake.pcap", "T07.09")
    if pcap:
        r = h.cmd("--no-color pcap check {pcap}", pcap=pcap)
        t.expect_ok(r, "T07.09: pcap check exits 0")

    # --- T07.10: Check on empty capture ---
    pcap = _require_pcap(h, t, "empty.pcap", "T07.10")
    if pcap:
        r = h.cmd("--no-color pcap check {pcap}", pcap=pcap)
        t.expect_ok(r, "T07.10: pcap check on empty capture exits 0")

    # --- T07.11: Check with filter + aggressive ---
    pcap = _require_pcap(h, t, "multi-session.pcap", "T07.11")
    if pcap:
        r = h.cmd('--no-color pcap check -f "example" -a {pcap}', pcap=pcap)
        t.expect_ok(r, "T07.11: pcap check --filter --aggressive exits 0")

    # --- T07.12: Extract certs from capture ---
    pcap = _require_pcap(h, t, "tls-handshake.pcap", "T07.12")
    if pcap:
        extract_dir = h.tmp("pcap-extract")
        r = h.cmd("--no-color pcap extract --target-dir {d} {pcap}", d=extract_dir, pcap=pcap)
        t.expect_ok(r, "T07.12a: pcap extract exits 0")
        if extract_dir.is_dir():
            t.PASS("T07.12b: pcap extract created target directory")
        else:
            t.FAIL("T07.12b: pcap extract created target directory", "directory not found")

    # --- T07.13: Extract from empty capture ---
    pcap = _require_pcap(h, t, "empty.pcap", "T07.13")
    if pcap:
        extract_dir = h.tmp("pcap-empty")
        r = h.cmd("--no-color pcap extract --target-dir {d} {pcap}", d=extract_dir, pcap=pcap)
        t.expect_ok(r, "T07.13: pcap extract on empty capture exits 0")

    # --- T07.14: Extract with filter ---
    pcap = _require_pcap(h, t, "multi-session.pcap", "T07.14")
    if pcap:
        extract_dir = h.tmp("pcap-filtered")
        r = h.cmd('--no-color pcap extract -f "example" --target-dir {d} {pcap}',
                  d=extract_dir, pcap=pcap)
        t.expect_ok(r, "T07.14: pcap extract --filter exits 0")

    # --- T07.15: Proxy with invalid listen address ---
    r = h.cmd('--no-color proxy -l "" -t "192.0.2.1:443"')
    t.expect_fail(r, "T07.15a: proxy with empty listen address fails")

    r = h.cmd('--no-color proxy -l "notanaddress" -t "192.0.2.1:443"')
    t.expect_fail(r, "T07.15b: proxy with invalid listen address fails")
    t.assert_contains_regex(r, "error", "T07.15c: invalid listen address produces error message", stream="stderr")

    # --- T07.16: Proxy missing required flags ---
    r = h.cmd('--no-color proxy -l "127.0.0.1:9999"')
    t.expect_fail(r, "T07.16a: proxy without -t fails")
    t.assert_contains_regex(r, "required", "T07.16a: missing -t mentions required", stream="stderr")

    r = h.cmd('--no-color proxy -t "192.0.2.1:443"')
    t.expect_fail(r, "T07.16b: proxy without -l fails")
    t.assert_contains_regex(r, "required", "T07.16b: missing -l mentions required", stream="stderr")

    r = h.cmd("--no-color proxy")
    t.expect_fail(r, "T07.16c: proxy with neither flag fails")
    t.assert_contains_regex(r, "required", "T07.16c: missing both flags mentions required", stream="stderr")

    # --- T07.17: Proxy with --dump-dir (requires live connection) ---
    t.SKIP("T07.17: requires live network connection and traffic routing")

    # --- T07.18: Proxy with --ndjson and --multiyaml (requires live connection) ---
    t.SKIP("T07.18: requires live network connection and traffic routing")

    # --- T07.19: Proxy with filter and aggressive (requires live connection) ---
    t.SKIP("T07.19: requires live network connection and traffic routing")

    # --- T07.20: Proxy port already in use ---
    if not h.has_tool("nc"):
        t.SKIP("T07.20: nc not available")
    else:
        proxy_port = 19876
        nc_proc = None
        try:
            nc_proc = subprocess.Popen(
                ["nc", "-l", "127.0.0.1", str(proxy_port)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            time.sleep(1)

            r = h.cmd(
                "--no-color proxy -l {addr} -t {target}",
                addr=f"127.0.0.1:{proxy_port}",
                target="192.0.2.1:443",
            )
            t.expect_fail(r, "T07.20a: proxy on occupied port fails")
            t.assert_contains_regex(r, "error", "T07.20b: port-in-use produces error message", stream="stderr")
        finally:
            if nc_proc:
                try:
                    nc_proc.kill()
                    nc_proc.wait(timeout=5)
                except Exception:
                    pass


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
        t.close()

    t.summary("T07")
