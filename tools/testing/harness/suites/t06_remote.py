"""T06: Remote command edge cases that need no live TLS server.

This suite is deliberately network-free: every assertion here is either a flag
/ usage error resolved before a connection is attempted, or a connection to an
address guaranteed to fail (a closed local port, or RFC 5737 TEST-NET-1).

Anything that needs a real TLS peer lives in `d01_remote_local.py`, which runs
in the docker phase against the local test infrastructure. Pointing tests at
example.com made them fail whenever the network hiccuped and made the suite the
slowest in the run.
"""

from ..lib.harness import Harness
from ..lib.assertions import Tracker


# Guaranteed connection refused, instantly, with no traffic leaving the host.
REFUSED = "localhost:1"

# RFC 5737 TEST-NET-1: reserved for documentation, never routed, so a connection
# attempt reliably times out rather than reaching anything.
UNREACHABLE = "192.0.2.1:443"


def run(h, t):
    print("\n=== T06: Remote Command Edge Cases (no live host) ===")

    # --- T06.00b: pcap without subcommand defaults to sessions ---
    r = h.cmd("--no-color pcap")
    if r.returncode <= 2:
        t.PASS(f"T06.00b: pcap without subcommand/file shows help or error (exit {r.returncode})")
    else:
        t.FAIL("T06.00b: pcap without subcommand", f"unexpected exit {r.returncode}")

    # --- T06.03: --tls-version validation (rejected before dialling) ---
    r = h.cmd("--no-color remote fetch --tls-version tls1.4 {tgt}", tgt=REFUSED)
    t.expect_exit(1, r, "T06.03c: --tls-version tls1.4 exits 1 (usage error, not 2=CRITICAL)")

    r = h.cmd("--no-color remote fetch --tls-version ssl3 {tgt}", tgt=REFUSED)
    t.expect_exit(1, r, "T06.03d: --tls-version ssl3 exits 1 (usage error, not 2=CRITICAL)")

    # --- T06.04: --starttls validation ---
    r = h.cmd("--no-color remote fetch --starttls invalid-proto {tgt}", tgt=REFUSED)
    t.expect_exit(1, r, "T06.04a: --starttls invalid-proto exits 1 (usage error, not 2=CRITICAL)")

    # Valid protocols against a closed port must fail with a connection error,
    # never "unknown protocol".
    for proto in ["smtp", "imap", "pop3", "ftp", "ldap", "mysql", "postgres"]:
        r = h.cmd("--no-color remote fetch --starttls {proto} --timeout 3s {tgt}",
                  proto=proto, tgt=REFUSED)
        t.assert_not_contains(r, "unknown protocol",
                              f"T06.04b: --starttls {proto} no 'unknown protocol' error")

    # --- T06.05: --timeout ---
    r = h.cmd("--no-color remote fetch --timeout 1s {tgt}", tgt=REFUSED, timeout=15)
    t.assert_not_timed_out(r, "T06.05a: --timeout 1s completed (did not hang)")

    r = h.cmd("--no-color remote fetch --timeout not-a-duration {tgt}", tgt=REFUSED)
    t.expect_exit(1, r, "T06.05c: --timeout invalid format exits 1 (usage error, not 2=CRITICAL)")

    # --- T06.15: unreachable host ---
    r = h.cmd("--no-color remote fetch --timeout 3s {tgt}", tgt=UNREACHABLE, timeout=20)
    t.expect_exit(3, r, "T06.15: unreachable host exits 3")

    # --- T06.23: probe unreachable host ---
    r = h.cmd("--no-color remote probe --timeout 3s {tgt}", tgt=UNREACHABLE, timeout=60)
    t.expect_exit(3, r, "T06.23: probe unreachable host exits 3")

    # --- T06.27: http --proxy error paths ---
    # The proxy itself is unreachable, so these never reach the target.
    r = h.cmd("--no-color remote http --proxy socks5://127.0.0.1:19999 --timeout 3s {tgt}",
              tgt=REFUSED, timeout=15)
    t.expect_exit(3, r, "T06.27a: socks5 proxy unreachable exits 3")

    r = h.cmd("--no-color remote http --proxy http://127.0.0.1:19999 --timeout 3s {tgt}",
              tgt=REFUSED, timeout=15)
    t.expect_exit(3, r, "T06.27b: http proxy unreachable exits 3")

    r = h.cmd("--no-color remote http --proxy not-a-url --timeout 3s {tgt}", tgt=REFUSED)
    t.expect_exit(1, r, "T06.27c: invalid proxy URL exits 1 (usage error, not 2=CRITICAL)")

    r = h.cmd("--no-color remote http --proxy socks5://127.0.0.1 --timeout 3s {tgt}",
              tgt=REFUSED, timeout=15)
    if r.returncode in (2, 3):
        t.PASS(f"T06.27d: proxy missing port handled (exit {r.returncode})")
    else:
        t.FAIL("T06.27d: proxy missing port", f"expected exit 2 or 3, got {r.returncode}")

    # --- T06.32: target parsing rejects malformed input before dialling ---
    for bad, label in [
        ("://nohost", "scheme with no host"),
        ("http://[unclosed", "malformed IPv6 literal"),
    ]:
        r = h.cmd("--no-color remote fetch --timeout 3s {tgt}", tgt=bad, timeout=15)
        if r.returncode != 0:
            t.PASS(f"T06.32: {label} rejected (exit {r.returncode})")
        else:
            t.FAIL(f"T06.32: {label} rejected", "expected non-zero exit")


if __name__ == "__main__":
    h = Harness()
    h.setup()
    t = Tracker()
    try:
        run(h, t)
    finally:
        h.cleanup()
