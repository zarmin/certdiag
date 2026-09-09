import json
import time
from pathlib import Path

from ..lib.harness import Harness, _find_repo_root
from ..lib.assertions import Tracker


REPO_ROOT = _find_repo_root()
STRESS_CERTS = REPO_ROOT / "tools" / "testing" / "stresstest" / "certs"


def run(h, t, certs_dir=None, timeout=35):
    certs_dir = Path(certs_dir) if certs_dir else STRESS_CERTS
    passwords = certs_dir / "passwords.txt"

    if not certs_dir.is_dir():
        t.SKIP("stress test: certs directory not found")
        return
    if not passwords.is_file():
        t.SKIP("stress test: passwords.txt not found")
        return

    file_count = sum(1 for p in certs_dir.rglob("*") if p.is_file() and p.name != "passwords.txt")
    pw_count = len(passwords.read_text().strip().splitlines())

    print("=== Stress Test ===")
    print(f"  Files:      {file_count}")
    print(f"  Passwords:  {pw_count}")
    print()

    # --- Run 1: JSON scan ---
    print("--- Run 1: JSON output ---")
    t1_start = time.time()
    r = h.cmd("{d} -P {pw} -o json --no-color",
              d=certs_dir, pw=passwords, timeout=timeout)
    t1_ms = int((time.time() - t1_start) * 1000)

    t.assert_not_timed_out(r, "stress JSON scan completes within timeout")

    if r.ok or r.stdout.strip():
        try:
            data = json.loads(r.stdout)
            files = data.get("files", [])
            total = len(files)
            protected = sum(1 for f in files if f.get("password", {}).get("protected", False))
            unlocked = sum(1 for f in files if f.get("password", {}).get("unlocked", False))
            locked = protected - unlocked
            items = sum(len(f.get("items") or []) for f in files)

            print(f"  Files scanned:  {total}")
            print(f"  Protected:      {protected}")
            print(f"  Unlocked:       {unlocked}")
            print(f"  Still locked:   {locked}")
            print(f"  Total items:    {items}")
            print(f"  Time:           {t1_ms} ms")
            print()

            t.assert_greater_than(total, 0, "stress: scanned files > 0")
            t.assert_greater_than(protected, 0, "stress: found protected files")
            t.assert_equal(locked, 0, "stress: all protected files unlocked")
            t.assert_greater_than(items, 0, "stress: found items in files")

        except (json.JSONDecodeError, TypeError) as e:
            t.FAIL("stress JSON parse", str(e))
    else:
        t.FAIL("stress JSON scan", f"exit {r.returncode}")

    # --- Run 2: text scan ---
    print("--- Run 2: text output ---")
    t2_start = time.time()
    r2 = h.cmd("{d} -P {pw} --no-color",
               d=certs_dir, pw=passwords, timeout=timeout)
    t2_ms = int((time.time() - t2_start) * 1000)

    t.assert_not_timed_out(r2, "stress text scan completes within timeout")
    print(f"  Time:           {t2_ms} ms")
    print()

    # --- Summary ---
    print("=== Summary ===")
    print(f"  JSON scan:  {t1_ms} ms")
    print(f"  Text scan:  {t2_ms} ms")


if __name__ == "__main__":
    h = Harness()
    t = Tracker()
    h.setup()
    try:
        run(h, t)
    finally:
        h.cleanup()
    ok = t.summary("Stress")
    raise SystemExit(0 if ok else 1)
