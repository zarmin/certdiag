import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from .lib import gotest_formatter, formatting, report as report_lib
from .lib.assertions import Tracker
from .lib.harness import Harness


REPO_ROOT = Path(__file__).resolve().parents[3]
APP_DIR = REPO_ROOT / "certdiag_app"
TESTING_DIR = REPO_ROOT / "tools" / "testing"
EDGE_DIR = TESTING_DIR / "edgecases"
STRESS_DIR = TESTING_DIR / "stresstest"
LOG_DIR = TESTING_DIR / "logs"
REPORT_DIR = TESTING_DIR / "reports"
TESTINFRA_DIR = REPO_ROOT / "tools" / "testinfra"

STRESS_TIMEOUT = 35

LOGGING_ENABLED = os.environ.get("CERTDIAG_TEST_LOGGING") == "1"


def require_tool(name, label):
    if not shutil.which(name):
        print(f"missing: {name} ({label})", file=sys.stderr)
        sys.exit(1)


def prune_logs(prefix, keep=5):
    logs = sorted(LOG_DIR.glob(f"{prefix}_*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in logs[keep:]:
        old.unlink(missing_ok=True)


def run_go_tests(log_file, extra_flags=None, race=False):
    cmd = ["go", "test", "-json"]
    if race:
        cmd.append("-race")
    if extra_flags:
        cmd.extend(extra_flags)
    cmd.append("./...")

    env = os.environ.copy()
    if race:
        env["CGO_ENABLED"] = "1"

    flags_str = " ".join(extra_flags or [])

    if LOGGING_ENABLED and log_file:
        # utf-8 explicitly: go test output contains non-ASCII (test names, box
        # drawing), which crashes on Windows where open() defaults to cp1252.
        log_fh = open(log_file, "w", encoding="utf-8", errors="replace")
    else:
        log_fh = None

    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace",
        cwd=APP_DIR, env=env,
    )

    class TeeStream:
        def __init__(self, stream, log_fh):
            self.stream = stream
            self.log_fh = log_fh

        def __iter__(self):
            return self

        def __next__(self):
            line = self.stream.readline()
            if not line:
                raise StopIteration
            if self.log_fh:
                self.log_fh.write(line)
                self.log_fh.flush()
            return line

    tee = TeeStream(proc.stdout, log_fh)
    stats = gotest_formatter.format_stream(tee, flags_str)
    proc.wait()

    if log_fh:
        log_fh.close()

    return stats


def run_phase_unit(args):
    formatting.section("Unit Tests")
    require_tool("go", "Go compiler")
    log = LOG_DIR / f"unit_{args.ts}.log" if LOGGING_ENABLED else None
    stats = run_go_tests(log)
    print()
    return stats


def run_phase_extended(args):
    formatting.section("Extended Unit Tests")
    require_tool("go", "Go compiler")
    log = LOG_DIR / f"extended_{args.ts}.log" if LOGGING_ENABLED else None
    stats = run_go_tests(log, extra_flags=["-count=1", "-tags", "fulltest"])
    print()
    return stats


def select_suites(suites, patterns):
    if not patterns:
        return suites
    wanted = [p.strip().lower() for p in patterns.split(",") if p.strip()]
    return [s for s in suites
            if any(w in s.__name__.rsplit(".", 1)[-1].lower() for w in wanted)]


def run_suite(suite, h, t):
    """Run one CLI suite, turning an unexpected crash into a recorded failure so
    one bad suite can't abort the whole phase (and swallow the final summary)."""
    name = suite.__name__.rsplit(".", 1)[-1]
    t.suite = name
    try:
        suite.run(h, t)
    except Exception as e:
        import traceback
        t.FAIL(f"{name} (suite crashed)", str(e))
        print(f"  SUITE CRASH in {name}: {e}")
        traceback.print_exc()
    finally:
        t.suite = None


def run_phase_cli(args):
    formatting.section("CLI Tests")
    require_tool("openssl", "OpenSSL CLI")

    fixture_dir = EDGE_DIR / "fixtures"
    h = Harness(fixtures_dir=fixture_dir)
    h.setup(required_tools=["openssl"])

    # Self-heal: the edge-case fixtures are gitignored (generated artifacts), so
    # a fresh checkout / CI runner has none. Regenerate when missing or stale.
    from .lib.fixtures import verify_fixture_hashes, regenerate
    fixture_errors = verify_fixture_hashes(fixture_dir, fixture_dir / "fixtures.sha256")
    if fixture_errors:
        print(f"  Fixtures missing or stale ({len(fixture_errors)} issue(s)) -- regenerating...")
        regenerate()

    t = Tracker(manifest_path=args.manifest)

    # -- smoke tests --
    from .suites import smoke_certchecks, smoke_changeactions, smoke_extended
    smoke_suites = select_suites(
        [smoke_certchecks, smoke_changeactions, smoke_extended], args.suite)
    if smoke_suites:
        print("\n--- Smoke Tests ---")
        for suite in smoke_suites:
            run_suite(suite, h, t)

    # -- edge case tests --
    from .suites import (t01_scanning, t02_formats, t03_creation, t04_conversion,
                         t05_check_diff, t06_remote, t07_pcap_proxy, t08_passwords,
                         t09_config_global, t10_negative, t11_revocation,
                         t12_truststore, t13_pcap_decrypt, t14_fingerprints,
                         t15_trust, t16_bundles, t17_storediff, t18_write_paths,
                         t19_remote_local)
    edge_suites = select_suites(
        [t01_scanning, t02_formats, t03_creation, t04_conversion,
         t05_check_diff, t06_remote, t07_pcap_proxy, t08_passwords,
         t09_config_global, t10_negative, t11_revocation,
         t12_truststore, t13_pcap_decrypt, t14_fingerprints,
         t15_trust, t16_bundles, t17_storediff, t18_write_paths,
         t19_remote_local], args.suite)
    if edge_suites:
        print("\n--- Edge Case Tests ---")
        for suite in edge_suites:
            run_suite(suite, h, t)

    h.cleanup()
    t.close()

    print()
    print(f"CLI: {t.passed} passed, {t.failed} failed, {t.skipped} skipped")
    print()
    return t


def run_phase_stress(args):
    formatting.section("Stress Test")
    certs_dir = STRESS_DIR / "certs"

    h = Harness()
    h.setup()

    t = Tracker(manifest_path=args.manifest)

    from .suites import stress
    t_start = time.time()
    t.suite = "stress"
    stress.run(h, t, certs_dir=certs_dir, timeout=STRESS_TIMEOUT)
    t.suite = None
    elapsed = time.time() - t_start

    h.cleanup()
    t.close()

    if t.failed == 0:
        formatting.phase_pass("stress test", f"({elapsed:.0f}s, limit {STRESS_TIMEOUT}s)")
    else:
        formatting.phase_fail("stress test", f"({elapsed:.0f}s)")
    print()
    return t


def infra_running():
    result = subprocess.run(
        ["docker", "compose", "ps", "-q", "--status=running"],
        capture_output=True, text=True, cwd=TESTINFRA_DIR,
    )
    return bool(result.stdout.strip())


def run_phase_docker(args):
    formatting.section("Docker Remote Tests")
    require_tool("docker", "Docker engine")
    require_tool("go", "Go compiler")

    log = LOG_DIR / f"docker_{args.ts}.log" if LOGGING_ENABLED else None

    # Only tear down infra we started; leave a pre-existing testinfra-up alone.
    preexisting = infra_running()
    if preexisting:
        print("  Using already-running test infrastructure...")
    else:
        print("  Starting test infrastructure...")
        subprocess.run(
            ["docker", "compose", "up", "-d", "--build"],
            capture_output=True, cwd=TESTINFRA_DIR,
        )
        print("  Waiting for services...")
        time.sleep(10)

    docker_cli = None
    try:
        stats = run_go_tests(log, extra_flags=["-count=1", "-tags", "dockertest"])
        docker_cli = run_docker_cli_suites(args)
    finally:
        # Capture container logs before teardown so infra-side failures (e.g. a
        # service that didn't enable TLS) are diagnosable from the uploaded
        # artifact -- the go test output alone can't show why.
        if LOGGING_ENABLED:
            clog = LOG_DIR / f"docker_compose_{args.ts}.log"
            proc = subprocess.run(
                ["docker", "compose", "logs", "--no-color", "-t"],
                capture_output=True, text=True, cwd=TESTINFRA_DIR,
            )
            clog.write_text(proc.stdout + proc.stderr, encoding="utf-8", errors="replace")
            print(f"  Captured container logs -> {clog.name}")
        if preexisting:
            print("  Leaving pre-existing test infrastructure up.")
        else:
            print("  Stopping test infrastructure...")
            subprocess.run(
                ["docker", "compose", "down"],
                capture_output=True, cwd=TESTINFRA_DIR,
            )

    print()
    if docker_cli is not None:
        return [("docker", stats), ("docker-cli", docker_cli)]
    return stats


def run_docker_cli_suites(args):
    """CLI suites that need a live TLS peer. They run here, against the local
    testinfra, rather than in the cli phase against a public host."""
    from .suites import d01_remote_local

    fixture_dir = EDGE_DIR / "fixtures"
    h = Harness(fixtures_dir=fixture_dir)
    h.setup()

    suites = select_suites([d01_remote_local], args.suite)
    if not suites:
        h.cleanup()
        return None

    print("\n--- Docker CLI Suites ---")
    t = Tracker()
    for suite in suites:
        run_suite(suite, h, t)

    h.cleanup()
    t.close()
    print()
    print(f"Docker CLI: {t.passed} passed, {t.failed} failed, {t.skipped} skipped")
    return t


PHASES = {
    "unit": run_phase_unit,
    "extended": run_phase_extended,
    "cli": run_phase_cli,
    "stress": run_phase_stress,
    "docker": run_phase_docker,
}


def main():
    parser = argparse.ArgumentParser(description="certdiag test runner")
    parser.add_argument("--phase", choices=list(PHASES.keys()),
                        help="run a single phase")
    parser.add_argument("--skip-docker", action="store_true",
                        help="run all phases except docker (for hosts without Linux Docker)")
    parser.add_argument("--suite", type=str, default=None,
                        help="comma-separated suite name filter for the cli phase (e.g. t06, t05,t06)")
    parser.add_argument("--race", action="store_true",
                        help="enable Go race detector")
    parser.add_argument("--manifest", type=str, default=None,
                        help="write test manifest TSV to this path")
    parser.add_argument("--regenerate-fixtures", action="store_true",
                        help="regenerate edge case fixtures")
    parser.add_argument("--no-report", action="store_true",
                        help="skip writing the run report to tools/testing/reports/")
    parser.add_argument("--report-dir", type=str, default=None,
                        help="directory for run reports (default tools/testing/reports)")
    args, _ = parser.parse_known_args()

    ts = time.strftime("%Y%m%d_%H%M%S")
    args.ts = ts

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    for prefix in ["unit", "extended", "cli", "stress", "docker"]:
        prune_logs(prefix)

    report_dir = Path(args.report_dir) if args.report_dir else REPORT_DIR
    report = None if args.no_report else report_lib.Report(args)

    if args.regenerate_fixtures:
        from .lib.fixtures import regenerate
        regenerate()
        return

    phases = [args.phase] if args.phase else list(PHASES.keys())
    if args.skip_docker:
        phases = [p for p in phases if p != "docker"]

    has_failure = False
    results = {}

    for phase in phases:
        result = PHASES[phase](args)

        # A phase may report several results (docker runs Go tests and CLI
        # suites), each surfaced separately in the summary and the report.
        parts = result if isinstance(result, list) else [(phase, result)]
        for label, res in parts:
            results[label] = res
            if report is not None:
                report.add_phase(label, res)

            if hasattr(res, "failed"):
                if res.failed > 0:
                    has_failure = True
            elif hasattr(res, "returncode"):
                if res.returncode != 0:
                    has_failure = True

    # summary
    print("=" * 43)
    print("  FULL TEST SUMMARY")
    print("=" * 43)

    total_pass = 0
    total_fail = 0

    for phase, result in results.items():
        if hasattr(result, "passed") and hasattr(result, "failed"):
            p = result.passed
            f = result.failed
            total_pass += p
            total_fail += f
            label = phase.capitalize() + " tests:"
            print(f"  {label:<20s} {p:4d} passed, {f:2d} failed")

    print()
    if has_failure:
        red = formatting._c("\033[31m")
        reset = formatting._c("\033[0m")
        print(f"  {red}RESULT: FAILED ({total_fail} failures){reset}")
    else:
        green = formatting._c("\033[32m")
        reset = formatting._c("\033[0m")
        print(f"  {green}RESULT: ALL PASSED{reset}")
    print()

    if report is not None:
        try:
            txt_path, json_path = report.write(report_dir, ts)
            report_lib.prune(report_dir)
            print(f"  Report: {txt_path}")
            print(f"          {json_path}")
            print()
        except OSError as e:
            print(f"  WARNING: could not write report: {e}", file=sys.stderr)

    sys.exit(1 if has_failure else 0)
