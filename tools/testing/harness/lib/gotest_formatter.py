import json
import os
import sys
import time
from dataclasses import dataclass, field


MODULE_PREFIX = "github.com/zarmin/certdiag/certdiag_app/"


@dataclass
class GoTestStats:
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    elapsed: float = 0.0
    # Per-package rollup and failure detail, for lib/report.py.
    packages: list = field(default_factory=list)
    failures: list = field(default_factory=list)


def format_stream(input_stream, extra_flags=""):
    use_color = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    GREEN = "\033[32m" if use_color else ""
    RED = "\033[31m" if use_color else ""
    DIM = "\033[2m" if use_color else ""
    RESET = "\033[0m" if use_color else ""

    def short_pkg(pkg):
        if pkg.startswith(MODULE_PREFIX):
            return pkg.replace(MODULE_PREFIX, "")
        if pkg == MODULE_PREFIX.rstrip("/"):
            return "(module root)"
        return pkg

    pkg_tests = {}
    pkg_passed = {}
    pkg_failed = {}
    pkg_skipped = {}
    pkg_elapsed = {}
    pkg_output = {}

    test_output = {}
    failed_tests = []

    total_start = time.time()

    for raw_line in input_stream:
        raw_line = raw_line.rstrip("\n")
        if not raw_line:
            continue
        try:
            ev = json.loads(raw_line)
        except json.JSONDecodeError:
            print(raw_line, flush=True)
            continue

        action = ev.get("Action", "")
        pkg = ev.get("Package", "")
        test = ev.get("Test")
        output = ev.get("Output", "")
        elapsed = ev.get("Elapsed")

        if not pkg:
            continue

        if pkg not in pkg_tests:
            pkg_tests[pkg] = set()
            pkg_passed[pkg] = 0
            pkg_failed[pkg] = 0
            pkg_skipped[pkg] = 0
            pkg_output[pkg] = []

        if action == "output":
            if test:
                key = (pkg, test)
                test_output.setdefault(key, []).append(output)
            else:
                pkg_output[pkg].append(output)

        elif action == "run":
            if test:
                pkg_tests[pkg].add(test)

        elif action == "pass":
            if test:
                pkg_passed[pkg] += 1
                test_output.pop((pkg, test), None)
            else:
                name = short_pkg(pkg)
                n = len(pkg_tests[pkg])
                t = f"{elapsed:.1f}s" if elapsed else ""
                info = f"({n} tests, {t})" if n else "(no tests)"
                print(f"  {GREEN}PASS{RESET}  {name:<35s} {DIM}{info}{RESET}", flush=True)
                if elapsed:
                    pkg_elapsed[pkg] = elapsed

        elif action == "fail":
            if test:
                pkg_failed[pkg] += 1
                failed_tests.append((pkg, test))
            else:
                if pkg_failed[pkg] == 0:
                    # The package failed without a failing test: a build
                    # error, a panic, or an os.Exit from inside a test. Count
                    # it, or the run reports green with a dead package.
                    pkg_failed[pkg] += 1
                    failed_tests.append((pkg, "<package failed without a failing test: build error, panic or os.Exit>"))
                name = short_pkg(pkg)
                n = len(pkg_tests[pkg])
                t = f"{elapsed:.1f}s" if elapsed else ""
                info = f"({n} tests, {t})" if n else f"({t})" if t else ""
                print(f"  {RED}FAIL{RESET}  {name:<35s} {info}", flush=True)
                if elapsed:
                    pkg_elapsed[pkg] = elapsed

        elif action == "skip":
            if test:
                pkg_skipped[pkg] += 1
            else:
                name = short_pkg(pkg)
                print(f"  SKIP  {name:<35s} {DIM}(no test files){RESET}", flush=True)

    total_elapsed = time.time() - total_start
    total_pass = sum(pkg_passed.values())
    total_fail = sum(pkg_failed.values())
    total_skip = sum(pkg_skipped.values())
    n_pkgs = len(pkg_tests)
    n_pkg_fail = sum(1 for p in pkg_failed if pkg_failed[p] > 0)
    n_pkg_pass = sum(1 for p in pkg_passed if pkg_passed[p] > 0 and pkg_failed.get(p, 0) == 0)
    n_pkg_skip = sum(1 for p in pkg_tests if not pkg_tests[p] and pkg_failed.get(p, 0) == 0 and pkg_passed.get(p, 0) == 0)

    print(flush=True)
    print(f"Go: {n_pkgs} packages, {n_pkg_pass} passed, {n_pkg_fail} failed, {n_pkg_skip} skipped ({total_elapsed:.1f}s)", flush=True)
    print(f"    {total_pass} tests passed, {total_fail} failed, {total_skip} skipped", flush=True)

    if failed_tests:
        print(flush=True)
        print(f"  {RED}Failed tests:{RESET}", flush=True)

        fail_by_pkg = {}
        for pkg, test in failed_tests:
            fail_by_pkg.setdefault(pkg, []).append(test)

        for pkg, test in failed_tests:
            name = short_pkg(pkg)
            print(f"  --- {test} ({name}) ---", flush=True)
            lines = test_output.get((pkg, test), [])
            for line in lines:
                stripped = line.rstrip("\n")
                if stripped:
                    print(f"    {stripped}", flush=True)
            if not lines and pkg_output.get(pkg):
                for line in pkg_output[pkg]:
                    stripped = line.rstrip("\n")
                    if stripped:
                        print(f"    {stripped}", flush=True)
            print(flush=True)

        print(f"  {RED}Rerun failed:{RESET}", flush=True)
        for pkg, tests in fail_by_pkg.items():
            pattern = "|".join(tests)
            name = short_pkg(pkg)
            flags = f" {extra_flags}" if extra_flags else ""
            print(f"    cd certdiag_app && go test -v -run '{pattern}'{flags} ./{name}/...", flush=True)

    packages = [
        {
            "package": short_pkg(pkg),
            "passed": pkg_passed.get(pkg, 0),
            "failed": pkg_failed.get(pkg, 0),
            "skipped": pkg_skipped.get(pkg, 0),
            "elapsed": pkg_elapsed.get(pkg),
        }
        for pkg in sorted(pkg_tests)
    ]

    failures = []
    for pkg, test in failed_tests:
        out = "".join(test_output.get((pkg, test), []))
        if not out:
            out = "".join(pkg_output.get(pkg, []))
        failures.append({
            "package": short_pkg(pkg),
            "test": test,
            "output": out.rstrip(),
        })

    return GoTestStats(
        passed=total_pass,
        failed=total_fail,
        skipped=total_skip,
        elapsed=total_elapsed,
        packages=packages,
        failures=failures,
    )
