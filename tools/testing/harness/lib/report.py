"""Test report generation.

Every harness run writes two artifacts into tools/testing/reports/:

  report_<timestamp>.txt   human-readable summary
  report_<timestamp>.json  the same data, indented, for tooling

Both are also copied to latest.txt / latest.json so a consumer does not have to
resolve the newest timestamp. The directory is gitignored apart from .gitkeep.
"""

import json
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


SCHEMA = "certdiag-test-report"
SCHEMA_VERSION = "1"


def _go_version():
    try:
        out = subprocess.run(["go", "version"], capture_output=True, text=True, timeout=10)
        return out.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


class Report:
    """Collects phase results across a run and renders them to text + JSON."""

    def __init__(self, args):
        self._t0 = time.monotonic()
        self.started_at = datetime.now(timezone.utc)
        self.phases = []
        self.command = {
            "phase": getattr(args, "phase", None) or "all",
            "suite_filter": getattr(args, "suite", None),
            "race": bool(getattr(args, "race", False)),
            "skip_docker": bool(getattr(args, "skip_docker", False)),
            "argv": sys.argv[1:],
        }

    # --- collection ---

    def add_go_phase(self, name, stats):
        """Record a Go test phase (unit / extended / docker)."""
        self.phases.append({
            "name": name,
            "kind": "go",
            "totals": {
                "passed": stats.passed,
                "failed": stats.failed,
                "skipped": stats.skipped,
            },
            "duration_seconds": round(stats.elapsed, 3),
            "packages": [
                {
                    "package": p["package"],
                    "passed": p["passed"],
                    "failed": p["failed"],
                    "skipped": p["skipped"],
                    "duration_seconds": round(p["elapsed"], 3) if p["elapsed"] else None,
                }
                for p in getattr(stats, "packages", [])
            ],
            "failures": [
                {
                    "package": f["package"],
                    "test": f["test"],
                    "output": f["output"],
                }
                for f in getattr(stats, "failures", [])
            ],
        })

    def add_tracker_phase(self, name, tracker):
        """Record an assertion-based phase (cli / stress)."""
        suites = {}
        order = []
        for rec in getattr(tracker, "records", []):
            suite = rec.get("suite") or "(ungrouped)"
            if suite not in suites:
                suites[suite] = []
                order.append(suite)
            suites[suite].append(rec)

        suite_entries = []
        for suite in order:
            recs = suites[suite]
            suite_entries.append({
                "suite": suite,
                "totals": {
                    "passed": sum(1 for r in recs if r["status"] == "PASS"),
                    "failed": sum(1 for r in recs if r["status"] == "FAIL"),
                    "skipped": sum(1 for r in recs if r["status"] == "SKIP"),
                },
                "assertions": [
                    {
                        "status": r["status"],
                        "label": r["label"],
                        "detail": r["detail"],
                        "at_seconds": round(r["at"], 3),
                    }
                    for r in recs
                ],
            })

        self.phases.append({
            "name": name,
            "kind": "assertions",
            "totals": {
                "passed": tracker.passed,
                "failed": tracker.failed,
                "skipped": tracker.skipped,
            },
            "duration_seconds": round(time.monotonic() - tracker._t0, 3),
            "suites": suite_entries,
            "failures": [
                {
                    "suite": r.get("suite") or "(ungrouped)",
                    "label": r["label"],
                    "detail": r["detail"],
                }
                for r in getattr(tracker, "records", [])
                if r["status"] == "FAIL"
            ],
        })

    def add_phase(self, name, result):
        """Dispatch on whatever the phase returned."""
        if hasattr(result, "records"):
            self.add_tracker_phase(name, result)
        elif hasattr(result, "passed"):
            self.add_go_phase(name, result)

    # --- rendering ---

    def totals(self):
        return {
            "passed": sum(p["totals"]["passed"] for p in self.phases),
            "failed": sum(p["totals"]["failed"] for p in self.phases),
            "skipped": sum(p["totals"]["skipped"] for p in self.phases),
        }

    def to_dict(self):
        totals = self.totals()
        return {
            "schema": SCHEMA,
            "version": SCHEMA_VERSION,
            "generated_at": self.started_at.isoformat().replace("+00:00", "Z"),
            "duration_seconds": round(time.monotonic() - self._t0, 3),
            "result": "failed" if totals["failed"] else "passed",
            "totals": totals,
            "command": self.command,
            "environment": {
                "os": platform.system().lower(),
                "arch": platform.machine(),
                "platform": platform.platform(),
                "python": platform.python_version(),
                "go": _go_version(),
            },
            "phases": self.phases,
        }

    def to_text(self):
        d = self.to_dict()
        t = d["totals"]
        lines = []

        def rule(ch="="):
            lines.append(ch * 72)

        rule()
        lines.append("  certdiag test report")
        rule()
        lines.append(f"  Generated : {d['generated_at']}")
        lines.append(f"  Duration  : {d['duration_seconds']:.1f}s")
        lines.append(f"  Phase     : {d['command']['phase']}")
        if d["command"]["suite_filter"]:
            lines.append(f"  Suites    : {d['command']['suite_filter']}")
        if d["command"]["race"]:
            lines.append("  Race      : enabled")
        env = d["environment"]
        lines.append(f"  Platform  : {env['os']}/{env['arch']}  python {env['python']}")
        if env["go"]:
            lines.append(f"  Go        : {env['go']}")
        lines.append("")
        lines.append(f"  RESULT    : {d['result'].upper()}"
                     f"   ({t['passed']} passed, {t['failed']} failed, {t['skipped']} skipped)")
        lines.append("")

        # --- per-phase ---
        rule("-")
        lines.append("  Phases")
        rule("-")
        for p in d["phases"]:
            pt = p["totals"]
            status = "FAIL" if pt["failed"] else "PASS"
            lines.append(f"  [{status}] {p['name']:<10s} "
                         f"{pt['passed']:5d} passed  {pt['failed']:3d} failed  "
                         f"{pt['skipped']:3d} skipped   ({p['duration_seconds']:.1f}s)")
        lines.append("")

        # --- detail ---
        for p in d["phases"]:
            if p["kind"] == "go" and p["packages"]:
                rule("-")
                lines.append(f"  {p['name']}: packages")
                rule("-")
                for pkg in p["packages"]:
                    dur = f"{pkg['duration_seconds']:.1f}s" if pkg["duration_seconds"] else "-"
                    mark = "FAIL" if pkg["failed"] else "ok  "
                    lines.append(f"  {mark} {pkg['package']:<45s} "
                                 f"{pkg['passed']:4d}P {pkg['failed']:3d}F {pkg['skipped']:3d}S  {dur:>7s}")
                lines.append("")
            elif p["kind"] == "assertions" and p["suites"]:
                rule("-")
                lines.append(f"  {p['name']}: suites")
                rule("-")
                for s in p["suites"]:
                    st = s["totals"]
                    mark = "FAIL" if st["failed"] else "ok  "
                    lines.append(f"  {mark} {s['suite']:<45s} "
                                 f"{st['passed']:4d}P {st['failed']:3d}F {st['skipped']:3d}S")
                lines.append("")

        # --- failures ---
        any_failures = any(p["failures"] for p in d["phases"])
        if any_failures:
            rule("-")
            lines.append("  Failures")
            rule("-")
            for p in d["phases"]:
                for f in p["failures"]:
                    if p["kind"] == "go":
                        lines.append(f"  [{p['name']}] {f['package']} :: {f['test']}")
                        for line in (f["output"] or "").splitlines():
                            if line.strip():
                                lines.append(f"        {line.rstrip()}")
                    else:
                        loc = f"{f['suite']}" if f.get("suite") else p["name"]
                        lines.append(f"  [{p['name']}] {loc}")
                        lines.append(f"        {f['label']}")
                        if f["detail"]:
                            lines.append(f"        -> {f['detail']}")
                    lines.append("")
        else:
            rule("-")
            lines.append("  No failures.")
            rule("-")
            lines.append("")

        return "\n".join(lines) + "\n"

    def write(self, report_dir, ts):
        report_dir = Path(report_dir)
        report_dir.mkdir(parents=True, exist_ok=True)

        txt_path = report_dir / f"report_{ts}.txt"
        json_path = report_dir / f"report_{ts}.json"

        text = self.to_text()
        payload = json.dumps(self.to_dict(), indent=2, sort_keys=False) + "\n"

        txt_path.write_text(text, encoding="utf-8")
        json_path.write_text(payload, encoding="utf-8")

        # Stable names so tooling does not have to find the newest timestamp.
        (report_dir / "latest.txt").write_text(text, encoding="utf-8")
        (report_dir / "latest.json").write_text(payload, encoding="utf-8")

        return txt_path, json_path


def prune(report_dir, keep=10):
    """Keep only the newest `keep` timestamped reports of each kind."""
    report_dir = Path(report_dir)
    if not report_dir.exists():
        return
    for suffix in ("txt", "json"):
        files = sorted(
            report_dir.glob(f"report_*.{suffix}"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for old in files[keep:]:
            old.unlink(missing_ok=True)
