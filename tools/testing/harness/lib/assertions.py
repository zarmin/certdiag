import json
import os
import re
import time
from pathlib import Path

from .proc import FileHelper


def _normalize_path_seps(text):
    return text.replace("\\", "/")


_TIMESTAMPS = os.environ.get("CERTDIAG_TEST_TIMESTAMPS") == "1"


class Tracker:

    def __init__(self, manifest_path=None):
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self._t0 = time.monotonic()
        self._manifest = open(manifest_path, "w") if manifest_path else None
        # Structured record of every assertion, consumed by lib/report.py.
        self.records = []
        self.suite = None

    def close(self):
        if self._manifest:
            self._manifest.close()
            self._manifest = None

    def _manifest_write(self, status, label, detail=""):
        if self._manifest:
            self._manifest.write(f"{status}\t{label}\t{detail}\n")
            self._manifest.flush()

    def _record(self, status, label, detail=""):
        self.records.append({
            "suite": self.suite,
            "status": status,
            "label": label,
            "detail": detail,
            "at": time.monotonic() - self._t0,
        })

    def _ts(self):
        if not _TIMESTAMPS:
            return ""
        elapsed = time.monotonic() - self._t0
        return f"[{elapsed:7.2f}s] "

    # --- primitives ---

    def PASS(self, msg):
        self.passed += 1
        print(f"  {self._ts()}PASS: {msg}")
        self._manifest_write("PASS", msg)
        self._record("PASS", msg)

    def FAIL(self, msg, detail=""):
        self.failed += 1
        suffix = f" -- {detail}" if detail else ""
        print(f"  {self._ts()}FAIL: {msg}{suffix}")
        self._manifest_write("FAIL", msg, detail)
        self._record("FAIL", msg, detail)

    def SKIP(self, msg):
        self.skipped += 1
        print(f"  {self._ts()}SKIP: {msg}")
        self._manifest_write("SKIP", msg)
        self._record("SKIP", msg)

    # --- exit code assertions ---

    def assert_exit_code(self, expected, actual, label):
        if expected == actual:
            self.PASS(f"{label} (exit {actual})")
        else:
            self.FAIL(label, f"expected exit {expected}, got {actual}")

    def expect_exit(self, expected, result, label):
        self.assert_exit_code(expected, result.returncode, label)

    def expect_ok(self, result, label):
        self.expect_exit(0, result, label)

    def expect_fail(self, result, label):
        if result.returncode != 0:
            self.PASS(f"{label} (exit {result.returncode})")
        else:
            self.FAIL(label, "expected non-zero exit, got 0")

    # --- output assertions ---

    def _resolve_text(self, text_or_result, stream="stdout"):
        if isinstance(text_or_result, str):
            return text_or_result
        return text_or_result.stdout if stream == "stdout" else text_or_result.stderr

    def assert_contains(self, output, text, label, stream="stdout"):
        source = self._resolve_text(output, stream)
        if text in source:
            self.PASS(label)
        else:
            self.FAIL(label, f"text not found: {text}")

    def assert_not_contains(self, output, text, label, stream="stdout"):
        source = self._resolve_text(output, stream)
        if text not in source:
            self.PASS(label)
        else:
            self.FAIL(label, f"unexpected text found: {text}")

    def assert_contains_path(self, output, path_fragment, label, stream="stdout"):
        source = _normalize_path_seps(self._resolve_text(output, stream))
        normalized = _normalize_path_seps(path_fragment)
        if normalized in source:
            self.PASS(label)
        else:
            self.FAIL(label, f"path not found: {path_fragment}")

    def assert_contains_regex(self, output, pattern, label, stream="stdout",
                              case_insensitive=True):
        source = self._resolve_text(output, stream)
        flags = re.IGNORECASE if case_insensitive else 0
        if re.search(pattern, source, flags):
            self.PASS(label)
        else:
            self.FAIL(label, f"regex not found: {pattern}")

    def assert_not_contains_regex(self, output, pattern, label, stream="stdout",
                                  case_insensitive=True):
        source = self._resolve_text(output, stream)
        flags = re.IGNORECASE if case_insensitive else 0
        if not re.search(pattern, source, flags):
            self.PASS(label)
        else:
            self.FAIL(label, f"unexpected regex match: {pattern}")

    # --- JSON assertions ---

    def assert_json(self, text_or_result, label):
        text = text_or_result.stdout if hasattr(text_or_result, "stdout") else text_or_result
        try:
            json.loads(text)
            self.PASS(label)
        except (json.JSONDecodeError, TypeError):
            self.FAIL(label, "invalid JSON")

    def assert_json_schema(self, result, schema, label):
        try:
            data = json.loads(result.stdout)
        except (json.JSONDecodeError, TypeError) as e:
            self.FAIL(label, f"invalid JSON: {e}")
            return

        errors = _validate_schema(data, schema, "")
        if errors:
            self.FAIL(label, "; ".join(errors[:3]))
        else:
            self.PASS(label)

    def assert_json_item_count(self, result, expected, label):
        try:
            data = json.loads(result.stdout)
            files = data.get("files", [])
            items = files[0].get("items", []) if files else []
            if len(items) == expected:
                self.PASS(f"{label} ({expected} items)")
            else:
                self.FAIL(label, f"expected {expected} items, got {len(items)}")
        except (json.JSONDecodeError, TypeError, IndexError) as e:
            self.FAIL(label, f"JSON parse error: {e}")

    # --- file assertions ---

    def assert_file_exists(self, path, label):
        if Path(path).is_file():
            self.PASS(label)
        else:
            self.FAIL(label, f"file not found: {path}")

    def assert_file_not_empty(self, path, label):
        p = Path(path)
        if p.is_file() and p.stat().st_size > 0:
            self.PASS(label)
        else:
            self.FAIL(label, f"file missing or empty: {path}")

    def assert_file_count(self, directory, pattern, expected, label):
        actual = len(FileHelper.files_matching(directory, pattern))
        if actual == expected:
            self.PASS(f"{label} ({actual} files)")
        else:
            self.FAIL(label, f"expected {expected} files, got {actual}")

    def assert_hex_starts_with(self, filepath, expected_hex, label, limit=1):
        actual = FileHelper.read_hex(filepath, limit=limit)
        if actual == expected_hex:
            self.PASS(label)
        else:
            self.FAIL(label, f"expected hex {expected_hex}, got {actual}")

    # --- misc assertions ---

    def assert_no_ansi(self, text_or_result, label):
        text = self._resolve_text(text_or_result)
        if "\033[" not in text:
            self.PASS(label)
        else:
            self.FAIL(label, "ANSI escape codes found")

    def assert_equal(self, actual, expected, label):
        if actual == expected:
            self.PASS(label)
        else:
            self.FAIL(label, f"expected {expected!r}, got {actual!r}")

    def assert_not_timed_out(self, result, label):
        if not result.timed_out:
            self.PASS(label)
        else:
            self.FAIL(label, f"timed out after {result.cmd}")

    def assert_line_count(self, output, expected, label, stream="stdout"):
        text = self._resolve_text(output, stream)
        actual = len([l for l in text.splitlines() if l.strip()])
        if actual == expected:
            self.PASS(f"{label} ({actual} lines)")
        else:
            self.FAIL(label, f"expected {expected} lines, got {actual}")

    def assert_greater_than(self, actual, minimum, label):
        if actual > minimum:
            self.PASS(label)
        else:
            self.FAIL(label, f"expected > {minimum}, got {actual}")

    # --- summary ---

    def summary(self, suite_name):
        sep = "=" * 41
        print(sep)
        print(f"{suite_name}: {self.passed} passed, {self.failed} failed, {self.skipped} skipped")
        print(sep)
        return self.failed == 0


def _validate_schema(data, schema, path):
    errors = []
    if isinstance(schema, type):
        if not isinstance(data, schema):
            errors.append(f"{path}: expected {schema.__name__}, got {type(data).__name__}")
    elif isinstance(schema, dict):
        if not isinstance(data, dict):
            errors.append(f"{path}: expected dict, got {type(data).__name__}")
        else:
            for key, val_schema in schema.items():
                if key not in data:
                    errors.append(f"{path}.{key}: missing required key")
                else:
                    errors.extend(_validate_schema(data[key], val_schema, f"{path}.{key}"))
    elif isinstance(schema, list) and len(schema) == 1:
        if not isinstance(data, list):
            errors.append(f"{path}: expected list, got {type(data).__name__}")
        elif data:
            errors.extend(_validate_schema(data[0], schema[0], f"{path}[0]"))
    return errors
