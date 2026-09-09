import os
import shutil
import sys
import tempfile
from pathlib import Path

from .proc import CmdRunner


REPO_ROOT_MARKER = ".git"


def _find_repo_root():
    d = Path(__file__).resolve().parent
    for _ in range(10):
        if (d / REPO_ROOT_MARKER).exists():
            return d
        d = d.parent
    raise FileNotFoundError(f"repo root not found (looked for {REPO_ROOT_MARKER})")


class Harness:

    def __init__(self, binary=None, fixtures_dir=None):
        repo_root = _find_repo_root()
        self.binary_path = Path(binary or os.environ.get(
            "CERTDIAG_BINARY",
            repo_root / "certdiag_app" / "dist" / "certdiag"
        ))
        self.fixtures_dir = Path(fixtures_dir) if fixtures_dir else None
        self.tmp_dir = None
        self.cmd = CmdRunner(binary=self.binary_path)

    def setup(self, required_tools=None):
        if not self.binary_path.exists() and not (
            sys.platform == "win32" and self.binary_path.with_suffix(".exe").exists()
        ):
            raise FileNotFoundError(f"binary not found: {self.binary_path}")
        missing = [t for t in (required_tools or []) if not self.has_tool(t)]
        if missing:
            raise RuntimeError(f"missing required tools: {', '.join(missing)}")
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="certdiag_test_"))

    def cleanup(self):
        if self.tmp_dir and self.tmp_dir.exists():
            shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def tmp(self, *parts):
        p = self.tmp_dir.joinpath(*parts)
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def fixture(self, *parts):
        return self.fixtures_dir.joinpath(*parts)

    @staticmethod
    def has_tool(name):
        return shutil.which(name) is not None

    @staticmethod
    def has_network():
        return os.environ.get("CERTDIAG_TEST_NETWORK") == "1"
