import json
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class RunResult:
    cmd: list
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self):
        return self.returncode == 0

    def json(self):
        return json.loads(self.stdout)

    def lines(self, stream="stdout"):
        text = self.stdout if stream == "stdout" else self.stderr
        return [l for l in text.splitlines() if l.strip()]

    def contains(self, text, stream="stdout"):
        source = self.stdout if stream == "stdout" else self.stderr
        return text in source

    def contains_regex(self, pattern, stream="stdout", case_insensitive=True):
        source = self.stdout if stream == "stdout" else self.stderr
        flags = re.IGNORECASE if case_insensitive else 0
        return bool(re.search(pattern, source, flags))

    def line_count(self, stream="stdout"):
        return len(self.lines(stream))


class FileHelper:

    @staticmethod
    def read_bytes(filepath, limit=None):
        data = Path(filepath).read_bytes()
        return data[:limit] if limit else data

    @staticmethod
    def read_hex(filepath, limit=None):
        data = FileHelper.read_bytes(filepath, limit)
        return data.hex()

    @staticmethod
    def file_size(filepath):
        return Path(filepath).stat().st_size

    @staticmethod
    def files_matching(directory, pattern):
        return list(Path(directory).glob(pattern))


class CmdRunner:

    def __init__(self, binary=None, default_timeout=30):
        self.binary = Path(binary) if binary else None
        self.default_timeout = default_timeout

        if self.binary and sys.platform == "win32" and self.binary.suffix != ".exe":
            exe = self.binary.with_suffix(".exe")
            if exe.exists():
                self.binary = exe

    def __call__(self, template, stdin=None, env_extra=None, timeout=None,
                 cwd=None, check=False, **kwargs):
        if not self.binary:
            raise RuntimeError("no binary configured")
        args = self._parse_template(template, kwargs)
        return self._exec(
            [str(self.binary)] + args,
            stdin=stdin, env_extra=env_extra,
            timeout=timeout or self.default_timeout, cwd=cwd, check=check,
        )

    def run(self, *args, stdin=None, env_extra=None, timeout=None, cwd=None, check=False):
        if not self.binary:
            raise RuntimeError("no binary configured")
        return self._exec(
            [str(self.binary)] + [str(a) for a in args],
            stdin=stdin, env_extra=env_extra,
            timeout=timeout or self.default_timeout, cwd=cwd, check=check,
        )

    def tool(self, template_or_name, *args, stdin=None, env_extra=None,
             timeout=None, cwd=None, check=False, **kwargs):
        if args:
            cmd_list = [template_or_name] + [str(a) for a in args]
        else:
            cmd_list = self._parse_template(template_or_name, kwargs)
        return self._exec(
            cmd_list, stdin=stdin, env_extra=env_extra,
            timeout=timeout or self.default_timeout, cwd=cwd, check=check,
        )

    def openssl(self, template, check=False, **kwargs):
        return self.tool(f"openssl {template}", check=check, **kwargs)

    def keytool(self, template, check=False, **kwargs):
        return self.tool(f"keytool {template}", check=check, **kwargs)

    @staticmethod
    def _parse_template(template, kwargs):
        if "\x00" in template:
            raise ValueError("template contains null bytes")

        if not kwargs:
            return shlex.split(template)

        for name, value in kwargs.items():
            sval = str(value)
            if "{" in sval or "}" in sval:
                raise ValueError(
                    f"placeholder {{{name}}} value contains curly braces: {sval!r}"
                )

        sentinels = {}

        def replacer(match):
            name = match.group(1)
            if name not in kwargs:
                raise KeyError(f"template placeholder {{{name}}} not in kwargs")
            sentinel = f"\x00TMPL_{len(sentinels)}\x00"
            sentinels[sentinel] = str(kwargs[name])
            return sentinel

        filled = re.sub(r"\{(\w+)\}", replacer, template)
        parts = shlex.split(filled)

        result = []
        for p in parts:
            for sentinel, val in sentinels.items():
                p = p.replace(sentinel, val)
            result.append(p)
        return result

    def _exec(self, cmd, stdin=None, env_extra=None, timeout=30, cwd=None, check=False):
        env = os.environ.copy()
        # No terminal behind a pipe: give tables a wide, deterministic width
        # (the narrow-width behaviour is covered by Go tests) unless a suite
        # sets COLUMNS itself.
        env.setdefault("COLUMNS", "200")
        if env_extra:
            env.update(env_extra)

        # Always give the child an explicit, already-closed stdin. With
        # input=None subprocess leaves stdin inherited, so a command that
        # prompts (for a password, say) blocks on the developer's terminal
        # until the timeout -- which `expect_fail` then records as a pass,
        # hiding the hang. An empty stdin makes local runs behave exactly like
        # CI: the prompt hits EOF and the command fails immediately.
        if stdin is None:
            stdin = ""

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                encoding="utf-8", errors="replace",
                input=stdin, env=env, timeout=timeout, cwd=cwd,
            )
            result = RunResult(
                cmd=cmd, returncode=proc.returncode,
                stdout=proc.stdout, stderr=proc.stderr,
            )
        except subprocess.TimeoutExpired as e:
            result = RunResult(
                cmd=cmd, returncode=124,
                stdout=e.stdout or "", stderr=e.stderr or "",
                timed_out=True,
            )
        except FileNotFoundError:
            result = RunResult(
                cmd=cmd, returncode=127,
                stdout="", stderr=f"command not found: {cmd[0]}",
            )

        if check and not result.ok:
            raise RuntimeError(
                f"command failed (exit {result.returncode}): "
                f"{' '.join(str(c) for c in cmd)}\n"
                f"stderr: {result.stderr.strip()}"
            )
        return result
