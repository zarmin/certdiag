import os
import sys


def use_color():
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code):
    return code if use_color() else ""


GREEN = property(lambda self: _c("\033[32m"))
RED = property(lambda self: _c("\033[31m"))
DIM = property(lambda self: _c("\033[2m"))
RESET = property(lambda self: _c("\033[0m"))


def phase_pass(name, detail=""):
    g = _c("\033[32m")
    r = _c("\033[0m")
    print(f"  {g}PASS{r}  {name}  {detail}")


def phase_fail(name, detail=""):
    red = _c("\033[31m")
    r = _c("\033[0m")
    print(f"  {red}FAIL{r}  {name}  {detail}")


def phase_skip(name, detail=""):
    d = _c("\033[2m")
    r = _c("\033[0m")
    print(f"  {d}SKIP{r}  {name}  {detail}")


def section(title):
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")
