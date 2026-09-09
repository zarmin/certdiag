#!/usr/bin/env python3
"""Generate the pkg/sqliteread test databases.

Run from anywhere:  python3 tools/testing/gen_sqlite_fixtures.py

Uses python's stdlib sqlite3, so nothing external is needed at generation time
and nothing at all is needed to run the tests. Blob contents are deterministic
patterns the Go tests recompute themselves, so there is no digest file to keep
in sync.
"""

import sqlite3
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parents[2] / "certdiag_app" / "pkg" / "sqliteread" / "testdata"


def pattern(n, step):
    """Deterministic blob: byte i is (i * step) % 251. Mirrored in Go."""
    return bytes((i * step) % 251 for i in range(n))


def build(path, page_size, rows, big_blob):
    path.unlink(missing_ok=True)
    con = sqlite3.connect(path)
    con.execute(f"PRAGMA page_size={page_size}")
    con.execute("VACUUM")
    con.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT, blob1, num, flag)")

    con.execute("INSERT INTO t (name, blob1, num, flag) VALUES (?,?,?,?)",
                ("small", pattern(5, 1), 42, 1))
    con.execute("INSERT INTO t (name, blob1, num, flag) VALUES (?,?,?,?)",
                ("big", pattern(big_blob, 3), -7, 0))
    con.execute("INSERT INTO t (name, blob1, num, flag) VALUES (?,?,?,?)",
                ("mid", pattern(3000, 7), 2**40, None))
    con.execute("INSERT INTO t (name, blob1, num, flag) VALUES (?,?,?,?)",
                ("nulls", None, None, None))
    con.execute("INSERT INTO t (name, blob1, num, flag) VALUES (?,?,?,?)",
                ("floats", pattern(9, 11), 1.5, 0))

    for i in range(rows):
        con.execute("INSERT INTO t (name, blob1, num, flag) VALUES (?,?,?,?)",
                    (f"r{i}", pattern(900, (i % 13) + 1), i, i % 2))

    con.commit()
    con.close()
    print(f"  {path.name}: page_size={page_size} rows={rows + 5} big_blob={big_blob}")


def build_nss_shaped(path):
    """A table whose columns are named like NSS nssPublic, to exercise the
    column-name path the real reader depends on."""
    path.unlink(missing_ok=True)
    con = sqlite3.connect(path)
    con.execute("PRAGMA page_size=4096")
    con.execute("VACUUM")
    con.execute("CREATE TABLE nssPublic (id PRIMARY KEY UNIQUE ON CONFLICT ABORT, "
                "a0, a1, a3, a11, a81, a82, a101, a102)")
    con.execute("CREATE INDEX subject ON nssPublic (a101)")
    con.execute("INSERT INTO nssPublic (id, a0, a3, a11) VALUES (?,?,?,?)",
                ("1", (1).to_bytes(4, "big"), b"label-one", pattern(1400, 5)))
    con.execute("INSERT INTO nssPublic (id, a0, a3, a11) VALUES (?,?,?,?)",
                ("2", (11).to_bytes(4, "big"), b"label-two", pattern(64, 2)))
    con.commit()
    con.close()
    print(f"  {path.name}: NSS-shaped column names, non-INTEGER primary key")


def corrupt(src, dst):
    """Copy a valid database and mangle one cell pointer, so a reader must skip
    the bad cell without losing the rest of the table."""
    data = bytearray(src.read_bytes())
    page_size = int.from_bytes(data[16:18], "big")
    if page_size == 1:
        page_size = 65536
    # Page 2 is the table root; its cell pointer array starts right after the
    # 8-byte leaf header. Point the first cell past the end of the page.
    ptr = page_size + 8
    data[ptr] = 0xFF
    data[ptr + 1] = 0xF0
    dst.write_bytes(bytes(data))
    print(f"  {dst.name}: one cell pointer mangled")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    print(f"writing to {OUT}")

    build(OUT / "pages512.db", 512, 400, 20000)
    build(OUT / "pages4096.db", 4096, 40, 9000)
    build(OUT / "pages32768.db", 32768, 20, 40000)
    build_nss_shaped(OUT / "nsscolumns.db")
    corrupt(OUT / "pages4096.db", OUT / "corrupt.db")

    (OUT / "notsqlite.bin").write_bytes(b"NOT A SQLITE FILE" + bytes(200))
    print("  notsqlite.bin: wrong magic")

    (OUT / "truncated.db").write_bytes((OUT / "pages4096.db").read_bytes()[:60])
    print("  truncated.db: shorter than the file header")

    return 0


if __name__ == "__main__":
    sys.exit(main())
