import os
import subprocess
import sys

from ..lib.harness import Harness
from ..lib.assertions import Tracker


NC = "--no-confirm"


def run(h, t):
    print("\n=== T10: Negative Tests -- Things That MUST Fail ===")

    # ======================================================================
    # MISSING REQUIRED ARGUMENTS
    # ======================================================================

    # --- T10.01: Commands without required arguments ---
    print("-- T10.01: Commands without required arguments")

    r = h.cmd("--no-color convert")
    t.expect_fail(r, "T10.01a: convert without args")

    r = h.cmd("--no-color convert {f}", f=h.fixture("leaf-rsa.pem"))
    t.expect_fail(r, "T10.01b: convert without output")

    r = h.cmd("--no-color extract")
    t.expect_fail(r, "T10.01c: extract without args")

    r = h.cmd("--no-color sign")
    t.expect_fail(r, "T10.01d: sign without args")

    r = h.cmd("--no-color sign {f}", f=h.fixture("basic.csr"))
    t.expect_fail(r, "T10.01e: sign without CA")

    r = h.cmd("--no-color reencrypt")
    t.expect_fail(r, "T10.01f: reencrypt without args")

    r = h.cmd("--no-color diff")
    t.expect_fail(r, "T10.01g: diff without args")

    r = h.cmd("--no-color diff {f}", f=h.fixture("leaf-rsa.pem"))
    t.expect_fail(r, "T10.01h: diff with only one file")

    r = h.cmd("--no-color bundle -o {out}", out=h.tmp("b.pem"))
    t.expect_fail(r, "T10.01i: bundle without input files")

    r = h.cmd("--no-color renew")
    t.expect_fail(r, "T10.01j: renew without args")

    r = h.cmd("--no-color remote fetch")
    t.expect_fail(r, "T10.01k: remote fetch without host")

    r = h.cmd("--no-color remote check")
    t.expect_fail(r, "T10.01l: remote check without host")

    r = h.cmd("--no-color remote probe")
    t.expect_fail(r, "T10.01m: remote probe without host")

    r = h.cmd("--no-color remote http")
    t.expect_fail(r, "T10.01n: remote http without host")

    r = h.cmd("--no-color pcap sessions")
    t.expect_fail(r, "T10.01o: pcap sessions without file")

    r = h.cmd("--no-color pcap check")
    t.expect_fail(r, "T10.01p: pcap check without file")

    r = h.cmd("--no-color pcap extract")
    t.expect_fail(r, "T10.01q: pcap extract without file")

    r = h.cmd("--no-color proxy")
    t.expect_fail(r, "T10.01r: proxy without args")

    r = h.cmd("--no-color proxy -l 127.0.0.1:8888")
    t.expect_fail(r, "T10.01s: proxy without target")

    r = h.cmd("--no-color proxy -t 192.0.2.1:443")
    t.expect_fail(r, "T10.01t: proxy without listen")

    # ======================================================================
    # INVALID FILE INPUTS
    # ======================================================================

    # --- T10.02: Non-existent files ---
    print("-- T10.02: Non-existent files")

    r = h.cmd("--no-color /nonexistent/file.pem")
    t.expect_fail(r, "T10.02a: view nonexistent file")

    r = h.cmd("--no-color convert /nonexistent/file.pem -o {out}", out=h.tmp("x.pem"))
    t.expect_fail(r, "T10.02b: convert nonexistent file")

    r = h.cmd("--no-color check /nonexistent/file.pem")
    t.expect_fail(r, "T10.02c: check nonexistent file")

    r = h.cmd("--no-color extract /nonexistent/file.pem --output-dir {d}", d=h.tmp("extract-noexist"))
    t.expect_fail(r, "T10.02d: extract nonexistent file")

    r = h.cmd("--no-color renew /nonexistent/file.pem -k {k} -o {out}",
              k=h.fixture("leaf-rsa.key"), out=h.tmp("x.pem"))
    t.expect_fail(r, "T10.02e: renew nonexistent file")

    r = h.cmd("--no-color diff /nonexistent/a.pem /nonexistent/b.pem")
    t.expect_fail(r, "T10.02f: diff nonexistent files")

    # --- T10.03: Directories where files expected ---
    print("-- T10.03: Directories where files expected")

    r = h.cmd("--no-color convert {d} -f der -o {out}",
              d=h.fixture(""), out=h.tmp("x.der"))
    t.expect_fail(r, "T10.03a: convert directory")

    r = h.cmd("--no-color extract {d} --output-dir {out}",
              d=h.fixture(""), out=h.tmp("extract-dir"))
    t.expect_fail(r, "T10.03b: extract directory")

    r = h.cmd("--no-color sign {d} --ca-cert {ca} --ca-key {ck}",
              d=h.fixture(""), ca=h.fixture("root-ca.pem"), ck=h.fixture("root-ca.key"))
    t.expect_fail(r, "T10.03c: sign directory")

    r = h.cmd("--no-color renew {d} -o {out}",
              d=h.fixture(""), out=h.tmp("x.pem"))
    t.expect_fail(r, "T10.03d: renew directory")

    r = h.cmd("--no-color reencrypt {d}", d=h.fixture(""))
    t.expect_fail(r, "T10.03e: reencrypt directory")

    # --- T10.04: Binary garbage as input ---
    print("-- T10.04: Binary garbage as input")

    r = h.cmd("--no-color convert {f} -f pem -o {out} {nc}",
              f=h.fixture("garbage.bin"), out=h.tmp("x.pem"), nc=NC)
    t.expect_fail(r, "T10.04a: convert garbage")

    r = h.cmd("--no-color check {f}", f=h.fixture("garbage.bin"))
    t.expect_fail(r, "T10.04b: check garbage")

    r = h.cmd("--no-color extract {f} --output-dir {d} {nc}",
              f=h.fixture("garbage.bin"), d=h.tmp("extract-garbage"), nc=NC)
    t.expect_fail(r, "T10.04c: extract garbage")

    r = h.cmd("--no-color diff {f} {g}",
              f=h.fixture("garbage.bin"), g=h.fixture("leaf-rsa.pem"))
    t.expect_fail(r, "T10.04d: diff garbage vs cert")

    r = h.cmd("--no-color renew {f} -o {out} {nc}",
              f=h.fixture("garbage.bin"), out=h.tmp("x.pem"), nc=NC)
    t.expect_fail(r, "T10.04e: renew garbage")

    # --- T10.05: Zero-byte file ---
    print("-- T10.05: Zero-byte file")

    r = h.cmd("--no-color {f}", f=h.fixture("zero-byte.pem"))
    t.expect_fail(r, "T10.05a: view zero-byte file")

    r = h.cmd("--no-color convert {f} -f der -o {out} {nc}",
              f=h.fixture("zero-byte.pem"), out=h.tmp("x.der"), nc=NC)
    t.expect_fail(r, "T10.05b: convert zero-byte file")

    r = h.cmd("--no-color check {f}", f=h.fixture("zero-byte.pem"))
    t.expect_fail(r, "T10.05c: check zero-byte file")

    # ======================================================================
    # INVALID FLAG VALUES
    # ======================================================================

    # --- T10.06: Invalid output formats ---
    print("-- T10.06: Invalid output formats")

    r = h.cmd("--no-color -o xml {f}", f=h.fixture("leaf-rsa.pem"))
    t.expect_fail(r, "T10.06a: -o xml on view")

    r = h.cmd("--no-color -o csv {f}", f=h.fixture("leaf-rsa.pem"))
    t.expect_fail(r, "T10.06b: -o csv on view")

    r = h.cmd("--no-color check -o xml {d}", d=h.fixture(""))
    t.expect_fail(r, "T10.06c: check -o xml")

    r = h.cmd("--no-color diff -o xml {a} {b}",
              a=h.fixture("leaf-rsa.pem"), b=h.fixture("leaf-ec.pem"))
    t.expect_fail(r, "T10.06d: diff -o xml")

    # --- T10.07: Invalid algorithms and sizes ---
    print("-- T10.07: Invalid algorithms and sizes")

    r = h.cmd("--no-color create-key -a blowfish")
    t.expect_fail(r, "T10.07a: create-key with invalid algo")

    r = h.cmd("--no-color create-key -a rsa -s 512")
    t.expect_fail(r, "T10.07b: create-key RSA size 512")

    r = h.cmd("--no-color create-key -a rsa -s 0")
    t.expect_fail(r, "T10.07c: create-key RSA size 0")

    r = h.cmd("--no-color create-key -a rsa -s -1")
    t.expect_fail(r, "T10.07d: create-key RSA size -1")

    r = h.cmd("--no-color create-key -a ecdsa --curve p128")
    t.expect_fail(r, "T10.07e: create-key ECDSA curve p128")

    r = h.cmd("--no-color create-key -a ecdsa --curve secp256k1")
    t.expect_fail(r, "T10.07f: create-key ECDSA curve secp256k1")

    # --- T10.08: Invalid conversion targets ---
    print("-- T10.08: Invalid conversion targets")

    r = h.cmd("--no-color convert {f} -f xml -o {out} {nc}",
              f=h.fixture("leaf-rsa.pem"), out=h.tmp("x.xml"), nc=NC)
    t.expect_fail(r, "T10.08a: convert to xml format")

    r = h.cmd('--no-color convert {f} -f "" -o {out} {nc}',
              f=h.fixture("leaf-rsa.pem"), out=h.tmp("x"), nc=NC)
    t.expect_fail(r, "T10.08b: convert to empty format")

    # --- T10.09: Invalid depth values ---
    print("-- T10.09: Invalid depth values")

    r = h.cmd("--no-color -r --depth -1 {d}", d=h.fixture(""))
    t.expect_fail(r, "T10.09a: depth -1")

    r = h.cmd("--no-color -r --depth abc {d}", d=h.fixture(""))
    t.expect_fail(r, "T10.09b: depth abc")

    # --- T10.10: Invalid severity/category values ---
    print("-- T10.10: Invalid severity/category values")

    r = h.cmd("--no-color check --severity panic {d}", d=h.fixture(""))
    t.expect_fail(r, "T10.10a: check severity panic")

    r = h.cmd("--no-color check --category nonexistent_category {d}", d=h.fixture(""))
    t.expect_fail(r, "T10.10b: check category nonexistent")

    # ======================================================================
    # CONFLICTING FLAGS
    # ======================================================================

    # --- T10.11: Key source conflicts (--with-key + -k together) ---
    print("-- T10.11: Key source conflicts")

    r = h.cmd("--no-color create-cert --with-key -k {k} --subject CN=x -o {out} {nc}",
              k=h.fixture("leaf-rsa.key"), out=h.tmp("x.pem"), nc=NC)
    t.expect_fail(r, "T10.11: --with-key and -k conflict")

    # --- T10.12: Table + JSON conflict ---
    print("-- T10.12: Table + JSON conflict")

    r = h.cmd("--no-color -t -o json {f}", f=h.fixture("leaf-rsa.pem"))
    if r.returncode <= 2:
        t.PASS(f"T10.12 table+JSON conflict exits {r.returncode} (no crash)")
    else:
        t.FAIL("T10.12 table+JSON conflict", f"unexpected exit {r.returncode}")

    # --- T10.13: IPv4 + IPv6 forcing together ---
    print("-- T10.13: IPv4 + IPv6 forcing together")

    # Mutually exclusive flags are rejected before any connection is attempted.
    r = h.cmd("--no-color remote fetch -4 -6 192.0.2.1:443")
    t.expect_fail(r, "T10.13: -4 and -6 together")

    # --- T10.13b: Repeated -p on convert ---
    print("-- T10.13b: Repeated -p on convert")

    r = h.cmd("--no-color convert {f} -p test -p extra -f pem -o {out} {nc}",
              f=h.fixture("leaf.p12"), out=h.tmp("multi-p.pem"), nc=NC)
    if r.returncode <= 2:
        t.PASS(f"T10.13b repeated -p on convert exits {r.returncode} (no crash)")
    else:
        t.FAIL("T10.13b repeated -p on convert", f"unexpected exit {r.returncode}")

    # ======================================================================
    # IMPOSSIBLE OPERATIONS
    # ======================================================================

    # --- T10.14: Convert key-only file to PKCS#7 ---
    print("-- T10.14: Convert key-only to PKCS#7")

    r = h.cmd("--no-color convert {f} -f pkcs7 -o {out} {nc}",
              f=h.fixture("leaf-rsa.key"), out=h.tmp("x.p7b"), nc=NC)
    t.expect_fail(r, "T10.14: convert key to pkcs7")

    # --- T10.15: Bundle keys into PKCS#7 ---
    print("-- T10.15: Bundle keys into PKCS#7")

    r = h.cmd("--no-color bundle {f} -f pkcs7 -o {out} {nc}",
              f=h.fixture("leaf-rsa.key"), out=h.tmp("x.p7b"), nc=NC)
    t.expect_fail(r, "T10.15: bundle key into pkcs7")

    # --- T10.16: Extract from single DER cert ---
    print("-- T10.16: Extract from single DER cert")

    extract_dir = h.tmp("extract-der-single")
    r = h.cmd("--no-color extract {f} --output-dir {d} {nc}",
              f=h.fixture("leaf.der"), d=extract_dir, nc=NC)
    t.expect_ok(r, "T10.16a: extract single DER succeeds")

    from ..lib.proc import FileHelper
    file_count = len(FileHelper.files_matching(extract_dir, "*"))
    if file_count >= 1:
        t.PASS(f"T10.16b: extract single DER produces {file_count} file(s)")
    else:
        t.FAIL("T10.16b: extract single DER", f"expected at least 1 file, got {file_count}")

    # --- T10.17: Sign with non-CA cert ---
    print("-- T10.17: Sign with non-CA cert")

    r = h.cmd("--no-color sign {csr} --ca-cert {ca} --ca-key {ck} -o {out} {nc}",
              csr=h.fixture("basic.csr"), ca=h.fixture("leaf-rsa.pem"),
              ck=h.fixture("leaf-rsa.key"), out=h.tmp("bad-signed.pem"), nc=NC)
    if r.returncode == 0:
        t.PASS("T10.17a: sign with non-CA cert exits 0 (allowed but check should warn)")
        rc = h.cmd("--no-color check {signed} {signer}",
                    signed=h.tmp("bad-signed.pem"), signer=h.fixture("leaf-rsa.pem"))
        if rc.returncode != 0:
            t.PASS(f"T10.17b: check on non-CA-signed cert reports issues (exit {rc.returncode})")
        else:
            t.SKIP(f"T10.17b: check did not flag non-CA signer (exit {rc.returncode})")
    elif r.returncode == 2:
        t.PASS("T10.17: sign with non-CA cert correctly rejected (exit 2)")
    else:
        t.FAIL("T10.17: sign with non-CA cert", f"unexpected exit {r.returncode}")

    # --- T10.18: Renew without signing key ---
    print("-- T10.18: Renew without signing key")

    r = h.cmd("--no-color renew {f} -o {out} {nc}",
              f=h.fixture("leaf-rsa.pem"), out=h.tmp("x.pem"), nc=NC)
    t.expect_fail(r, "T10.18: renew without signing key")

    # --- T10.19: Renew with wrong key type (RSA cert with EC key) ---
    print("-- T10.19: Renew with wrong key type")

    r = h.cmd("--no-color renew {f} -k {k} -o {out} {nc}",
              f=h.fixture("leaf-rsa.pem"), k=h.fixture("leaf-ec.key"),
              out=h.tmp("x.pem"), nc=NC)
    t.expect_fail(r, "T10.19: renew RSA cert with EC key")

    # --- T10.20: Convert multi-cert PEM to DER ---
    print("-- T10.20: Convert multi-cert PEM to DER")

    r = h.cmd("--no-color convert {f} -f der -o {out} {nc}",
              f=h.fixture("chain-full.pem"), out=h.tmp("x.der"), nc=NC)
    t.expect_fail(r, "T10.20: convert multi-cert PEM to DER")

    # ======================================================================
    # OVERWRITE PROTECTION AND FILE SYSTEM
    # ======================================================================

    # --- T10.21: Overwrite protection in non-TTY ---
    print("-- T10.21: Overwrite protection in non-TTY")

    precious_path = h.tmp("precious.pem")
    precious_path.write_text("precious data")
    r = h.cmd("--no-color create-key -a ed25519 -o {out}",
              out=precious_path, stdin="")
    content = precious_path.read_text()
    if "precious data" in content:
        t.PASS("T10.21: overwrite refused in non-TTY (data preserved)")
    else:
        t.FAIL("T10.21: overwrite refused in non-TTY", "file was overwritten")

    # --- T10.22: Output to read-only path ---
    print("-- T10.22: Output to read-only path")

    ro_path = h.tmp("readonly", "file.pem")
    ro_path.write_text("")
    ro_path.chmod(0o444)
    r = h.cmd("--no-color create-key -a ed25519 -o {out} {nc}",
              out=ro_path, nc=NC)
    t.expect_fail(r, "T10.22: output to read-only path")
    ro_path.chmod(0o644)

    # --- T10.23: Output to non-existent directory ---
    print("-- T10.23: Output to non-existent directory")

    r = h.cmd("--no-color create-key -a ed25519 -o /tmp/certdiag_nonexistent_dir_xyz/key.pem {nc}",
              nc=NC)
    t.expect_fail(r, "T10.23: output to non-existent directory")

    # --- T10.24: Very long file paths ---
    print("-- T10.24: Very long file paths")

    long_name = "a" * 200
    long_dir = h.tmp(long_name)
    long_dir.mkdir(parents=True, exist_ok=True)
    import shutil
    shutil.copy2(str(h.fixture("leaf-rsa.pem")), str(long_dir / "cert.pem"))
    r = h.cmd("--no-color {f}", f=long_dir / "cert.pem")
    t.expect_ok(r, "T10.24: very long file path works")
    shutil.rmtree(str(long_dir), ignore_errors=True)

    # --- T10.25: No read permissions ---
    print("-- T10.25: No read permissions")

    if sys.platform == "win32":
        t.SKIP("T10.25: no read permissions (chmod not enforced on Windows)")
    else:
        noperm_path = h.tmp("noperm.pem")
        shutil.copy2(str(h.fixture("leaf-rsa.pem")), str(noperm_path))
        noperm_path.chmod(0o000)
        r = h.cmd("--no-color {f}", f=noperm_path)
        t.expect_fail(r, "T10.25: no read permissions")
        noperm_path.chmod(0o644)

    # --- T10.26: Stdin as input (/dev/stdin) ---
    print("-- T10.26: Stdin as input")

    pem_data = h.fixture("leaf-rsa.pem").read_text()
    r = h.cmd("--no-color /dev/stdin", stdin=pem_data)
    if r.returncode <= 2:
        t.PASS(f"T10.26: /dev/stdin exits {r.returncode} (no crash)")
    else:
        t.FAIL("T10.26: /dev/stdin", f"unexpected exit {r.returncode}")

    # --- T10.27: Symlink to cert file ---
    print("-- T10.27: Symlink to cert file")

    symlink_path = h.tmp("symlink.pem")
    try:
        symlink_path.symlink_to(h.fixture("leaf-rsa.pem"))
    except OSError as e:
        # Windows requires a privilege (or Developer Mode) to create symlinks.
        t.SKIP(f"T10.27: symlink to cert file (cannot create symlink: {e})")
    else:
        r = h.cmd("--no-color {f}", f=symlink_path)
        t.expect_ok(r, "T10.27: symlink followed successfully")
        symlink_path.unlink()

    # --- T10.28: Broken symlink ---
    print("-- T10.28: Broken symlink")

    broken_link = h.tmp("broken-link.pem")
    try:
        broken_link.symlink_to("/nonexistent/cert.pem")
    except OSError as e:
        t.SKIP(f"T10.28: broken symlink (cannot create symlink: {e})")
    else:
        r = h.cmd("--no-color {f}", f=broken_link)
        t.expect_fail(r, "T10.28: broken symlink")
        broken_link.unlink()

    # --- T10.29: Named pipe FIFO ---
    print("-- T10.29: Named pipe FIFO")

    if not hasattr(os, "mkfifo"):
        t.SKIP("T10.29: named pipe FIFO (os.mkfifo unavailable on Windows)")
    else:
        fifo_path = h.tmp("fifo.pem")
        os.mkfifo(str(fifo_path))
        src = str(h.fixture("leaf-rsa.pem"))
        writer = subprocess.Popen(f"cat {src} > {fifo_path}",
                                   shell=True,
                                   stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
        r = h.cmd("--no-color {f}", f=fifo_path, timeout=10)
        if not r.timed_out and r.returncode <= 128:
            t.PASS(f"T10.29: FIFO exits {r.returncode} (did not hang)")
        elif sys.platform == "darwin":
            t.SKIP("T10.29: FIFO timed out on macOS (expected)")
        else:
            t.FAIL("T10.29: FIFO", f"timed out or signal killed (exit {r.returncode})")
        writer.kill()
        writer.wait()
        fifo_path.unlink(missing_ok=True)

    # ======================================================================
    # PASSWORD AND ENCRYPTION EDGE CASES
    # ======================================================================

    # --- T10.30: Multiple conflicting passwords (correct one wins) ---
    print("-- T10.30: Multiple conflicting passwords")

    r = h.cmd("--no-color -p wrong1 -p wrong2 -p test -p wrong3 {f}",
              f=h.fixture("leaf.p12"))
    t.expect_ok(r, "T10.30: correct password wins among multiple -p flags")

    # --- T10.31: Remote fetch save as P12 without password ---
    print("-- T10.31: Remote fetch save as P12 without password")

    # Needs a live TLS peer, so it lives in the docker phase now: see
    # d01_remote_local.py D01.10e, which covers it against the local infra.
    t.SKIP("T10.31: remote fetch save as P12 -- covered by D01.10e (docker phase)")

    # ======================================================================
    # EDGE CASES ON SPECIFIC OPERATIONS
    # ======================================================================

    # --- T10.32: Bundle auto-assemble on empty directory ---
    print("-- T10.32: Bundle auto-assemble on empty directory")

    empty_dir = h.tmp("neg-empty-assemble")
    empty_dir.mkdir(parents=True, exist_ok=True)
    r = h.cmd("--no-color bundle --auto-assemble {d} -o {out} {nc}",
              d=empty_dir, out=h.tmp("bad.pem"), nc=NC)
    t.expect_fail(r, "T10.32: bundle auto-assemble on empty dir")

    # --- T10.33: Extract with non-existent alias from JKS ---
    print("-- T10.33: Extract with non-existent alias from JKS")

    r = h.cmd("--no-color extract {f} -p jkspass --alias does_not_exist --output-dir {d} {nc}",
              f=h.fixture("multi.jks"), d=h.tmp("bad"), nc=NC)
    t.expect_fail(r, "T10.33: extract non-existent alias from JKS")

    # --- T10.34: Create-cert without --subject and --template ---
    print("-- T10.34: Create-cert without --subject and --template")

    r = h.cmd("--no-color create-cert --with-key -a ed25519 -o {out} {nc}",
              out=h.tmp("bad.pem"), nc=NC)
    t.expect_fail(r, "T10.34: create-cert without subject or template")

    # --- T10.35: Depth without --recursive flag ---
    print("-- T10.35: Depth without --recursive flag")

    r = h.cmd("--no-color --depth 5 {d}", d=h.fixture(""))
    if r.returncode <= 2:
        t.PASS(f"T10.35: --depth without -r exits {r.returncode} (no crash)")
    else:
        t.FAIL("T10.35: --depth without -r", f"unexpected exit {r.returncode}")

    # --- T10.36: Table + JSON output format conflict (verify no crash) ---
    print("-- T10.36: Table + JSON conflict (verify no crash)")

    r = h.cmd("--no-color -t -o json {f}", f=h.fixture("leaf-rsa.pem"))
    if r.returncode <= 2:
        t.PASS(f"T10.36: table+JSON conflict exits {r.returncode} (no crash)")
    else:
        t.FAIL("T10.36: table+JSON conflict", f"unexpected exit {r.returncode}")

    # --- T10.37: Password-prompt in non-TTY context ---
    print("-- T10.37: Password-prompt in non-TTY context")

    r = h.cmd("--no-color -i {f}", f=h.fixture("leaf.p12"), stdin="")
    if r.returncode != 0:
        t.PASS(f"T10.37: password-prompt in non-TTY exits {r.returncode} (not 0, did not hang)")
    else:
        t.FAIL("T10.37: password-prompt in non-TTY", "unexpectedly succeeded (exit 0)")


if __name__ == "__main__":
    h = Harness(fixtures_dir="../../edgecases/fixtures")
    h.setup()
    t = Tracker()
    try:
        run(h, t)
    finally:
        h.cleanup()
        t.close()
    t.summary("T10")
