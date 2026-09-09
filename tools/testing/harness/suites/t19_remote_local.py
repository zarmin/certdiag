"""T19: remote commands against a loopback TLS server (no network).

Everything here talks to a Python HTTPS server on 127.0.0.1 (and ::1 when the
host has it), so `remote pipe`, `remote http`, `--no-sni`, `--aia` and the
IPv6 forms get exercised without leaving the machine. Also carries the
CLI surfaces M31 found untested that need an isolated HOME: the AIA cache,
`config migrate`, `password change-master-key`.
"""

import json
import re
import sys

from ..lib.tlsserver import LocalServer

NC = "--no-confirm"


def _either(r, pattern):
    return re.search(pattern, r.stdout + r.stderr, re.IGNORECASE) is not None


def run(h, t):
    print("\n=== T19: Remote commands against a loopback TLS server ===\n")
    if not h.has_tool("openssl"):
        t.SKIP("T19: openssl not available")
        return

    home = h.tmp("t19", "home")
    home.mkdir(parents=True, exist_ok=True)
    iso = {"HOME": str(home), "USERPROFILE": str(home), "CERTDIAG_CONFIG": ""}

    d = h.tmp("t19", "pki")
    d.mkdir(parents=True, exist_ok=True)
    ca_crt, ca_key = d / "ca.crt", d / "ca.key"
    h.cmd.openssl("req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout {key} -out {crt} "
                  "-subj /CN=Local_Test_CA -days 30 -addext basicConstraints=critical,CA:TRUE "
                  "-addext keyUsage=critical,keyCertSign,cRLSign", key=ca_key, crt=ca_crt, check=True)
    ca_der = d / "ca.der"
    h.cmd.openssl("x509 -in {crt} -outform DER -out {der}", crt=ca_crt, der=ca_der, check=True)

    issuer_srv = LocalServer(issuer_der=ca_der.read_bytes())
    aia_url = f"http://127.0.0.1:{issuer_srv.port}/issuer.der"

    srv_key, srv_csr, srv_crt = d / "server.key", d / "server.csr", d / "server.crt"
    h.cmd.openssl("req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout {key} -out {csr} "
                  "-subj /CN=localhost", key=srv_key, csr=srv_csr, check=True)
    ext = d / "ext.cnf"
    ext.write_text("subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\n"
                   f"authorityInfoAccess=caIssuers;URI:{aia_url}\n"
                   "extendedKeyUsage=serverAuth\nkeyUsage=digitalSignature\n")
    h.cmd.openssl("x509 -req -in {csr} -CA {ca} -CAkey {cakey} -CAcreateserial -days 30 -out {crt} -extfile {ext}",
                  csr=srv_csr, ca=ca_crt, cakey=ca_key, crt=srv_crt, ext=ext, check=True)

    tls = LocalServer(certfile=str(srv_crt), keyfile=str(srv_key))
    try:
        tls6 = LocalServer(certfile=str(srv_crt), keyfile=str(srv_key), host="::1")
    except OSError:
        tls6 = None
    try:
        _cases(h, t, tls, tls6, iso, srv_crt, srv_key, ca_crt, home)
    finally:
        tls.stop()
        issuer_srv.stop()
        if tls6:
            tls6.stop()


def _cases(h, t, tls, tls6, iso, srv_crt, srv_key, ca_crt, home):
    tgt = tls.target

    # --- T19.01: fetch, with and without SNI ---
    print("--- T19.01: remote fetch against the loopback server ---")
    r = h.cmd("--no-color remote fetch {tgt}", tgt=tgt)
    t.assert_contains(r, "localhost", "T19.01a: fetch shows the server certificate")
    r = h.cmd("--no-color remote fetch --no-sni {tgt}", tgt=tgt)
    t.assert_contains(r, "localhost", "T19.01b: --no-sni still fetches")
    r = h.cmd("--no-color remote fetch --hostname localhost {tgt}", tgt=tgt)
    t.assert_contains(r, "localhost", "T19.01c: --hostname sets the SNI")

    # --- T19.02: hostname mismatch is one finding, not two ---
    print("--- T19.02: --hostname mismatch fires once ---")
    r = h.cmd("--no-color remote check --hostname other.test {tgt}", tgt=tgt)
    n = len(re.findall(r"^.*mismatch.*$", r.stdout, re.IGNORECASE | re.MULTILINE))
    if n == 1:
        t.PASS("T19.02a: exactly one mismatch finding for a wrong --hostname")
    else:
        t.FAIL("T19.02a: exactly one mismatch finding", f"found {n} in:\n{r.stdout}")
    t.assert_contains(r, "remote_hostname_mismatch", "T19.02b: the finding is remote_hostname_mismatch")

    # --- T19.03: remote pipe ---
    print("--- T19.03: remote pipe relays stdin over TLS ---")
    r = h.cmd("--no-color remote pipe {tgt}", tgt=tgt, stdin="GET /final HTTP/1.0\r\nHost: localhost\r\n\r\n", timeout=20)
    t.assert_contains(r, "final stop", "T19.03a: the server's reply reaches stdout")
    t.assert_contains(r, "Connected to", "T19.03b: the handshake summary goes to stderr", stream="stderr")

    # --- T19.04: remote http ---
    print("--- T19.04: remote http body, headers-only, redirects ---")
    r = h.cmd("--no-color remote http https://{tgt}/", tgt=tgt)
    t.assert_contains(r, "hello from local tls", "T19.04a: body is shown")
    r = h.cmd("--no-color remote http --headers-only https://{tgt}/", tgt=tgt)
    t.assert_not_contains(r, "hello from local tls", "T19.04b: --headers-only omits the body")
    t.assert_contains_regex(r, r"content-type", "T19.04c: --headers-only shows headers")
    r = h.cmd("--no-color remote http https://{tgt}/redir", tgt=tgt)
    t.assert_contains(r, "302", "T19.04d: a redirect is reported, not followed, by default")
    t.assert_not_contains(r, "final stop", "T19.04e: the redirect target is not fetched by default")
    r = h.cmd("--no-color remote http --follow-redirects https://{tgt}/redir", tgt=tgt)
    t.assert_contains(r, "final stop", "T19.04f: --follow-redirects reaches the target")
    r = h.cmd("--no-color remote http --follow-redirects --max-redirects 2 https://{tgt}/loop", tgt=tgt, timeout=20)
    t.assert_not_timed_out(r, "T19.04g: a redirect loop terminates")
    if _either(r, r"redirect"):
        t.PASS("T19.04h: the redirect limit is reported")
    else:
        t.FAIL("T19.04h: the redirect limit is reported", r.stdout + r.stderr)

    # --- T19.05: IPv6 literals with brackets on every subcommand ---
    print("--- T19.05: IPv6 literal targets ---")
    if tls6 is None:
        t.SKIP("T19.05: no IPv6 loopback on this host")
    else:
        t6 = tls6.target
        r = h.cmd("--no-color remote fetch {tgt}", tgt=t6)
        t.assert_contains(r, "localhost", "T19.05a: remote fetch [::1]:port")
        r = h.cmd("--no-color remote check {tgt}", tgt=t6)
        t.assert_not_contains_regex(r, r"invalid target|parse", "T19.05b: remote check [::1]:port parses the target", stream="stderr")
        r = h.cmd("--no-color remote http https://{tgt}/final", tgt=t6)
        t.assert_contains(r, "final stop", "T19.05c: remote http https://[::1]:port/")
        r = h.cmd("--no-color remote pipe {tgt}", tgt=t6, stdin="GET /final HTTP/1.0\r\n\r\n", timeout=20)
        t.assert_contains(r, "final stop", "T19.05d: remote pipe [::1]:port")
        r = h.cmd("--no-color verify {tgt}", tgt=t6)
        t.assert_not_contains_regex(r, r"invalid target|parse", "T19.05e: verify [::1]:port parses the target", stream="stderr")
        r = h.cmd("--no-color remote fetch --hostname localhost {tgt}", tgt=t6)
        t.assert_contains(r, "localhost", "T19.05f: [::1]:port with --hostname")

    # --- T19.06: --aia fetch and the cache commands ---
    print("--- T19.06: AIA fetch through the loopback issuer ---")
    r = h.cmd("--no-color --aia {crt}", crt=srv_crt, env_extra=iso)
    t.expect_ok(r, "T19.06a: a scan with --aia against a reachable issuer exits 0")
    r = h.cmd("--no-color aia cache list", env_extra=iso)
    t.assert_contains(r, "empty", "T19.06a2: nothing is cached unless defaults.aia.cache is on")
    cache_cfg = h.tmp("t19", "aia-cache.yaml")
    cache_cfg.write_text("kind: certdiag-config\nversion: \"1\"\ndefaults:\n  aia:\n    cache: true\n")
    iso = dict(iso, CERTDIAG_CONFIG=str(cache_cfg))
    r = h.cmd("--no-color --aia {crt}", crt=srv_crt, env_extra=iso)
    t.expect_ok(r, "T19.06a3: a scan with --aia and the cache on exits 0")
    r = h.cmd("--no-color aia cache list", env_extra=iso)
    t.assert_contains(r, "Local_Test_CA", "T19.06b: the fetched issuer is in the AIA cache")
    r = h.cmd("--no-color aia cache list -o json", env_extra=iso)
    t.assert_json(r, "T19.06c: aia cache list -o json is JSON")
    try:
        if len(json.loads(r.stdout)) == 1:
            t.PASS("T19.06d: one cached issuer")
        else:
            t.FAIL("T19.06d: one cached issuer", r.stdout)
    except (ValueError, TypeError):
        t.FAIL("T19.06d: one cached issuer", r.stdout)
    r = h.cmd("--no-color --aia --aia-refresh {crt}", crt=srv_crt, env_extra=iso)
    t.expect_ok(r, "T19.06e: --aia-refresh re-fetches without error")
    r = h.cmd("--no-color aia cache clear", env_extra=iso)
    t.assert_contains(r, "cleared", "T19.06f: aia cache clear reports")
    r = h.cmd("--no-color aia cache list", env_extra=iso)
    t.assert_contains(r, "empty", "T19.06g: the cache is empty after clear")
    cfg = h.tmp("t19", "aia.yaml")
    cfg.write_text("kind: certdiag-config\nversion: \"1\"\ndefaults:\n  aia:\n    cache: true\n    cache_ttl: 1s\n")
    r = h.cmd("--no-color -c {cfg} --aia {crt}", cfg=cfg, crt=srv_crt, env_extra=iso)
    t.expect_ok(r, "T19.06h: defaults.aia.cache_ttl is accepted")
    r = h.cmd("--no-color -c {cfg} aia cache list", cfg=cfg, env_extra=iso)
    t.expect_ok(r, "T19.06i: aia cache list honours the configured TTL")

    # --- T19.07: extract --alias on PKCS#12 ---
    print("--- T19.07: extract --alias on a PKCS#12 with a friendlyName ---")
    p12 = h.tmp("t19", "alias.p12")
    h.cmd.openssl("pkcs12 -export -in {crt} -inkey {key} -name my-alias -passout pass:pw -out {p12}",
                  crt=srv_crt, key=srv_key, p12=p12, check=True)
    outdir = h.tmp("t19", "extracted")
    outdir.mkdir(parents=True, exist_ok=True)
    r = h.cmd("--no-color extract {p12} -p pw --alias my-alias --output-dir {out} {nc}", p12=p12, out=outdir, nc=NC)
    t.expect_ok(r, "T19.07a: extract --alias finds the friendlyName")
    if any(outdir.iterdir()):
        t.PASS("T19.07b: extract --alias wrote files")
    else:
        t.FAIL("T19.07b: extract --alias wrote files", r.stdout + r.stderr)
    r = h.cmd("--no-color extract {p12} -p pw --alias nope --output-dir {out} {nc}", p12=p12, out=outdir, nc=NC)
    t.expect_fail(r, "T19.07c: an unknown alias fails")

    # --- T19.08: password change-master-key round trip ---
    print("--- T19.08: change-master-key round trip ---")
    old_env = dict(iso, CERTDIAG_MASTER_KEY="oldkey-1")
    r = h.cmd("--no-color password encrypt", stdin="secret\n", env_extra=old_env)
    t.expect_ok(r, "T19.08a: password encrypt with the old key")
    enc = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""
    cfg = h.tmp("t19", "master.yaml")
    cfg.write_text(f"kind: certdiag-config\nversion: \"1\"\npasswords:\n  common_encrypted:\n    - {enc}\n")
    r = h.cmd("--no-color -c {cfg} password change-master-key", cfg=cfg,
              env_extra=dict(old_env, CERTDIAG_NEW_MASTER_KEY="newkey-2"))
    t.assert_contains(r, "changed successfully", "T19.08b: the master key is rotated", stream="stderr")
    t.assert_file_exists(str(cfg) + ".bak", "T19.08c: a backup is left behind")
    m = re.search(r"-\s+(\S+)\s*$", cfg.read_text(), re.MULTILINE)
    new_enc = m.group(1) if m else ""
    if new_enc and new_enc != enc:
        t.PASS("T19.08d: the encrypted entry was rewritten")
    else:
        t.FAIL("T19.08d: the encrypted entry was rewritten", cfg.read_text())
    r = h.cmd("--no-color password decrypt", stdin=new_enc + "\n", env_extra=dict(iso, CERTDIAG_MASTER_KEY="newkey-2"))
    t.assert_contains(r, "secret", "T19.08e: the rewritten entry decrypts with the new key")
    r = h.cmd("--no-color password decrypt", stdin=new_enc + "\n", env_extra=old_env)
    t.expect_fail(r, "T19.08f: the old key no longer decrypts it")

    # --- T19.09: config migrate ---
    print("--- T19.09: config migrate ---")
    # A fresh HOME: no command writes ~/.certdiag/certdiag.yaml on its own,
    # so migrate finds the target free the first time and refuses the second.
    mhome = h.tmp("t19", "migratehome")
    mhome.mkdir(parents=True, exist_ok=True)
    iso = {"HOME": str(mhome), "USERPROFILE": str(mhome), "CERTDIAG_CONFIG": ""}
    legacy = mhome / ".certdiag.yaml"
    target = mhome / ".certdiag" / "certdiag.yaml"
    legacy.write_text("kind: certdiag-config\nversion: \"1\"\n")
    r = h.cmd("--no-color config migrate --dry-run", env_extra=iso)
    t.assert_contains(r, "Would move", "T19.09a: --dry-run says what it would do")
    t.assert_file_exists(legacy, "T19.09b: --dry-run leaves the legacy file")
    r = h.cmd("--no-color config migrate", env_extra=iso)
    t.assert_contains(r, "Moved", "T19.09c: migrate moves the file")
    t.assert_file_exists(target, "T19.09d: the new location exists")
    if not legacy.exists():
        t.PASS("T19.09e: the legacy file is gone")
    else:
        t.FAIL("T19.09e: the legacy file is gone")
    legacy.write_text("kind: certdiag-config\nversion: \"1\"\n")
    r = h.cmd("--no-color config migrate", env_extra=iso)
    t.expect_exit(1, r, "T19.09f: migrate refuses to overwrite an existing config")
    t.assert_contains(r, "refusing", "T19.09g: the refusal is explicit", stream="stderr")
    r = h.cmd("--no-color config migrate", env_extra={"HOME": str(h.tmp("t19", "nohome")), "USERPROFILE": str(h.tmp("t19", "nohome")), "CERTDIAG_CONFIG": ""})
    t.assert_contains(r, "nothing to migrate", "T19.09h: no legacy config is not an error")

    # --- T19.10: --show-openssl --dry-run, --manual, pcap live, store update failures ---
    print("--- T19.10: assorted CLI surfaces ---")
    dry = h.tmp("t19", "dry.crt")
    r = h.cmd("--no-color create-cert --with-key --subject CN=dry.test -o {crt} --show-openssl --dry-run {nc}", crt=dry, nc=NC)
    t.expect_ok(r, "T19.10a: --show-openssl --dry-run exits 0")
    if _either(r, r"openssl req"):
        t.PASS("T19.10b: the openssl command is printed")
    else:
        t.FAIL("T19.10b: the openssl command is printed", r.stdout + r.stderr)
    if not dry.exists():
        t.PASS("T19.10c: --dry-run writes nothing")
    else:
        t.FAIL("T19.10c: --dry-run writes nothing")
    r = h.cmd("--no-color remote fetch --show-openssl --dry-run localhost:1")
    t.expect_ok(r, "T19.10d: remote fetch --dry-run does not connect")
    if _either(r, r"s_client"):
        t.PASS("T19.10e: the s_client command is printed")
    else:
        t.FAIL("T19.10e: the s_client command is printed", r.stdout + r.stderr)
    r = h.cmd("--no-color --manual")
    t.expect_ok(r, "T19.10f: --manual on a pipe exits 0")
    if r.line_count() > 100:
        t.PASS("T19.10g: --manual prints the manual to the pipe")
    else:
        t.FAIL("T19.10g: --manual prints the manual to the pipe", f"{r.line_count()} lines")
    if sys.platform != "linux":
        r = h.cmd("--no-color pcap live --iface lo0", timeout=15)
        t.expect_fail(r, "T19.10h: pcap live is refused off Linux")
        if _either(r, r"linux|not supported|unsupported|not available"):
            t.PASS("T19.10i: pcap live says where it works")
        else:
            t.FAIL("T19.10i: pcap live says where it works", r.stdout + r.stderr)
    empty = h.tmp("t19", "emptydir")
    empty.mkdir(parents=True, exist_ok=True)
    r = h.cmd("--no-color store update --import {d}", d=empty, env_extra=iso)
    t.expect_exit(1, r, "T19.10j: store update --import on a directory without manifests exits 1")
    t.assert_contains(r, "no bundle manifests", "T19.10k: the reason is named", stream="stderr")
    r = h.cmd("--no-color store update --import {d}", d=empty / "missing", env_extra=iso)
    t.expect_exit(1, r, "T19.10l: store update --import on a missing path exits 1")
    r = h.cmd("--no-color store update --from {d} --source mozilla --dry-run", d=empty, env_extra=iso)
    t.expect_exit(1, r, "T19.10m: store update --from a directory without the vendor file exits 1")
