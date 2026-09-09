import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

from ..lib.harness import Harness, _find_repo_root
from ..lib.assertions import Tracker

REPO_ROOT = _find_repo_root()
SMOKE_CERTS = REPO_ROOT / "tools" / "testing" / "certs"


def _is_real_cert(path):
    p = Path(path)
    if not p.is_file() or p.stat().st_size == 0:
        return False
    try:
        first_line = p.read_text(errors="replace").split("\n", 1)[0]
        return "BEGIN" in first_line
    except Exception:
        return False



def _openssl_gen_cert(cmd, key_out, cert_out, extra_args=None):
    args = [
        "openssl", "req", "-x509",
        "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-nodes", "-keyout", str(key_out), "-out", str(cert_out),
    ]
    if extra_args:
        args.extend(extra_args)
    return cmd.tool(*args)


def run(h, t):
    print("\n=== Certificate Checks (smoke) ===")

    # -- Expiry Checks --
    print("\n--- Expiry Checks ---")

    # expired (started 2020-01-01, valid 1 day -> expired 2020-01-02)
    expired_crt = h.tmp("smoke", "expired.pem")
    expired_key = h.tmp("smoke", "expired.key")
    h.cmd("create-cert --with-key -a ed25519 --subject CN=expired.example.com "
          "--not-before 2020-01-01 --days 1 -o {cert} --key-output {key} --no-confirm",
          cert=expired_crt, key=expired_key)
    r = h.cmd("check --no-color {cert}", cert=expired_crt)
    t.expect_exit(2, r, "expired cert returns exit 2 (critical)")
    t.assert_contains_regex(r, r"Expired", "expired cert flagged")

    # expiring_soon_critical (5 days from now -> within 7-day critical threshold)
    expiring_soon_key = h.tmp("smoke", "expiring-soon.key")
    expiring_soon_crt = h.tmp("smoke", "expiring-soon.crt")
    _openssl_gen_cert(h.cmd, expiring_soon_key, expiring_soon_crt, [
        "-days", "5",
        "-subj", "/CN=expiring-soon.example.com",
        "-addext", "subjectAltName=DNS:expiring-soon.example.com",
    ])
    r = h.cmd("check --no-color {cert}", cert=expiring_soon_crt)
    t.expect_exit(2, r, "expiring-soon cert returns exit 2")
    t.assert_contains_regex(r, r"Expires in", "expiring-soon flagged")

    # expiring_soon_warning (20 days from now -> within 30-day warning threshold)
    expiring_warn_key = h.tmp("smoke", "expiring-warn.key")
    expiring_warn_crt = h.tmp("smoke", "expiring-warn.crt")
    _openssl_gen_cert(h.cmd, expiring_warn_key, expiring_warn_crt, [
        "-days", "20",
        "-subj", "/CN=expiring-warn.example.com",
        "-addext", "subjectAltName=DNS:expiring-warn.example.com",
    ])
    r = h.cmd("check --no-color {cert}", cert=expiring_warn_crt)
    t.expect_exit(1, r, "expiring-warn cert returns exit 1 (warning)")
    t.assert_contains_regex(r, r"Expires in", "expiring-warn flagged")

    # not_yet_valid (starts 30 days from now)
    future_crt = h.tmp("smoke", "future-cert.pem")
    future_key = h.tmp("smoke", "future-cert.key")
    future_start = (datetime.utcnow() + timedelta(days=30)).strftime("%Y-%m-%d")
    h.cmd("create-cert --with-key -a ed25519 --subject CN=future.example.com "
          "--not-before {start} --days 365 -o {cert} --key-output {key} --no-confirm",
          start=future_start, cert=future_crt, key=future_key)
    r = h.cmd("check --no-color {cert}", cert=future_crt)
    t.assert_contains_regex(r, r"Not yet valid", "future cert flagged")

    # -- Key Strength Checks --
    print("\n--- Key Strength Checks ---")

    weak_rsa_1024 = SMOKE_CERTS / "weak-rsa-1024.crt"
    if _is_real_cert(weak_rsa_1024):
        r = h.cmd("check --no-color {cert}", cert=weak_rsa_1024)
        t.assert_contains_regex(r, r"Weak RSA", "1024-bit RSA flagged")
    else:
        t.SKIP("weak RSA 1024 (cert not generated)")

    very_weak_rsa_512 = SMOKE_CERTS / "very-weak-rsa-512.crt"
    if _is_real_cert(very_weak_rsa_512):
        r = h.cmd("check --no-color {cert}", cert=very_weak_rsa_512)
        t.expect_exit(2, r, "512-bit RSA returns exit 2 (critical)")
        t.assert_contains_regex(r, r"Very weak RSA", "512-bit RSA flagged")
    else:
        t.SKIP("very_weak_rsa (docker not available during cert generation)")
        t.SKIP("512-bit RSA flagged")

    self_signed_rsa = SMOKE_CERTS / "self-signed-rsa.crt"
    r = h.cmd("check --no-color {cert} --category key_strength", cert=self_signed_rsa)
    t.expect_ok(r, "2048-bit RSA no key_strength issues")

    # -- Algorithm Checks --
    print("\n--- Algorithm Checks ---")

    md5_signed = SMOKE_CERTS / "md5-signed.crt"
    if _is_real_cert(md5_signed):
        r = h.cmd("check --no-color {cert}", cert=md5_signed)
        t.expect_exit(2, r, "MD5 sig returns exit 2 (critical)")
        t.assert_contains_regex(r, r"MD5", "MD5 signature flagged")
    else:
        t.SKIP("md5_sig (docker not available during cert generation)")
        t.SKIP("MD5 signature flagged")

    sha1_signed = SMOKE_CERTS / "sha1-signed.crt"
    if _is_real_cert(sha1_signed):
        r = h.cmd("check --no-color {cert}", cert=sha1_signed)
        t.assert_contains_regex(r, r"SHA-1", "SHA-1 signature flagged")
    else:
        t.SKIP("sha1_sig (docker not available during cert generation)")

    # -- Config Checks --
    print("\n--- Config Checks ---")

    self_signed_rsa_key = SMOKE_CERTS / "self-signed-rsa.key"
    r = h.cmd("check --no-color {key}", key=self_signed_rsa_key)
    t.assert_contains_regex(r, r"not password-protected", "unprotected key flagged")

    missing_san = SMOKE_CERTS / "missing-san.crt"
    if _is_real_cert(missing_san):
        r = h.cmd("check --no-color {cert}", cert=missing_san)
        t.assert_contains_regex(r, r"Missing SANs", "missing SANs flagged")
    else:
        t.SKIP("missing SANs (cert not generated)")

    ca_no_keyusage = SMOKE_CERTS / "ca-no-keyusage.crt"
    if _is_real_cert(ca_no_keyusage):
        r = h.cmd("check --no-color {cert}", cert=ca_no_keyusage)
        t.assert_contains_regex(r, r"keyCertSign", "CA without keyUsage flagged")
    else:
        t.SKIP("ca_no_keyusage (cert not generated)")

    leaf_certsign = SMOKE_CERTS / "leaf-certsign.crt"
    if _is_real_cert(leaf_certsign):
        r = h.cmd("check --no-color {cert}", cert=leaf_certsign)
        t.assert_contains_regex(r, r"keyCertSign", "leaf with keyCertSign flagged")
    else:
        t.SKIP("leaf_certsign (cert not generated)")

    ip_cn_no_san = SMOKE_CERTS / "ip-cn-no-san.crt"
    if _is_real_cert(ip_cn_no_san):
        r = h.cmd("check --no-color {cert}", cert=ip_cn_no_san)
        t.assert_contains_regex(r, r"IP address", "IP in CN flagged")
    else:
        t.SKIP("ip_in_cn (cert not generated)")

    # -- Chain Checks --
    print("\n--- Chain Checks ---")

    leaf_crt = SMOKE_CERTS / ".ca" / "leaf.crt"
    r = h.cmd("check --no-color {cert}", cert=leaf_crt)
    t.assert_contains_regex(r, r"Chain incomplete", "standalone leaf flagged as incomplete")

    key_cert_mismatch = SMOKE_CERTS / "key-cert-mismatch.pem"
    if key_cert_mismatch.is_file() and key_cert_mismatch.stat().st_size > 0:
        r = h.cmd("check --no-color {cert}", cert=key_cert_mismatch)
        t.assert_contains_regex(r, r"does not match any certificate", "key-cert mismatch flagged")
    else:
        t.SKIP("key_cert_mismatch (bundle not generated)")

    ca_chain = SMOKE_CERTS / "ca-chain.pem"
    r = h.cmd("check --no-color {cert} --category chain", cert=ca_chain)
    t.assert_not_contains_regex(r, r"Chain incomplete", "full chain no incomplete warning")

    # -- Structure Checks --
    print("\n--- Structure Checks ---")

    r = h.cmd("check --no-color {cert} --category structure", cert=self_signed_rsa)
    t.expect_ok(r, "365-day cert has no structure issues")

    # -- Info Checks --
    print("\n--- Info Checks ---")

    if _is_real_cert(missing_san):
        r = h.cmd("check --no-color {cert} --category info", cert=missing_san)
        t.assert_contains_regex(r, r"Self-signed leaf", "self-signed leaf flagged")
    else:
        t.SKIP("self-signed leaf (cert not generated)")

    wildcard = SMOKE_CERTS / "wildcard.crt"
    if _is_real_cert(wildcard):
        r = h.cmd("check --no-color {cert}", cert=wildcard)
        t.assert_contains_regex(r, r"Wildcard", "wildcard cert flagged")
    else:
        t.SKIP("wildcard (cert not generated)")

    # -- Output Format Checks --
    print("\n--- Output Format Checks ---")

    r = h.cmd("check --no-color {cert} -o json", cert=self_signed_rsa)
    t.assert_contains(r, "files_scanned", "JSON output has files_scanned")

    t.assert_json(r, "JSON output is valid")

    r_yaml = h.cmd("check --no-color {cert} -o yaml", cert=self_signed_rsa)
    t.assert_contains(r_yaml, "files_scanned", "YAML output has files_scanned")

    r = h.cmd("check --no-color {cert} --severity critical", cert=self_signed_rsa)
    t.expect_ok(r, "severity critical on info-only cert returns 0")

    r = h.cmd("check --no-color {cert} --category expiry", cert=self_signed_rsa)
    t.expect_ok(r, "valid cert in expiry category returns 0")

    # Disabled check via config file
    disable_cfg = h.tmp("smoke", "disable-test.yaml")
    disable_cfg.write_text(
        "defaults:\n"
        "  check:\n"
        "    disabled_checks:\n"
        '      - "self_signed_leaf"\n'
    )
    r = h.cmd("check --no-color {cert} --category info", cert=self_signed_rsa,
              env_extra={"CERTDIAG_CONFIG": str(disable_cfg)})
    t.assert_not_contains_regex(r, r"Self-signed leaf", "disabled check does not fire")

    # --list-checks
    r = h.cmd("check --list-checks")
    t.expect_ok(r, "list-checks exits 0")
    t.assert_contains_regex(r, r"expired", "list-checks shows expired check")
    t.assert_contains_regex(r, r"wildcard", "list-checks shows wildcard check")

    # -- Extra Certificate Information --
    print("\n--- Extra Certificate Information ---")

    r = h.cmd("{cert} --details", cert=self_signed_rsa,
              env_extra={"NO_COLOR": "1"})
    t.assert_contains_regex(r, r"v3|Version.*3", "Version shown in details")

    extra_ext = SMOKE_CERTS / "extra-ext.crt"
    if extra_ext.is_file():
        r = h.cmd("{cert} --details", cert=extra_ext,
                  env_extra={"NO_COLOR": "1"})
        t.assert_contains(r, "crl.example.com", "CRL Distribution Points shown")
        t.assert_contains(r, "ocsp.example.com", "OCSP server shown in AIA")
        t.assert_contains_regex(r, r"ca\.example\.com/intermediate", "CA Issuers shown in AIA")

        r_default = h.cmd("{cert}", cert=extra_ext,
                          env_extra={"NO_COLOR": "1"})
        t.assert_contains(r_default, "ca.example.com", "Issuer Alt Name shown in default view")

        r_json = h.cmd("{cert} -o json", cert=extra_ext)
        try:
            data = r_json.json()
            cert_obj = data["files"][0]["items"][0]["certificate"]

            if "version" in cert_obj:
                t.PASS("JSON has version field")
            else:
                t.FAIL("JSON has version field", "missing")

            cdp = cert_obj.get("crl_distribution_points", [])
            if cdp and len(cdp) > 0:
                t.PASS("JSON has CRL dist points")
            else:
                t.FAIL("JSON has CRL dist points", "missing")

            ocsp = cert_obj.get("ocsp_servers", [])
            if ocsp and len(ocsp) > 0:
                t.PASS("JSON has OCSP servers")
            else:
                t.FAIL("JSON has OCSP servers", "missing")

            ian = cert_obj.get("issuer_alt_names", [])
            if ian and len(ian) > 0:
                t.PASS("JSON has issuer alt names")
            else:
                t.FAIL("JSON has issuer alt names", "missing")
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as e:
            t.FAIL("JSON field checks", f"parse error: {e}")

        r_yaml = h.cmd("{cert} -o yaml", cert=extra_ext)
        t.assert_contains(r_yaml, "crl_distribution_points", "YAML has CRL dist points")
        t.assert_contains(r_yaml, "ocsp_servers", "YAML has OCSP servers")
        t.assert_contains(r_yaml, "issuer_alt_names", "YAML has issuer alt names")

        r_diff = h.cmd("diff {a} {b}", a=extra_ext, b=self_signed_rsa)
        t.assert_contains_regex(r_diff, r"Issuer Alt", "Diff shows IAN field")
    else:
        t.SKIP("Extra extension tests (extra-ext.crt not generated)")
        t.SKIP("CRL Distribution Points shown")
        t.SKIP("OCSP server shown in AIA")
        t.SKIP("CA Issuers shown in AIA")
        t.SKIP("Issuer Alt Name shown in default view")
        t.SKIP("JSON field checks")
        t.SKIP("YAML field checks")
        t.SKIP("Diff shows IAN field")

    # cert without CDP/AIA does NOT show those fields
    r = h.cmd("{cert} --details", cert=self_signed_rsa,
              env_extra={"NO_COLOR": "1"})
    t.assert_not_contains(r, "CRL Dist", "Self-signed cert has no CRL Dist Points")
    t.assert_not_contains_regex(r, r"Auth Info|OCSP", "Self-signed cert has no AIA")


if __name__ == "__main__":
    h = Harness(fixtures_dir=SMOKE_CERTS)
    h.setup(required_tools=["openssl"])
    t = Tracker()
    try:
        run(h, t)
    finally:
        h.cleanup()
    ok = t.summary("smoke_certchecks")
    sys.exit(0 if ok else 1)
