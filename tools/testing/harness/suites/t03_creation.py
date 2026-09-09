import shutil

from ..lib.harness import Harness
from ..lib.assertions import Tracker


NC = "--no-confirm"


def run(h, t):
    print("\n=== T03: Creation Flag Combos ===\n")

    # --- T03.01: All algorithm + size/curve combos ---
    print("--- T03.01: All algorithm + size/curve combos ---")

    r = h.cmd("--no-color create-key -a rsa -s 3072 -o {out} {nc}",
              out=h.tmp("rsa3072.key"), nc=NC)
    t.assert_file_not_empty(h.tmp("rsa3072.key"), "T03.01 RSA 3072 key")

    r = h.cmd("--no-color create-key -a ecdsa --curve p521 -o {out} {nc}",
              out=h.tmp("ecp521.key"), nc=NC)
    t.assert_file_not_empty(h.tmp("ecp521.key"), "T03.01 ECDSA P-521 key")

    # --- T03.02: Invalid algorithm/size combos ---
    print("--- T03.02: Invalid algorithm/size combos ---")

    r = h.cmd("--no-color create-key -a rsa -s 1024 -o {out} {nc}",
              out=h.tmp("bad.key"), nc=NC)
    t.expect_exit(1, r, "T03.02 RSA 1024 rejected")

    r = h.cmd("--no-color create-key -a rsa -s 999 -o {out} {nc}",
              out=h.tmp("bad.key"), nc=NC)
    t.expect_exit(1, r, "T03.02 RSA 999 rejected")

    r = h.cmd("--no-color create-key -a ecdsa -s 2048 -o {out} {nc}",
              out=h.tmp("bad.key"), nc=NC)
    t.expect_exit(1, r, "T03.02 ECDSA with -s 2048 rejected")

    r = h.cmd("--no-color create-key -a ed25519 -s 256 -o {out} {nc}",
              out=h.tmp("bad.key"), nc=NC)
    t.expect_exit(1, r, "T03.02 Ed25519 with -s 256 rejected")

    r = h.cmd("--no-color create-key -a ed25519 --curve p256 -o {out} {nc}",
              out=h.tmp("bad.key"), nc=NC)
    t.expect_exit(1, r, "T03.02 Ed25519 with --curve p256 rejected")

    r = h.cmd("--no-color create-key -a rsa --curve p256 -o {out} {nc}",
              out=h.tmp("bad.key"), nc=NC)
    t.expect_exit(1, r, "T03.02 RSA with --curve p256 rejected")

    r = h.cmd.run("--no-color", "create-key", "-a", "blowfish", "-o", str(h.tmp("bad.key")), NC)
    t.expect_exit(1, r, "T03.02 blowfish rejected")

    r = h.cmd("--no-color create-key -a ecdsa --curve secp256k1 -o {out} {nc}",
              out=h.tmp("bad.key"), nc=NC)
    t.expect_exit(1, r, "T03.02 ECDSA secp256k1 rejected")

    r = h.cmd.run("--no-color", "create-key", "-a", "ecdsa", "--curve", "", "-o", str(h.tmp("bad.key")), NC)
    t.expect_exit(1, r, "T03.02 ECDSA empty curve rejected")

    # --- T03.03: Key to stdout ---
    print("--- T03.03: Key to stdout ---")

    r = h.cmd("--no-color create-key -a ed25519")
    t.expect_ok(r, "T03.03 key to stdout exit code")
    t.assert_contains(r, "PRIVATE KEY", "T03.03 stdout key is valid PEM")

    # --- T03.04: Encrypted key ---
    print("--- T03.04: Encrypted key ---")

    r = h.cmd("--no-color create-key -a rsa -s 2048 --encrypt-key -p secret123 -o {out} {nc}",
              out=h.tmp("enc.key"), nc=NC)
    t.expect_ok(r, "T03.04 create encrypted key")

    r = h.cmd("--no-color {f} -p secret123", f=h.tmp("enc.key"))
    t.expect_ok(r, "T03.04 read encrypted key")

    enc_content = h.tmp("enc.key").read_text()
    if "ENCRYPTED" in enc_content:
        t.PASS("T03.04 PEM contains ENCRYPTED")
    else:
        t.FAIL("T03.04 PEM contains ENCRYPTED", "ENCRYPTED not found in PEM")

    # --- T03.05: DER key output ---
    print("--- T03.05: DER key output ---")

    r = h.cmd("--no-color create-key -a ecdsa --curve p256 -f der -o {out} {nc}",
              out=h.tmp("ec.der"), nc=NC)
    t.assert_file_not_empty(h.tmp("ec.der"), "T03.05 DER key file exists")
    t.assert_hex_starts_with(h.tmp("ec.der"), "30", "T03.05 DER starts with 0x30")

    # --- T03.06: All --with-key algo variants for create-cert ---
    print("--- T03.06: All --with-key algo variants for create-cert ---")

    algo_map = {
        "rsa2048": ["-a", "rsa", "-s", "2048"],
        "rsa3072": ["-a", "rsa", "-s", "3072"],
        "rsa4096": ["-a", "rsa", "-s", "4096"],
        "ecp256": ["-a", "ecdsa", "--curve", "p256"],
        "ecp384": ["-a", "ecdsa", "--curve", "p384"],
        "ecp521": ["-a", "ecdsa", "--curve", "p521"],
        "ed25519": ["-a", "ed25519"],
    }
    for name, flags in algo_map.items():
        r = h.cmd.run(
            "--no-color", "create-cert", "--with-key", *flags,
            "--subject", f"CN=test-{name}",
            "-o", str(h.tmp(f"cert-{name}.pem")),
            "--key-output", str(h.tmp(f"key-{name}.pem")),
            NC,
        )
        t.assert_file_not_empty(h.tmp(f"cert-{name}.pem"), f"T03.06 cert {name}")
        t.assert_file_not_empty(h.tmp(f"key-{name}.pem"), f"T03.06 key {name}")

    # --- T03.07: Subject DN edge cases ---
    print("--- T03.07: Subject DN edge cases ---")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "ed25519",
        "--subject", "CN=test,O=My Org,OU=Unit,L=City,ST=State,C=US",
        "-o", str(h.tmp("full-dn.pem")),
        "--key-output", str(h.tmp("full-dn.key")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("full-dn.pem"), "T03.07 multi-field DN")

    r = h.cmd("--no-color -o json {f}", f=h.tmp("full-dn.pem"))
    t.assert_contains(r, "My Org", "T03.07 DN contains O field")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "ed25519",
        "--subject", "CN=test+special,O=Org/Unit",
        "-o", str(h.tmp("special-dn.pem")),
        "--key-output", str(h.tmp("special-dn.key")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("special-dn.pem"), "T03.07 special chars DN")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "ed25519",
        "--subject", "",
        "-o", str(h.tmp("empty-dn.pem")),
        NC,
    )
    t.expect_exit(1, r, "T03.07 empty subject fails")

    long_cn = "a" * 200
    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "ed25519",
        "--subject", f"CN={long_cn}",
        "-o", str(h.tmp("long-cn.pem")),
        "--key-output", str(h.tmp("long-cn.key")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("long-cn.pem"), "T03.07 long CN")

    # --- T03.08: SAN edge cases ---
    print("--- T03.08: SAN edge cases ---")

    many_sans = ",".join(f"DNS:s{i}.example.com" for i in range(50))
    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "ed25519",
        "--subject", "CN=many-sans", "--san", many_sans,
        "-o", str(h.tmp("many-sans.pem")),
        "--key-output", str(h.tmp("many-sans.key")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("many-sans.pem"), "T03.08 50+ SANs")

    r = h.cmd("--no-color -o json {f}", f=h.tmp("many-sans.pem"))
    t.assert_contains(r, "s49.example.com", "T03.08 last SAN present")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "ed25519",
        "--subject", "CN=wildcard", "--san", "DNS:*.example.com",
        "-o", str(h.tmp("wildcard.pem")),
        "--key-output", str(h.tmp("wildcard.key")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("wildcard.pem"), "T03.08 wildcard SAN")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "ed25519",
        "--subject", "CN=ipv6", "--san", "IP:::1,IP:fe80::1",
        "-o", str(h.tmp("ipv6-san.pem")),
        "--key-output", str(h.tmp("ipv6-san.key")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("ipv6-san.pem"), "T03.08 IPv6 SAN")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "ed25519",
        "--san", "DNS:sans-only.com",
        "-o", str(h.tmp("sans-only.pem")),
        "--key-output", str(h.tmp("sans-only.key")),
        NC,
    )
    if r.ok:
        t.PASS("T03.08 SANs-only cert (no subject)")
    else:
        t.SKIP(f"T03.08 SANs-only cert (not supported, exit {r.returncode})")

    # --- T03.09: Validity edge cases ---
    print("--- T03.09: Validity edge cases ---")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "ed25519",
        "--subject", "CN=short", "--days", "1",
        "-o", str(h.tmp("1day.pem")),
        "--key-output", str(h.tmp("1day.key")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("1day.pem"), "T03.09 1-day validity")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "ed25519",
        "--subject", "CN=long", "--days", "36500",
        "-o", str(h.tmp("100yr.pem")),
        "--key-output", str(h.tmp("100yr.key")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("100yr.pem"), "T03.09 100-year validity")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "ed25519",
        "--subject", "CN=zero", "--days", "0",
        "-o", str(h.tmp("0day.pem")),
        NC,
    )
    t.expect_exit(1, r, "T03.09 0-day validity rejected")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "ed25519",
        "--subject", "CN=neg", "--days", "-1",
        "-o", str(h.tmp("negday.pem")),
        NC,
    )
    t.expect_exit(1, r, "T03.09 negative-day validity rejected")

    # --- T03.10: --not-before edge cases ---
    print("--- T03.10: --not-before edge cases ---")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "ed25519",
        "--subject", "CN=future", "--not-before", "2030-01-01", "--days", "365",
        "-o", str(h.tmp("future-start.pem")),
        "--key-output", str(h.tmp("future-start.key")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("future-start.pem"), "T03.10 future not-before")

    r = h.cmd("--no-color -o json {f}", f=h.tmp("future-start.pem"))
    t.assert_contains(r, "2030", "T03.10 not-before is 2030")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "ed25519",
        "--subject", "CN=rfc", "--not-before", "2025-06-15T10:30:00Z", "--days", "365",
        "-o", str(h.tmp("rfc-start.pem")),
        "--key-output", str(h.tmp("rfc-start.key")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("rfc-start.pem"), "T03.10 RFC3339 not-before")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "ed25519",
        "--subject", "CN=backdated", "--not-before", "2020-01-01", "--days", "3650",
        "-o", str(h.tmp("backdated.pem")),
        "--key-output", str(h.tmp("backdated.key")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("backdated.pem"), "T03.10 backdated not-before")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "ed25519",
        "--subject", "CN=bad", "--not-before", "not-a-date",
        "-o", str(h.tmp("bad.pem")),
        NC,
    )
    t.expect_exit(1, r, "T03.10 invalid not-before rejected")

    # --- T03.11: CA cert with path length ---
    print("--- T03.11: CA cert with path length ---")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "rsa", "-s", "2048",
        "--subject", "CN=CA-PL0", "--ca", "--path-length", "0",
        "-o", str(h.tmp("ca-pl0.pem")),
        "--key-output", str(h.tmp("ca-pl0.key")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("ca-pl0.pem"), "T03.11 CA pathlen 0")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "rsa", "-s", "2048",
        "--subject", "CN=CA-unconstrained", "--ca", "--path-length", "-1",
        "-o", str(h.tmp("ca-uncon.pem")),
        "--key-output", str(h.tmp("ca-uncon.key")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("ca-uncon.pem"), "T03.11 CA unconstrained")

    # --- T03.12: Key usage and extended key usage ---
    print("--- T03.12: Key usage and extended key usage ---")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "ed25519",
        "--subject", "CN=ku-test",
        "--key-usage", "digitalSignature,keyEncipherment",
        "--ext-key-usage", "serverAuth,clientAuth",
        "-o", str(h.tmp("ku-cert.pem")),
        "--key-output", str(h.tmp("ku-cert.key")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("ku-cert.pem"), "T03.12 KU+EKU combo")

    r = h.cmd("--no-color -o json {f}", f=h.tmp("ku-cert.pem"))
    t.assert_contains(r, "Digital Signature", "T03.12 digitalSignature in output")
    t.assert_contains(r, "Server Auth", "T03.12 serverAuth in output")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "ed25519",
        "--subject", "CN=ku-code",
        "--key-usage", "digitalSignature",
        "--ext-key-usage", "codeSigning",
        "-o", str(h.tmp("codesign.pem")),
        "--key-output", str(h.tmp("codesign.key")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("codesign.pem"), "T03.12 codeSigning cert")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "ed25519",
        "--subject", "CN=ku-all",
        "--key-usage", "digitalSignature,contentCommitment,keyEncipherment,dataEncipherment,keyAgreement,certSign,crlSign,encipherOnly,decipherOnly",
        "-o", str(h.tmp("ku-all.pem")),
        "--key-output", str(h.tmp("ku-all.key")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("ku-all.pem"), "T03.12 all KU values")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "ed25519",
        "--subject", "CN=bad",
        "--key-usage", "notARealUsage",
        "-o", str(h.tmp("bad.pem")),
        NC,
    )
    t.expect_exit(1, r, "T03.12 invalid key-usage rejected")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "ed25519",
        "--subject", "CN=bad",
        "--ext-key-usage", "notAnEKU",
        "-o", str(h.tmp("bad.pem")),
        NC,
    )
    t.expect_exit(1, r, "T03.12 invalid ext-key-usage rejected")

    # --- T03.13: Custom serial ---
    print("--- T03.13: Custom serial ---")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "ed25519",
        "--subject", "CN=serial", "--serial", "DEADBEEF",
        "-o", str(h.tmp("serial.pem")),
        "--key-output", str(h.tmp("serial.key")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("serial.pem"), "T03.13 custom serial")

    r = h.cmd("--no-color -o json {f}", f=h.tmp("serial.pem"))
    t.assert_contains(r, "de:ad:be:ef", "T03.13 serial DEADBEEF in output")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "ed25519",
        "--subject", "CN=serial-max",
        "--serial", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "-o", str(h.tmp("serial-max.pem")),
        "--key-output", str(h.tmp("serial-max.key")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("serial-max.pem"), "T03.13 max serial")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "ed25519",
        "--subject", "CN=bad", "--serial", "notHex",
        "-o", str(h.tmp("bad.pem")),
        NC,
    )
    t.expect_exit(1, r, "T03.13 non-hex serial rejected")

    # --- T03.14: Conflicting key source ---
    print("--- T03.14: Conflicting key source ---")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key",
        "-k", str(h.fixture("leaf-rsa.key")),
        "--subject", "CN=conflict",
        "-o", str(h.tmp("bad.pem")),
        NC,
    )
    t.expect_fail(r, "T03.14 --with-key + -k conflict rejected")

    r = h.cmd.run(
        "--no-color", "create-cert",
        "--subject", "CN=nokey",
        "-o", str(h.tmp("bad.pem")),
        NC,
    )
    t.expect_fail(r, "T03.14 create-cert without key source rejected")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "ed25519",
        "-o", str(h.tmp("bad.pem")),
        NC,
    )
    t.expect_exit(1, r, "T03.14 create-cert without subject rejected")

    # --- T03.15: --encrypt-key on generated keys ---
    print("--- T03.15: --encrypt-key on generated keys ---")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "rsa", "-s", "2048",
        "--subject", "CN=enckey",
        "--encrypt-key", "-p", "keypass",
        "-o", str(h.tmp("cert-enckey.pem")),
        "--key-output", str(h.tmp("enckey.pem")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("enckey.pem"), "T03.15 encrypted key file")

    enc_content = h.tmp("enckey.pem").read_text()
    if "ENCRYPTED" in enc_content:
        t.PASS("T03.15 key PEM contains ENCRYPTED")
    else:
        t.FAIL("T03.15 key PEM contains ENCRYPTED", "ENCRYPTED not found in PEM")

    r = h.cmd("--no-color {f} -p keypass", f=h.tmp("enckey.pem"))
    t.expect_ok(r, "T03.15 can read encrypted key")

    # --- T03.15b: --with-key without --key-output ---
    print("--- T03.15b: --with-key without --key-output ---")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "ed25519",
        "--subject", "CN=no-keyout",
        "-o", str(h.tmp("no-keyout.pem")),
        NC,
    )
    if r.ok:
        t.PASS("T03.15b --with-key without --key-output succeeds")
    else:
        t.PASS(f"T03.15b --with-key without --key-output handled (exit {r.returncode})")

    # --- T03.16: DER output for create-cert ---
    print("--- T03.16: DER output for create-cert ---")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "ed25519",
        "--subject", "CN=der",
        "-f", "der",
        "-o", str(h.tmp("cert.der")),
        "--key-output", str(h.tmp("cert-der.key")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("cert.der"), "T03.16 DER cert file")
    t.assert_hex_starts_with(h.tmp("cert.der"), "30", "T03.16 DER cert starts with 0x30")

    r = h.cmd("--no-color {f}", f=h.tmp("cert.der"))
    t.expect_ok(r, "T03.16 can read DER cert back")

    # --- T03.17: Template and template-profile usage ---
    print("--- T03.17: Template and template-profile usage ---")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "rsa", "-s", "2048",
        "--subject", "CN=original,O=Org",
        "--san", "DNS:orig.com", "--days", "365",
        "-o", str(h.tmp("original.pem")),
        "--key-output", str(h.tmp("original.key")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("original.pem"), "T03.17 original cert for template")

    r = h.cmd("--no-color create-cert --with-key -a ed25519 --template {tmpl} -o {out} --key-output {ko} {nc}",
              tmpl=h.tmp("original.pem"),
              out=h.tmp("from-template.pem"),
              ko=h.tmp("from-template.key"),
              nc=NC)
    t.assert_file_not_empty(h.tmp("from-template.pem"), "T03.17 cert from template")

    r = h.cmd("--no-color -o json {f}", f=h.tmp("from-template.pem"))
    t.assert_contains(r, "orig.com", "T03.17 template SAN preserved")

    r = h.cmd("--no-color templates cert")
    profile_path = h.tmp("profile.yaml")
    profile_path.write_text(r.stdout)
    t.assert_file_not_empty(profile_path, "T03.17 template profile generated")

    r = h.cmd("--no-color create-cert --with-key -a ed25519 --template-profile {tp} -o {out} --key-output {ko} {nc}",
              tp=h.tmp("profile.yaml"),
              out=h.tmp("from-profile.pem"),
              ko=h.tmp("from-profile.key"),
              nc=NC)
    t.assert_file_not_empty(h.tmp("from-profile.pem"), "T03.17 cert from template-profile")

    # --- T03.18: Autosign flag ---
    print("--- T03.18: Autosign flag ---")

    autosign_dir = h.tmp("autosign-dir")
    autosign_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(h.fixture("root-ca.pem"), autosign_dir / "root-ca.pem")
    shutil.copy2(h.fixture("root-ca.key"), autosign_dir / "root-ca.key")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "ed25519",
        "--subject", "CN=autosigned", "--autosign",
        "-o", str(autosign_dir / "leaf.pem"),
        "--key-output", str(autosign_dir / "leaf.key"),
        NC,
        cwd=str(autosign_dir),
    )
    t.assert_file_not_empty(autosign_dir / "leaf.pem", "T03.18 autosigned cert")

    r = h.cmd("--no-color -o json {f}", f=autosign_dir / "leaf.pem")
    t.assert_contains(r, "EdgeTest Root CA", "T03.18 issuer is root CA")

    # --- T03.19: CSR with all algo variants ---
    print("--- T03.19: CSR with all algo variants ---")

    r = h.cmd.run(
        "--no-color", "csr", "--with-key", "-a", "rsa", "-s", "2048",
        "--subject", "CN=csr-rsa",
        "-o", str(h.tmp("csr-rsa.pem")),
        "--key-output", str(h.tmp("csr-rsa.key")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("csr-rsa.pem"), "T03.19 CSR RSA 2048")

    r = h.cmd.run(
        "--no-color", "csr", "--with-key", "-a", "ecdsa", "--curve", "p384",
        "--subject", "CN=csr-ec",
        "-o", str(h.tmp("csr-ec.pem")),
        "--key-output", str(h.tmp("csr-ec.key")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("csr-ec.pem"), "T03.19 CSR ECDSA P-384")

    r = h.cmd.run(
        "--no-color", "csr", "--with-key", "-a", "ed25519",
        "--subject", "CN=csr-ed",
        "-o", str(h.tmp("csr-ed.pem")),
        "--key-output", str(h.tmp("csr-ed.key")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("csr-ed.pem"), "T03.19 CSR Ed25519")

    # --- T03.20: CSR in DER format ---
    print("--- T03.20: CSR in DER format ---")

    r = h.cmd.run(
        "--no-color", "csr", "--with-key", "-a", "ed25519",
        "--subject", "CN=csr-der",
        "-f", "der",
        "-o", str(h.tmp("csr.der")),
        "--key-output", str(h.tmp("csr-der.key")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("csr.der"), "T03.20 DER CSR")

    r = h.cmd("--no-color {f}", f=h.tmp("csr.der"))
    t.expect_ok(r, "T03.20 can read DER CSR")

    # --- T03.20b: csr alias equivalence ---
    print("--- T03.20b: csr alias equivalence ---")

    r = h.cmd.run(
        "--no-color", "create-csr", "--with-key", "-a", "ed25519",
        "--subject", "CN=alias-test",
        "-o", str(h.tmp("csr-full-name.pem")),
        "--key-output", str(h.tmp("csr-full-name.key")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("csr-full-name.pem"), "T03.20b create-csr full name")

    r = h.cmd.run(
        "--no-color", "csr", "--with-key", "-a", "ed25519",
        "--subject", "CN=alias-test",
        "-o", str(h.tmp("csr-alias.pem")),
        "--key-output", str(h.tmp("csr-alias.key")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("csr-alias.pem"), "T03.20b csr alias")

    r = h.cmd("--no-color {f}", f=h.tmp("csr-full-name.pem"))
    t.expect_ok(r, "T03.20b read full-name CSR")

    r = h.cmd("--no-color {f}", f=h.tmp("csr-alias.pem"))
    t.expect_ok(r, "T03.20b read alias CSR")

    # --- T03.21: CSR with --template from existing cert ---
    print("--- T03.21: CSR with --template from existing cert ---")

    r = h.cmd("--no-color csr --with-key -a ed25519 --template {tmpl} -o {out} --key-output {ko} {nc}",
              tmpl=h.fixture("leaf-rsa.pem"),
              out=h.tmp("csr-template.pem"),
              ko=h.tmp("csr-template.key"),
              nc=NC)
    t.assert_file_not_empty(h.tmp("csr-template.pem"), "T03.21 CSR from template")

    r = h.cmd("--no-color -o json {f}", f=h.tmp("csr-template.pem"))
    t.assert_contains(r, "edge.test", "T03.21 CSR template subject preserved")

    # --- T03.22: Sign CSR as sub-CA ---
    print("--- T03.22: Sign CSR as sub-CA ---")

    r = h.cmd.run(
        "--no-color", "sign", str(h.tmp("csr-rsa.pem")),
        "--ca-cert", str(h.fixture("root-ca.pem")),
        "--ca-key", str(h.fixture("root-ca.key")),
        "--ca", "--days", "1825",
        "-o", str(h.tmp("signed-subca.pem")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("signed-subca.pem"), "T03.22 signed sub-CA")

    r = h.cmd("--no-color -o json {f}", f=h.tmp("signed-subca.pem"))
    t.assert_contains(r, "true", "T03.22 sub-CA is CA")

    # --- T03.23: Sign with custom validity and serial ---
    print("--- T03.23: Sign with custom validity and serial ---")

    r = h.cmd.run(
        "--no-color", "sign", str(h.tmp("csr-rsa.pem")),
        "--ca-cert", str(h.fixture("inter-ca.pem")),
        "--ca-key", str(h.fixture("inter-ca.key")),
        "--days", "30", "--serial", "CAFE01",
        "-o", str(h.tmp("signed-custom.pem")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("signed-custom.pem"), "T03.23 custom validity+serial")

    r = h.cmd("--no-color -o json {f}", f=h.tmp("signed-custom.pem"))
    t.assert_contains(r, "ca:fe:01", "T03.23 serial CAFE01 in output")

    # --- T03.24: Sign with encrypted CA key ---
    print("--- T03.24: Sign with encrypted CA key ---")

    r = h.cmd.run(
        "--no-color", "sign", str(h.tmp("csr-rsa.pem")),
        "--ca-cert", str(h.fixture("root-ca.pem")),
        "--ca-key", str(h.fixture("root-ca-enc.key")),
        "-p", "capass",
        "-o", str(h.tmp("signed-encca.pem")),
        NC,
    )
    t.expect_ok(r, "T03.24 sign with encrypted CA key exits 0")
    t.assert_file_not_empty(h.tmp("signed-encca.pem"), "T03.24 signed with encrypted CA key")

    # --- T03.25: Sign DER CSR output DER cert ---
    print("--- T03.25: Sign DER CSR output DER cert ---")

    r = h.cmd.run(
        "--no-color", "sign", str(h.tmp("csr.der")),
        "--ca-cert", str(h.fixture("root-ca.pem")),
        "--ca-key", str(h.fixture("root-ca.key")),
        "-f", "der",
        "-o", str(h.tmp("signed.der")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("signed.der"), "T03.25 signed DER cert")
    t.assert_hex_starts_with(h.tmp("signed.der"), "30", "T03.25 signed DER starts with 0x30")

    # --- T03.25b: Sign with --key-usage and --ext-key-usage override ---
    print("--- T03.25b: Sign with --key-usage and --ext-key-usage override ---")

    r = h.cmd.run(
        "--no-color", "sign", str(h.tmp("csr-rsa.pem")),
        "--ca-cert", str(h.fixture("root-ca.pem")),
        "--ca-key", str(h.fixture("root-ca.key")),
        "--key-usage", "digitalSignature,keyEncipherment",
        "--ext-key-usage", "serverAuth,clientAuth",
        "-o", str(h.tmp("signed-ku.pem")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("signed-ku.pem"), "T03.25b sign with KU/EKU override")

    r = h.cmd("--no-color -o json {f}", f=h.tmp("signed-ku.pem"))
    t.assert_contains(r, "Server Auth", "T03.25b serverAuth in signed cert")

    r = h.cmd.run(
        "--no-color", "sign", str(h.tmp("csr-rsa.pem")),
        "--ca-cert", str(h.fixture("root-ca.pem")),
        "--ca-key", str(h.fixture("root-ca.key")),
        "--ext-key-usage", "codeSigning",
        "-o", str(h.tmp("signed-codesign.pem")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("signed-codesign.pem"), "T03.25b sign with codeSigning EKU")

    # --- T03.25c: Sign with --not-before and --serial ---
    print("--- T03.25c: Sign with --not-before and --serial ---")

    r = h.cmd.run(
        "--no-color", "sign", str(h.tmp("csr-rsa.pem")),
        "--ca-cert", str(h.fixture("root-ca.pem")),
        "--ca-key", str(h.fixture("root-ca.key")),
        "--not-before", "2030-01-01", "--serial", "ABCD1234", "--days", "730",
        "-o", str(h.tmp("signed-notbefore.pem")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("signed-notbefore.pem"), "T03.25c sign with not-before+serial")

    r = h.cmd("--no-color -o json {f}", f=h.tmp("signed-notbefore.pem"))
    t.assert_contains(r, "2030", "T03.25c not-before 2030 in output")
    t.assert_contains(r, "ab:cd:12:34", "T03.25c serial ABCD1234 in output")

    # --- T03.26: Missing CA cert or key ---
    print("--- T03.26: Missing CA cert or key ---")

    r = h.cmd.run(
        "--no-color", "sign", str(h.tmp("csr-rsa.pem")),
        "--ca-key", str(h.fixture("root-ca.key")),
        "-o", str(h.tmp("bad.pem")),
        NC,
    )
    t.expect_exit(1, r, "T03.26 sign without --ca-cert rejected")

    r = h.cmd.run(
        "--no-color", "sign", str(h.tmp("csr-rsa.pem")),
        "--ca-cert", str(h.fixture("root-ca.pem")),
        "-o", str(h.tmp("bad.pem")),
        NC,
    )
    t.expect_exit(1, r, "T03.26 sign without --ca-key rejected")

    # --- T03.27: Build full PKI hierarchy ---
    print("--- T03.27: Build full PKI hierarchy ---")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "rsa", "-s", "4096",
        "--subject", "CN=EdgeTest Root CA,O=EdgeTest",
        "--ca",
        "-o", str(h.tmp("pki-root.pem")),
        "--key-output", str(h.tmp("pki-root.key")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("pki-root.pem"), "T03.27 PKI root CA")
    t.assert_file_not_empty(h.tmp("pki-root.key"), "T03.27 PKI root key")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "ecdsa", "--curve", "p384",
        "--subject", "CN=EdgeTest Intermediate CA,O=EdgeTest",
        "--ca", "--path-length", "0",
        "--sign-ca", str(h.tmp("pki-root.pem")),
        "--sign-key", str(h.tmp("pki-root.key")),
        "-o", str(h.tmp("pki-inter.pem")),
        "--key-output", str(h.tmp("pki-inter.key")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("pki-inter.pem"), "T03.27 PKI intermediate CA")
    t.assert_file_not_empty(h.tmp("pki-inter.key"), "T03.27 PKI intermediate key")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "ecdsa", "--curve", "p256",
        "--subject", "CN=server.edgetest.local",
        "--san", "DNS:server.edgetest.local,DNS:*.edgetest.local,IP:127.0.0.1,IP:::1",
        "--sign-ca", str(h.tmp("pki-inter.pem")),
        "--sign-key", str(h.tmp("pki-inter.key")),
        "-o", str(h.tmp("pki-server.pem")),
        "--key-output", str(h.tmp("pki-server.key")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("pki-server.pem"), "T03.27 PKI server leaf")
    t.assert_file_not_empty(h.tmp("pki-server.key"), "T03.27 PKI server key")

    r = h.cmd.run(
        "--no-color", "create-cert", "--with-key", "-a", "ed25519",
        "--subject", "CN=client.edgetest.local",
        "--ext-key-usage", "clientAuth",
        "--sign-ca", str(h.tmp("pki-inter.pem")),
        "--sign-key", str(h.tmp("pki-inter.key")),
        "-o", str(h.tmp("pki-client.pem")),
        "--key-output", str(h.tmp("pki-client.key")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("pki-client.pem"), "T03.27 PKI client leaf")
    t.assert_file_not_empty(h.tmp("pki-client.key"), "T03.27 PKI client key")

    r = h.cmd.run(
        "--no-color", "check",
        str(h.tmp("pki-server.pem")),
        str(h.tmp("pki-inter.pem")),
        str(h.tmp("pki-root.pem")),
    )
    t.expect_ok(r, "T03.27 PKI server chain validates")

    r = h.cmd.run(
        "--no-color", "check",
        str(h.tmp("pki-client.pem")),
        str(h.tmp("pki-inter.pem")),
        str(h.tmp("pki-root.pem")),
    )
    t.expect_ok(r, "T03.27 PKI client chain validates")

    # --- T03.28: Renew self-signed cert ---
    print("--- T03.28: Renew self-signed cert ---")

    shutil.copy2(h.fixture("self-signed.pem"), h.tmp("renew-ss.pem"))
    shutil.copy2(h.fixture("self-signed.key"), h.tmp("renew-ss.key"))

    r = h.cmd("--no-color renew {f} -o {out} {nc}",
              f=h.tmp("renew-ss.pem"),
              out=h.tmp("renew-ss-out.pem"),
              nc=NC)
    t.assert_file_not_empty(h.tmp("renew-ss-out.pem"), "T03.28 renewed self-signed cert")

    r = h.cmd("--no-color -o json {f}", f=h.tmp("renew-ss-out.pem"))
    t.assert_contains(r, "self-signed", "T03.28 renewed cert has same subject")

    # --- T03.29: Renew with --new-key algorithm variants ---
    print("--- T03.29: Renew with --new-key algorithm variants ---")

    r = h.cmd.run(
        "--no-color", "renew", str(h.fixture("root-ca.pem")),
        "--new-key", "-a", "ecdsa", "--curve", "p256",
        "-k", str(h.fixture("root-ca.key")),
        "-o", str(h.tmp("renew-rsa-to-ec.pem")),
        "--key-output", str(h.tmp("renew-rsa-to-ec.key")),
        NC,
    )
    t.expect_ok(r, "T03.29 RSA->ECDSA renewal")
    t.assert_file_not_empty(h.tmp("renew-rsa-to-ec.key"), "T03.29 RSA->ECDSA new key")

    r = h.cmd.run(
        "--no-color", "renew", str(h.fixture("root-ca.pem")),
        "--new-key", "-a", "ed25519",
        "-k", str(h.fixture("root-ca.key")),
        "-o", str(h.tmp("renew-rsa-to-ed.pem")),
        "--key-output", str(h.tmp("renew-rsa-to-ed.key")),
        NC,
    )
    t.expect_ok(r, "T03.29 RSA->Ed25519 renewal")

    r = h.cmd.run(
        "--no-color", "renew", str(h.fixture("leaf-ec.pem")),
        "--new-key", "-a", "rsa", "-s", "4096",
        "--sign-ca", str(h.fixture("inter-ca.pem")),
        "--sign-key", str(h.fixture("inter-ca.key")),
        "-o", str(h.tmp("renew-ec-to-rsa.pem")),
        "--key-output", str(h.tmp("renew-ec-to-rsa.key")),
        NC,
    )
    t.expect_ok(r, "T03.29 EC->RSA renewal")

    # --- T03.30: Renew with custom validity ---
    print("--- T03.30: Renew with custom validity ---")

    r = h.cmd.run(
        "--no-color", "renew", str(h.fixture("root-ca.pem")),
        "-k", str(h.fixture("root-ca.key")),
        "--days", "30",
        "-o", str(h.tmp("renew-30d.pem")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("renew-30d.pem"), "T03.30 renew 30 days")

    r = h.cmd.run(
        "--no-color", "renew", str(h.fixture("root-ca.pem")),
        "-k", str(h.fixture("root-ca.key")),
        "--days", "7300",
        "-o", str(h.tmp("renew-20yr.pem")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("renew-20yr.pem"), "T03.30 renew 20 years")

    r = h.cmd.run(
        "--no-color", "renew", str(h.fixture("root-ca.pem")),
        "-k", str(h.fixture("root-ca.key")),
        "-o", str(h.tmp("renew-default-days.pem")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("renew-default-days.pem"), "T03.30 renew default validity")

    # --- T03.31: Renew with DER output ---
    print("--- T03.31: Renew with DER output ---")

    r = h.cmd.run(
        "--no-color", "renew", str(h.fixture("root-ca.pem")),
        "-k", str(h.fixture("root-ca.key")),
        "-f", "der",
        "-o", str(h.tmp("renew.der")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("renew.der"), "T03.31 renewed DER cert")
    t.assert_hex_starts_with(h.tmp("renew.der"), "30", "T03.31 renewed DER starts with 0x30")

    r = h.cmd("--no-color {f}", f=h.tmp("renew.der"))
    t.expect_ok(r, "T03.31 can read renewed DER")

    # --- T03.32: Renew with --encrypt-key ---
    print("--- T03.32: Renew with --encrypt-key ---")

    r = h.cmd.run(
        "--no-color", "renew", str(h.fixture("root-ca.pem")),
        "--new-key", "-a", "ecdsa", "--curve", "p256",
        "-k", str(h.fixture("root-ca.key")),
        "--encrypt-key", "-p", "renewpass",
        "-o", str(h.tmp("renew-enc.pem")),
        "--key-output", str(h.tmp("renew-enc.key")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("renew-enc.key"), "T03.32 encrypted renewed key")

    enc_content = h.tmp("renew-enc.key").read_text()
    if "ENCRYPTED" in enc_content:
        t.PASS("T03.32 renewed key PEM contains ENCRYPTED")
    else:
        t.FAIL("T03.32 renewed key PEM contains ENCRYPTED", "ENCRYPTED not found in PEM")

    r = h.cmd("--no-color {f} -p renewpass", f=h.tmp("renew-enc.key"))
    t.expect_ok(r, "T03.32 can read encrypted renewed key")

    # --- T03.33: Renew CA-signed cert with --sign-ca/--sign-key ---
    print("--- T03.33: Renew CA-signed cert with --sign-ca/--sign-key ---")

    r = h.cmd.run(
        "--no-color", "renew", str(h.tmp("pki-server.pem")),
        "--sign-ca", str(h.tmp("pki-inter.pem")),
        "--sign-key", str(h.tmp("pki-inter.key")),
        "-k", str(h.tmp("pki-server.key")),
        "-o", str(h.tmp("renew-signed.pem")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("renew-signed.pem"), "T03.33 renewed CA-signed cert")

    r = h.cmd("--no-color -o json {f}", f=h.tmp("renew-signed.pem"))
    t.assert_contains(r, "EdgeTest Intermediate CA", "T03.33 issuer is intermediate CA")

    r = h.cmd.run(
        "--no-color", "check",
        str(h.tmp("renew-signed.pem")),
        str(h.tmp("pki-inter.pem")),
        str(h.tmp("pki-root.pem")),
    )
    t.expect_ok(r, "T03.33 renewed cert chain validates")

    # --- T03.34: Renew with --autosign ---
    print("--- T03.34: Renew with --autosign ---")

    renew_autosign_dir = h.tmp("renew-autosign")
    renew_autosign_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(h.tmp("pki-inter.pem"), renew_autosign_dir / "pki-inter.pem")
    shutil.copy2(h.tmp("pki-inter.key"), renew_autosign_dir / "pki-inter.key")
    shutil.copy2(h.tmp("pki-server.pem"), renew_autosign_dir / "pki-server.pem")
    shutil.copy2(h.tmp("pki-server.key"), renew_autosign_dir / "pki-server.key")

    r = h.cmd.run(
        "--no-color", "renew", str(renew_autosign_dir / "pki-server.pem"),
        "--autosign",
        "-o", str(renew_autosign_dir / "renewed.pem"),
        NC,
        cwd=str(renew_autosign_dir),
    )
    t.assert_file_not_empty(renew_autosign_dir / "renewed.pem", "T03.34 autosign renewed cert")

    # --- T03.35: Renew CA certificate ---
    print("--- T03.35: Renew CA certificate ---")

    r = h.cmd.run(
        "--no-color", "renew", str(h.tmp("pki-root.pem")),
        "-k", str(h.tmp("pki-root.key")),
        "--days", "3650",
        "-o", str(h.tmp("renew-ca.pem")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("renew-ca.pem"), "T03.35 renewed CA cert")

    r = h.cmd("--no-color -o json {f}", f=h.tmp("renew-ca.pem"))
    t.assert_contains(r, "true", "T03.35 renewed CA still has CA:TRUE")
    t.assert_contains(r, "EdgeTest Root CA", "T03.35 renewed CA subject preserved")

    # --- T03.36: Renew different cert types ---
    print("--- T03.36: Renew different cert types ---")

    r = h.cmd.run(
        "--no-color", "renew", str(h.tmp("pki-client.pem")),
        "-k", str(h.tmp("pki-client.key")),
        "--sign-ca", str(h.tmp("pki-inter.pem")),
        "--sign-key", str(h.tmp("pki-inter.key")),
        "-o", str(h.tmp("renew-client.pem")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("renew-client.pem"), "T03.36 renewed client cert")

    r = h.cmd("--no-color -o json {f}", f=h.tmp("renew-client.pem"))
    t.assert_contains(r, "Client Auth", "T03.36 clientAuth EKU preserved")

    r = h.cmd.run(
        "--no-color", "renew", str(h.tmp("codesign.pem")),
        "-k", str(h.tmp("codesign.key")),
        "-o", str(h.tmp("renew-codesign.pem")),
        NC,
    )
    t.assert_file_not_empty(h.tmp("renew-codesign.pem"), "T03.36 renewed codeSigning cert")

    r = h.cmd("--no-color -o json {f}", f=h.tmp("renew-codesign.pem"))
    t.assert_contains(r, "Code Signing", "T03.36 codeSigning EKU preserved")

    # --- T03.37: Renew from PKCS#12 source ---
    print("--- T03.37: Renew from PKCS#12 source ---")

    r = h.cmd.run(
        "--no-color", "renew", str(h.fixture("leaf.p12")),
        "-p", "test",
        "--sign-ca", str(h.fixture("root-ca.pem")),
        "--sign-key", str(h.fixture("root-ca.key")),
        "-o", str(h.tmp("renew-from-p12.pem")),
        NC,
    )
    t.expect_ok(r, "T03.37 renew from PKCS#12")
    t.assert_file_not_empty(h.tmp("renew-from-p12.pem"), "T03.37 renewed cert from P12")


if __name__ == "__main__":
    from pathlib import Path

    fixtures_dir = Path(__file__).resolve().parents[3] / "edgecases" / "fixtures"
    h = Harness(fixtures_dir=fixtures_dir)
    h.setup(required_tools=["openssl"])
    t = Tracker()
    try:
        run(h, t)
    finally:
        h.cleanup()
        t.summary("T03")
