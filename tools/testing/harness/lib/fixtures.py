import hashlib
import shutil
import tempfile
from pathlib import Path

from .certfactory import CertFactory
from .harness import Harness, _find_repo_root
from .proc import CmdRunner


EDGE_FIXTURES_DIR = _find_repo_root() / "tools" / "testing" / "edgecases" / "fixtures"


def generate_edge_fixtures(cmd, output_dir):
    f = CertFactory(cmd, output_dir)

    print("--- Standard materials ---")

    root_cert, root_key = f.create_ca("root-ca",
        "CN=EdgeTest Root CA,O=EdgeTest", algo="rsa", size=4096, days=3650)
    inter_cert, inter_key = f.create_ca("inter-ca",
        "CN=EdgeTest Intermediate CA,O=EdgeTest", algo="rsa", size=2048,
        days=1825, path_length=0, sign_ca=root_cert, sign_key=root_key)

    leaf_rsa, leaf_rsa_key = f.create_cert("leaf-rsa", "CN=edge.test",
        san="DNS:edge.test,DNS:*.edge.test,IP:127.0.0.1",
        sign_ca=inter_cert, sign_key=inter_key)
    leaf_ec, leaf_ec_key = f.create_cert("leaf-ec", "CN=edge-ec.test",
        algo="ecdsa", curve="p256", san="DNS:edge-ec.test",
        sign_ca=inter_cert, sign_key=inter_key)
    leaf_ed, leaf_ed_key = f.create_cert("leaf-ed", "CN=edge-ed.test",
        algo="ed25519", san="DNS:edge-ed.test",
        sign_ca=inter_cert, sign_key=inter_key)
    f.create_cert("self-signed", "CN=self-signed.test",
        san="DNS:self-signed.test")

    # expired: started 2020-01-01, valid 1 day
    f.create_cert("expired", "CN=expired.test", algo="ed25519",
        extra_args=["--not-before", "2020-01-01", "--days", "1"])

    print("--- Weird bundles and exotic files ---")

    # chain variants
    f.concat("chain-full.pem", root_cert, inter_cert, leaf_rsa)
    f.concat("chain-reversed.pem", leaf_rsa, inter_cert, root_cert)
    f.concat("chain-shuffled.pem", inter_cert, root_cert, leaf_rsa)
    f.concat("chain-duplicates.pem", root_cert, inter_cert, leaf_rsa, inter_cert, leaf_rsa)
    f.concat("chain-with-keys.pem", leaf_rsa, leaf_rsa_key, inter_cert, inter_key, root_cert)

    # key-only PEM files
    f.copy(leaf_rsa_key, "lone-key.pem")
    f.concat("multi-key.pem", leaf_rsa_key, leaf_ec_key, leaf_ed_key)

    # cert + CSR in one PEM
    tmp_csr = f.create_csr("_tmp_csr.pem", "CN=mixed-csr")
    f.concat("cert-and-csr.pem", leaf_rsa, tmp_csr)

    # empty/garbage files
    f.write("empty.pem", "# this PEM file has no blocks\n")
    f.random_bytes("garbage.bin", 1024)
    f.touch("zero-byte.pem")
    f.write("almost-pem.pem",
        "-----BEGIN CERTIFICATE-----\n!!!THIS_IS_NOT_BASE64!!!\n-----END CERTIFICATE-----\n")

    # truncated DER
    full_der = f.convert(leaf_rsa, "_full.der", "der")
    f.truncate(full_der, "truncated.der", 50)

    # cert with very long CN and many SANs
    long_cn = "a" * 200
    many_sans = ",".join(f"DNS:s{i}.edge.test" for i in range(50))
    f.create_cert("huge-subject", f"CN={long_cn}", algo="ed25519", san=many_sans)

    # UTF-8 subject
    f.create_cert("unicode-subject", "CN=Pruefung,O=Oesterreich", algo="ed25519")

    # multiple wildcard SANs
    f.create_cert("wildcard-multi", "CN=wildcard-multi.test", algo="ed25519",
        san="DNS:*.a.com,DNS:*.b.com,DNS:a.com")

    # IP-only SANs
    f.create_cert("ip-only-san", "CN=ip-only.test", algo="ed25519",
        san="IP:10.0.0.1,IP:192.168.1.1")

    # email and URI SANs
    f.create_cert("email-san", "CN=email-uri.test", algo="ed25519",
        san="email:test@example.com,URI:https://example.com")

    # no-CN cert (SANs only) -- best effort
    try:
        cmd.run("create-cert", "--with-key", "-a", "ed25519",
                "--san", "DNS:sans-only.com,DNS:www.sans-only.com", "--days", "365",
                "-o", str(f.path("no-cn.pem")), "--key-output", str(f.path("no-cn.key")),
                "--no-confirm", check=True)
    except RuntimeError:
        try:
            cmd.run("create-cert", "--with-key", "-a", "ed25519",
                    "--subject", "CN=", "--san", "DNS:sans-only.com", "--days", "365",
                    "-o", str(f.path("no-cn.pem")), "--key-output", str(f.path("no-cn.key")),
                    "--no-confirm", check=True)
        except RuntimeError:
            print("WARN: could not create no-cn cert, using placeholder")
            f.copy(leaf_rsa, "no-cn.pem")

    # CA with pathlen=0
    f.create_cert("ca-pathlen-zero", "CN=CA-PathLen0", algo="ed25519",
        extra_args=["--ca", "--path-length", "0"])

    print("--- Format variants ---")

    f.convert(leaf_rsa, "leaf.der", "der")

    f.bundle([leaf_rsa, leaf_rsa_key], "leaf.p12", fmt="pkcs12", password="test")

    # empty password p12
    try:
        cmd.run("bundle", str(leaf_rsa), str(leaf_rsa_key),
                "-f", "pkcs12", "-o", str(f.path("leaf-nopass.p12")),
                "--no-confirm", stdin="\n", check=True)
    except RuntimeError:
        print("WARN: could not create empty-password p12, skipping")

    f.bundle([root_cert, inter_cert, leaf_rsa, leaf_rsa_key],
        "chain.p12", fmt="pkcs12", password="chain")

    f.bundle([root_cert, inter_cert, leaf_rsa],
        "certs-only.p7b", fmt="pkcs7")

    f.bundle([leaf_rsa, leaf_rsa_key],
        "leaf.jks", fmt="jks", password="jkspass", alias="mykey")

    # multi-entry JKS (single entry copy for now)
    f.bundle([leaf_rsa, leaf_rsa_key],
        "multi.jks", fmt="jks", password="jkspass", alias="server")

    # legacy PKCS#12
    f.bundle([leaf_rsa, leaf_rsa_key],
        "legacy.p12", fmt="pkcs12", password="test", legacy=True)

    # encrypted PEM key
    f.create_key("leaf-encrypted.pem", encrypt=True, password="keypass")

    print("--- CSR fixtures ---")

    f.create_csr("basic.csr", "CN=basic-csr", algo="rsa")
    f.create_csr("ec.csr", "CN=ec-csr", algo="ecdsa")
    f.create_csr("ed.csr", "CN=ed-csr", algo="ed25519")
    f.create_csr("csr.der", "CN=der-csr", algo="ed25519", fmt="der")
    f.create_csr("rich.csr", "CN=rich-csr,O=Rich Org,OU=Unit,L=City,C=US",
        algo="ed25519", san="DNS:rich.test,DNS:www.rich.test,IP:10.0.0.1,email:rich@test.com")

    print("--- Directory structures ---")

    # deep nesting
    f.mkdir("deep", "a", "b", "c", "d", "e")
    f.copy(leaf_rsa, "deep/a/b/c/d/e/leaf.pem")

    # symlink loop (skip on Windows)
    import sys
    f.mkdir("loopy")
    f.copy(leaf_rsa, "loopy/cert.pem")
    if sys.platform != "win32":
        loopy_link = f.path("loopy/self")
        try:
            loopy_link.symlink_to(f.path("loopy"))
        except OSError:
            pass

    # empty tree
    f.mkdir("empty-tree", "a", "b", "c")

    # depth test
    f.mkdir("depth-test", "sub")
    f.copy(leaf_rsa, "depth-test/cert.pem")
    f.copy(leaf_ec, "depth-test/sub/cert2.pem")

    # signature scan test
    f.mkdir("sig-scan")
    f.copy(f.path("leaf.der"), "sig-scan/mystery.dat")
    f.copy(f.path("leaf.p12"), "sig-scan/archive.zip")
    f.fake_asn1("sig-scan/notacert.bin", [0x30, 0x82, 0x00, 0x10])

    # discover test
    f.mkdir("discover")
    f.copy(leaf_rsa, "discover/leaf-rsa.pem")
    f.copy(leaf_rsa_key, "discover/leaf-rsa.key")

    # discover mismatch
    f.mkdir("discover-mismatch")
    f.copy(leaf_rsa, "discover-mismatch/leaf-rsa.pem")
    f.copy(leaf_ec_key, "discover-mismatch/leaf-ec.key")

    # PEM with garbage between blocks
    garbage_text = f.write("_garbage.txt",
        "--- random garbage text between PEM blocks ---\nthis is not PEM data\n")
    f.concat("noisy.pem", leaf_rsa, garbage_text, inter_cert)

    # CRLF line endings
    f.crlf(leaf_rsa, "crlf.pem")

    # large bundle (20 self-signed certs)
    bulk = []
    for i in range(1, 21):
        cert, _ = f.create_cert(f"_bulk_{i}", f"CN=bulk-{i}", algo="ed25519")
        bulk.append(cert)
    f.concat("big-bundle.pem", *bulk)

    # DER key
    f.create_key("leaf-key.der", algo="ecdsa", curve="p256", fmt="der")

    # encrypted root CA key
    cmd.run("reencrypt", str(root_key), "-p", "", "--new-password", "capass",
            "-o", str(f.path("root-ca-enc.key")), "--no-confirm", check=True)

    print("--- Trust store fixtures ---")

    # A JDK-shaped tree with a real JKS cacerts. This is what makes
    # `store --java-home` deterministic on every platform: without it the Java
    # store tests would depend on whichever JDKs the host happens to have.
    ts_root1, _ = f.create_ca("_ts-root1", "CN=TrustStore Root One,O=EdgeTest",
        algo="ecdsa", curve="p256", days=3650)
    ts_root2, _ = f.create_ca("_ts-root2", "CN=TrustStore Root Two,O=EdgeTest",
        algo="ecdsa", curve="p256", days=3650)
    ts_root3, _ = f.create_ca("_ts-root3", "CN=TrustStore Root Three,O=EdgeTest",
        algo="ecdsa", curve="p256", days=3650)

    f.mkdir("truststore", "fake-java-home", "lib", "security")
    f.bundle([ts_root1, ts_root2, ts_root3],
             "truststore/fake-java-home/lib/security/cacerts",
             fmt="jks", password="changeit")

    # cacerts + jssecacerts side by side: Java prefers jssecacerts, and
    # certdiag must warn about the override.
    f.mkdir("truststore", "fake-java-home-jsse", "lib", "security")
    f.bundle([ts_root1],
             "truststore/fake-java-home-jsse/lib/security/cacerts",
             fmt="jks", password="changeit")
    f.bundle([ts_root1, ts_root2],
             "truststore/fake-java-home-jsse/lib/security/jssecacerts",
             fmt="jks", password="changeit")

    # A cacerts that does not use the default password.
    f.mkdir("truststore", "fake-java-home-badpw", "lib", "security")
    f.bundle([ts_root1],
             "truststore/fake-java-home-badpw/lib/security/cacerts",
             fmt="jks", password="notchangeit")

    # Custom CA bundles for --trust-file.
    f.concat("truststore/ca-bundle-3roots.pem", ts_root1, ts_root2, ts_root3)
    f.touch("truststore/ca-bundle-empty.pem")
    f.write("truststore/ca-bundle-corrupt.pem",
            "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n")

    # A chain for the verify matrix.
    v_root, v_root_key = f.create_ca("_v-root", "CN=Verify Root CA,O=EdgeTest",
        algo="ecdsa", curve="p256", days=3650)
    v_inter, v_inter_key = f.create_ca("_v-inter", "CN=Verify Intermediate CA,O=EdgeTest",
        algo="ecdsa", curve="p256", days=1825, sign_ca=v_root, sign_key=v_root_key)
    v_leaf, _ = f.create_cert("_v-leaf", "CN=verify.test",
        algo="ecdsa", curve="p256", san="DNS:verify.test",
        sign_ca=v_inter, sign_key=v_inter_key)
    v_expired, _ = f.create_cert("_v-expired", "CN=verify-expired.test",
        algo="ecdsa", curve="p256", san="DNS:verify-expired.test",
        sign_ca=v_root, sign_key=v_root_key,
        extra_args=["--not-before", "2020-01-01", "--days", "1"])

    f.mkdir("truststore", "verify-chain")
    f.copy(v_root, "truststore/verify-chain/root.pem")
    f.copy(v_inter, "truststore/verify-chain/intermediate.pem")
    f.copy(v_leaf, "truststore/verify-chain/leaf.pem")
    f.copy(v_expired, "truststore/verify-chain/leaf-expired.pem")
    f.concat("truststore/verify-chain/leaf-with-inter.pem", v_leaf, v_inter)

    # cleanup temp files
    for tmp in f.dir.glob("_*"):
        if tmp.is_file():
            tmp.unlink(missing_ok=True)
        elif tmp.is_dir():
            shutil.rmtree(tmp, ignore_errors=True)

    # cleanup stray key files from CSR generation
    for name in ["basic.key", "ec.key", "ed.key", "der-csr.key", "rich-csr.key",
                 "basic-csr.key", "ec-csr.key", "ed-csr.key", "rich.key"]:
        p = f.path(name)
        if p.exists():
            p.unlink()

    file_count = sum(1 for p in f.dir.rglob("*") if p.is_file())
    print(f"--- Fixtures generated: {file_count} files ---")


def compute_manifest(fixtures_dir):
    fixtures_dir = Path(fixtures_dir)
    lines = []
    for p in sorted(fixtures_dir.rglob("*")):
        if not p.is_file() or p.name == "fixtures.sha256":
            continue
        rel = str(p.relative_to(fixtures_dir))
        h = hashlib.sha256(p.read_bytes()).hexdigest()
        lines.append(f"{rel}\t{h}")
    return "\n".join(lines) + "\n"


def verify_fixture_hashes(fixtures_dir, manifest_path):
    fixtures_dir = Path(fixtures_dir)
    manifest_path = Path(manifest_path)

    if not manifest_path.exists():
        return ["fixtures.sha256 manifest not found"]

    expected = {}
    for line in manifest_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) == 2:
            expected[parts[0]] = parts[1]

    errors = []

    for rel_path, expected_hash in expected.items():
        full = fixtures_dir / rel_path
        if not full.is_file():
            errors.append(f"missing: {rel_path}")
            continue
        actual = hashlib.sha256(full.read_bytes()).hexdigest()
        if actual != expected_hash:
            errors.append(f"hash mismatch: {rel_path}")

    actual_files = {
        str(p.relative_to(fixtures_dir))
        for p in fixtures_dir.rglob("*") if p.is_file() and p.name != "fixtures.sha256"
    }
    manifest_files = set(expected.keys())
    extra = actual_files - manifest_files
    if extra:
        errors.append(f"untracked files not in manifest: {extra}")

    return errors


def regenerate(output_dir=None):
    output_dir = Path(output_dir) if output_dir else EDGE_FIXTURES_DIR

    # clean and recreate
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    h = Harness()
    h.setup(required_tools=["openssl"])

    generate_edge_fixtures(h.cmd, output_dir)

    # write manifest
    manifest = compute_manifest(output_dir)
    (output_dir / "fixtures.sha256").write_text(manifest)

    print(f"Manifest written: {output_dir / 'fixtures.sha256'}")
    h.cleanup()


if __name__ == "__main__":
    import sys
    if "--regenerate" in sys.argv:
        regenerate()
    else:
        print("Usage: python3 -m harness.lib.fixtures --regenerate")
