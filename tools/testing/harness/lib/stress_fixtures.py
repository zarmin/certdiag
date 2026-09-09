import shutil
import tempfile
from pathlib import Path

from .certfactory import CertFactory
from .harness import Harness, _find_repo_root
from .proc import CmdRunner


STRESS_CERTS_DIR = _find_repo_root() / "tools" / "testing" / "stresstest" / "certs"

VALIDITY_DAYS = 3650

PKCS12_SPECS = [
    # (name, algo, cn, password, chain_type, extra_opts)
    ("stress-01.p12", "rsa2048", "Stress 01 RSA Self-Signed", "alpine-thunder-01", "self", {}),
    ("stress-02.p12", "ecp256", "Stress 02 EC256 Self-Signed", "blazing-river-02", "self", {}),
    ("stress-03.p12", "rsa4096", "Stress 03 RSA4096 Self-Signed", "crystal-meadow-03", "self", {"iterations": 100000}),
    ("stress-04.p12", "ecp384", "Stress 04 EC384 Self-Signed", "dusty-canyon-04", "self", {}),
    ("stress-05.p12", "rsa2048", "Stress 05 RSA CA-Signed", "ember-forest-05", "ca", {"iterations": 200000}),
    ("stress-06.pfx", "rsa2048", "Stress 06 RSA PFX", "frozen-galaxy-06", "self", {}),
    ("stress-07.p12", "ecp256", "Stress 07 EC256 CA-Signed", "golden-harbor-07", "ca", {}),
    ("stress-08.p12", "rsa2048", "Stress 08 RSA Legacy 3DES", "hidden-island-08", "self", {"legacy": True}),
    ("stress-09.p12", "rsa2048", "Stress 09 RSA Multi-SAN", "iron-jungle-09", "self", {"iterations": 300000}),
    ("stress-10.p12", "rsa2048", "Stress 10 RSA Wildcard", "jade-kingdom-10", "self", {"iterations": 600000}),
]

PEM_SPECS = [
    # (name_prefix, algo, cn, password, iterations)
    ("stress-21", "rsa2048", "Stress 21 Encrypted PEM RSA", "upper-valley-21", 100000),
    ("stress-22", "ecp256", "Stress 22 Encrypted PEM EC256", "vivid-whisper-22", 200000),
    ("stress-23", "rsa4096", "Stress 23 Encrypted PEM RSA4096", "wild-xenon-23", 300000),
    ("stress-24", "ecp384", "Stress 24 Encrypted PEM EC384", "yellow-zenith-24", None),
    ("stress-25", "rsa2048", "Stress 25 Encrypted PEM RSA", "amber-breeze-25", 600000),
]

PASSWORDS_CONTENT = """\
decoy-alpha-99
alpine-thunder-01
blazing-river-02
decoy-bravo-98
crystal-meadow-03
dusty-canyon-04
decoy-charlie-97
ember-forest-05
frozen-galaxy-06
golden-harbor-07
decoy-delta-96
hidden-island-08
iron-jungle-09
decoy-echo-95
jade-kingdom-10
keen-lagoon-11
lunar-mountain-12
decoy-foxtrot-94
misty-nebula-13
noble-ocean-14
olive-prairie-15
decoy-golf-93
polar-quartz-16
quiet-ridge-17
decoy-hotel-92
rapid-summit-18
silent-tundra-19
topaz-umbra-20
decoy-india-91
upper-valley-21
vivid-whisper-22
wild-xenon-23
decoy-juliet-90
yellow-zenith-24
amber-breeze-25
"""


def generate_stress_fixtures(cmd, output_dir):
    output_dir = Path(output_dir)
    f = CertFactory(cmd, output_dir)
    work_dir = Path(tempfile.mkdtemp(prefix="stress_work_"))
    work = CertFactory(cmd, work_dir)

    try:
        print("=== Generating stress test certificates ===")

        # --- Internal CA ---
        print("[CA] Generating root CA...")
        ca_cert, ca_key = work.openssl_selfsigned("root-ca",
            subject="CN=Stress Test Root CA,O=CertDiag Stress Test")

        print("[CA] Generating intermediate CA...")
        # CSR for intermediate
        cmd.tool("openssl", "req", "-newkey", "rsa:2048",
                 "-keyout", str(work.path("int-ca.key")),
                 "-out", str(work.path("int-ca.csr")),
                 "-noenc", "-subj", "/CN=Stress Test Intermediate CA/O=CertDiag Stress Test",
                 check=True)
        # sign intermediate
        cmd.tool("openssl", "x509", "-req",
                 "-in", str(work.path("int-ca.csr")),
                 "-CA", str(ca_cert), "-CAkey", str(ca_key),
                 "-CAcreateserial",
                 "-out", str(work.path("int-ca.crt")),
                 "-days", str(VALIDITY_DAYS),
                 "-extfile", "/dev/stdin",
                 stdin="basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign",
                 check=True)

        work.concat("ca-chain.crt", work.path("int-ca.crt"), ca_cert)

        # --- PKCS#12 bundles (01-10) ---
        for name, algo, cn, password, chain_type, opts in PKCS12_SPECS:
            idx = name.split("-")[1].split(".")[0]
            print(f"[{idx}] {name}")
            cert, key = work.openssl_selfsigned(f"s{idx}", algo=algo, subject=f"CN={cn}")

            if chain_type == "ca":
                # generate CA-signed cert instead
                cmd.tool("openssl", "req", "-newkey",
                         "rsa:2048" if "rsa" in algo else f"ec",
                         *(["-pkeyopt", f"ec_paramgen_curve:P-{algo[3:]}"] if "ec" in algo else []),
                         "-keyout", str(work.path(f"s{idx}.key")),
                         "-out", str(work.path(f"s{idx}.csr")),
                         "-noenc", "-subj", f"/CN={cn}",
                         check=True)
                cmd.tool("openssl", "x509", "-req",
                         "-in", str(work.path(f"s{idx}.csr")),
                         "-CA", str(work.path("int-ca.crt")),
                         "-CAkey", str(work.path("int-ca.key")),
                         "-CAcreateserial",
                         "-out", str(work.path(f"s{idx}.crt")),
                         "-days", str(VALIDITY_DAYS),
                         check=True)
                cert = work.path(f"s{idx}.crt")
                key = work.path(f"s{idx}.key")

            chain = work.path("ca-chain.crt") if chain_type == "ca" else None
            f.openssl_pkcs12(name, cert, key, password,
                            chain=chain,
                            iterations=opts.get("iterations"),
                            legacy=opts.get("legacy", False))

        # --- JKS bundles (11-20) ---
        print("[11] stress-11.jks -- RSA 2048, single entry")
        cert11, key11 = work.openssl_selfsigned("s11", subject="CN=Stress 11 JKS Single")
        work_p12_11 = work.openssl_pkcs12("s11.p12", cert11, key11, "keen-lagoon-11", alias="stress11")
        f.keytool_import_p12(work_p12_11, "keen-lagoon-11",
                             f.path("stress-11.jks"), "keen-lagoon-11")

        print("[12] stress-12.jks -- RSA 2048, 2 entries")
        cert12a, key12a = work.openssl_selfsigned("s12a", subject="CN=Stress 12 Entry A")
        cert12b, key12b = work.openssl_selfsigned("s12b", subject="CN=Stress 12 Entry B")
        work.openssl_pkcs12("s12a.p12", cert12a, key12a, "lunar-mountain-12", alias="entry-a")
        work.openssl_pkcs12("s12b.p12", cert12b, key12b, "lunar-mountain-12", alias="entry-b")
        f.keytool_import_p12(work.path("s12a.p12"), "lunar-mountain-12",
                             f.path("stress-12.jks"), "lunar-mountain-12")
        f.keytool_import_p12(work.path("s12b.p12"), "lunar-mountain-12",
                             f.path("stress-12.jks"), "lunar-mountain-12")

        print("[13] stress-13.jks -- RSA via keytool")
        f.keytool_genkeypair("stress-13.jks", "stress13", "misty-nebula-13",
                             "CN=Stress 13 Keytool RSA")

        print("[14] stress-14.jks -- truststore (cert-only)")
        cert14, _ = work.openssl_selfsigned("s14", subject="CN=Stress 14 Truststore Cert")
        # create empty JKS then import cert
        f.keytool_importcert(f.path("stress-14.jks"), "trusted", cert14, "noble-ocean-14")

        print("[15] stress-15.jks -- 2 mixed entries")
        cert15a, key15a = work.openssl_selfsigned("s15a", subject="CN=Stress 15 Keypair")
        cert15b, _ = work.openssl_selfsigned("s15b", subject="CN=Stress 15 Trusted Cert")
        work.openssl_pkcs12("s15a.p12", cert15a, key15a, "olive-prairie-15", alias="keypair")
        f.keytool_import_p12(work.path("s15a.p12"), "olive-prairie-15",
                             f.path("stress-15.jks"), "olive-prairie-15")
        f.keytool_importcert(f.path("stress-15.jks"), "trusted", cert15b, "olive-prairie-15")

        print("[16] stress-16.jks -- long CN")
        f.keytool_genkeypair("stress-16.jks", "stress16", "polar-quartz-16",
                             "CN=Stress 16 Very Long Common Name For Testing Display Truncation In TUI And CLI Output Modes")

        print("[17] stress-17.jks -- RSA 2048, single keytool entry")
        f.keytool_genkeypair("stress-17.jks", "stress17", "quiet-ridge-17",
                             "CN=Stress 17 JKS Keytool")

        print("[18] stress-18.jks -- RSA 2048, keypair + trusted cert")
        f.keytool_genkeypair("stress-18.jks", "keypair", "rapid-summit-18",
                             "CN=Stress 18 JKS Keypair")
        cert18t, _ = work.openssl_selfsigned("s18t", subject="CN=Stress 18 Trusted Cert")
        f.keytool_importcert(f.path("stress-18.jks"), "trusted", cert18t, "rapid-summit-18")

        print("[19] stress-19.jks -- truststore (2 trusted certs)")
        cert19a, _ = work.openssl_selfsigned("s19a", subject="CN=Stress 19 Trusted Cert A")
        cert19b, _ = work.openssl_selfsigned("s19b", subject="CN=Stress 19 Trusted Cert B")
        f.keytool_importcert(f.path("stress-19.jks"), "trusted-a", cert19a, "silent-tundra-19")
        f.keytool_importcert(f.path("stress-19.jks"), "trusted-b", cert19b, "silent-tundra-19")

        print("[20] stress-20.jks -- 3 keypair entries")
        f.keytool_genkeypair("stress-20.jks", "entry-a", "topaz-umbra-20",
                             "CN=Stress 20 JKS Entry A")
        cmd.tool("keytool", "-genkeypair", "-alias", "entry-b",
                 "-keyalg", "RSA", "-keysize", "2048",
                 "-validity", str(VALIDITY_DAYS), "-dname", "CN=Stress 20 JKS Entry B",
                 "-keystore", str(f.path("stress-20.jks")), "-storetype", "JKS",
                 "-storepass", "topaz-umbra-20", "-keypass", "topaz-umbra-20", check=True)
        cmd.tool("keytool", "-genkeypair", "-alias", "entry-c",
                 "-keyalg", "RSA", "-keysize", "2048",
                 "-validity", str(VALIDITY_DAYS), "-dname", "CN=Stress 20 JKS Entry C",
                 "-keystore", str(f.path("stress-20.jks")), "-storetype", "JKS",
                 "-storepass", "topaz-umbra-20", "-keypass", "topaz-umbra-20", check=True)

        # --- Encrypted PEM pairs (21-25) ---
        for name_prefix, algo, cn, password, iters in PEM_SPECS:
            idx = name_prefix.split("-")[1]
            print(f"[{idx}] {name_prefix}.key/.crt")
            cert, key = work.openssl_selfsigned(f"s{idx}", algo=algo, subject=f"CN={cn}")
            f.openssl_pkcs8(key, f"{name_prefix}.key", password, iterations=iters)
            f.copy(cert, f"{name_prefix}.crt")

        # --- passwords.txt ---
        print("[pw] Writing passwords.txt")
        f.write("passwords.txt", PASSWORDS_CONTENT)

        file_count = sum(1 for p in output_dir.rglob("*") if p.is_file())
        print(f"\n=== Generation complete ===")
        print(f"Files: {file_count}")

    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def regenerate(output_dir=None):
    output_dir = Path(output_dir) if output_dir else STRESS_CERTS_DIR

    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    h = Harness()
    h.setup(required_tools=["openssl", "keytool"])
    generate_stress_fixtures(h.cmd, output_dir)
    h.cleanup()


if __name__ == "__main__":
    import sys
    if "--regenerate" in sys.argv:
        regenerate()
    else:
        print("Usage: python3 -m harness.lib.stress_fixtures --regenerate")
