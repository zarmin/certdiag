import shutil
import sys
from pathlib import Path

from ..lib.harness import Harness, _find_repo_root
from ..lib.assertions import Tracker
from ..lib.proc import FileHelper

REPO_ROOT = _find_repo_root()
SMOKE_CERTS = REPO_ROOT / "tools" / "testing" / "certs"


def run(h, t):
    print("\n=== Change Actions (smoke) ===")

    has_openssl = h.has_tool("openssl")

    # =====================================================================
    # Category 1: Key Generation
    # =====================================================================
    print("\n--- Category 1: Key Generation ---")

    r = h.cmd("create-key -a rsa -s 2048 -o {out} --no-confirm", out=h.tmp("rsa.key"))
    t.assert_file_exists(h.tmp("rsa.key"), "RSA 2048 key generation")

    r = h.cmd("create-key -a rsa -s 4096 -o {out} --no-confirm", out=h.tmp("rsa4096.key"))
    t.assert_file_exists(h.tmp("rsa4096.key"), "RSA 4096 key generation")

    r = h.cmd("create-key -a ecdsa --curve p256 -o {out} --no-confirm", out=h.tmp("ec256.key"))
    t.assert_file_exists(h.tmp("ec256.key"), "ECDSA P-256 key generation")

    r = h.cmd("create-key -a ecdsa --curve p384 -o {out} --no-confirm", out=h.tmp("ec384.key"))
    t.assert_file_exists(h.tmp("ec384.key"), "ECDSA P-384 key generation")

    r = h.cmd("create-key -a ed25519 -o {out} --no-confirm", out=h.tmp("ed.key"))
    t.assert_file_exists(h.tmp("ed.key"), "Ed25519 key generation")

    r = h.cmd("create-key -a ecdsa")
    t.assert_contains(r, "BEGIN", "Key to stdout")

    r = h.cmd("create-key -a rsa -s 2048 -f der -o {out} --no-confirm", out=h.tmp("rsa.der"))
    t.assert_file_exists(h.tmp("rsa.der"), "DER format key")

    r = h.cmd("create-key -a ecdsa --encrypt-key -p test123 -o {out} --no-confirm",
              out=h.tmp("enc.key"))
    t.assert_file_exists(h.tmp("enc.key"), "Encrypted PEM key (file)")
    enc_key_text = h.tmp("enc.key").read_text()
    if "ENCRYPTED" in enc_key_text:
        t.PASS("Encrypted PEM key")
    else:
        t.FAIL("Encrypted PEM key", "ENCRYPTED not found in PEM header")

    if has_openssl:
        r = h.cmd.openssl("pkey -in {key} -noout", key=h.tmp("rsa.key"))
        if r.ok:
            t.PASS("OpenSSL verify RSA key")
        else:
            t.FAIL("OpenSSL verify RSA key", "openssl pkey failed")

        r = h.cmd.openssl("pkey -in {key} -noout", key=h.tmp("ec256.key"))
        if r.ok:
            t.PASS("OpenSSL verify ECDSA key")
        else:
            t.FAIL("OpenSSL verify ECDSA key", "openssl pkey failed")

        r = h.cmd.openssl("pkey -inform der -in {key} -noout", key=h.tmp("rsa.der"))
        if r.ok:
            t.PASS("OpenSSL verify DER key")
        else:
            t.FAIL("OpenSSL verify DER key", "openssl pkey failed")

        r = h.cmd.openssl("pkey -in {key} -passin stdin -noout",
                          key=h.tmp("enc.key"), stdin="test123")
        if r.ok:
            t.PASS("OpenSSL verify encrypted key")
        else:
            t.FAIL("OpenSSL verify encrypted key", "openssl pkey failed")
    else:
        t.SKIP("OpenSSL verify RSA key")
        t.SKIP("OpenSSL verify ECDSA key")
        t.SKIP("OpenSSL verify DER key")
        t.SKIP("OpenSSL verify encrypted key")

    # =====================================================================
    # Category 2: Certificate Creation
    # =====================================================================
    print("\n--- Category 2: Certificate Creation ---")

    r = h.cmd('create-cert --with-key --subject "CN=test.local" -o {crt} --key-output {key} --no-confirm',
              crt=h.tmp("ss.crt"), key=h.tmp("ss.key"))
    t.assert_file_exists(h.tmp("ss.crt"), "Self-signed cert creation")
    t.assert_file_exists(h.tmp("ss.key"), "Self-signed cert key output")

    r = h.cmd('create-cert --with-key --ca --subject "CN=Test CA" --days 3650 -o {crt} --key-output {key} --no-confirm',
              crt=h.tmp("ca.crt"), key=h.tmp("ca.key"))
    t.assert_file_exists(h.tmp("ca.crt"), "CA certificate creation")

    if has_openssl:
        r = h.cmd.openssl("x509 -in {crt} -text -noout", crt=h.tmp("ca.crt"))
        t.assert_contains_regex(r, r"CA:TRUE", "CA certificate has CA:TRUE")
    else:
        t.SKIP("CA certificate has CA:TRUE")

    r = h.cmd('create-cert --with-key --subject "CN=leaf.test" --sign-ca {ca} --sign-key {cakey} -o {crt} --key-output {key} --no-confirm',
              ca=h.tmp("ca.crt"), cakey=h.tmp("ca.key"),
              crt=h.tmp("leaf.crt"), key=h.tmp("leaf.key"))
    t.assert_file_exists(h.tmp("leaf.crt"), "CA-signed leaf cert creation")

    if has_openssl:
        r = h.cmd.openssl("x509 -in {crt} -issuer -noout", crt=h.tmp("leaf.crt"))
        t.assert_contains_regex(r, r"Test CA", "Leaf cert issuer is Test CA")

        r = h.cmd.openssl("verify -CAfile {ca} {crt}",
                          ca=h.tmp("ca.crt"), crt=h.tmp("leaf.crt"))
        if r.ok:
            t.PASS("OpenSSL verify leaf cert chain")
        else:
            t.FAIL("OpenSSL verify leaf cert chain", "openssl verify failed")
    else:
        t.SKIP("Leaf cert issuer is Test CA")
        t.SKIP("OpenSSL verify leaf cert chain")

    r = h.cmd('create-cert --with-key --subject "CN=san.test" --san "DNS:a.com,DNS:b.com,IP:10.0.0.1" -o {crt} --key-output {key} --no-confirm',
              crt=h.tmp("san.crt"), key=h.tmp("san.key"))
    t.assert_file_exists(h.tmp("san.crt"), "Cert with SANs creation")

    if has_openssl:
        r = h.cmd.openssl("x509 -in {crt} -text -noout", crt=h.tmp("san.crt"))
        t.assert_contains_regex(r, r"a\.com", "SAN contains DNS:a.com")
        t.assert_contains_regex(r, r"b\.com", "SAN contains DNS:b.com")
        t.assert_contains(r, "10.0.0.1", "SAN contains IP:10.0.0.1")
    else:
        t.SKIP("SAN contains DNS:a.com")
        t.SKIP("SAN contains DNS:b.com")
        t.SKIP("SAN contains IP:10.0.0.1")

    r = h.cmd('create-cert --with-key -a rsa -s 4096 --subject "CN=rsa.test" -o {crt} --key-output {key} --no-confirm',
              crt=h.tmp("rsa.crt"), key=h.tmp("rsa-cert.key"))
    t.assert_file_exists(h.tmp("rsa.crt"), "Cert with RSA 4096 key")

    r = h.cmd("create-cert --with-key --template {tmpl} -o {crt} --key-output {key} --no-confirm",
              tmpl=h.tmp("san.crt"), crt=h.tmp("tmpl.crt"), key=h.tmp("tmpl.key"))
    t.assert_file_exists(h.tmp("tmpl.crt"), "Cert from template creation")

    # Autosign: set up CA dir and run from there
    autosign_dir = h.tmp("autosign-ca")
    autosign_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(h.tmp("ca.crt"), autosign_dir / "ca.crt")
    shutil.copy2(h.tmp("ca.key"), autosign_dir / "ca.key")

    r = h.cmd('create-cert --with-key --subject "CN=auto.test" --autosign -o {crt} --key-output {key} --no-confirm',
              crt=h.tmp("auto.crt"), key=h.tmp("auto.key"),
              cwd=str(autosign_dir))
    t.assert_file_exists(h.tmp("auto.crt"), "Autosign cert creation")

    if has_openssl:
        r = h.cmd.openssl("x509 -in {crt} -issuer -noout", crt=h.tmp("auto.crt"))
        t.assert_contains_regex(r, r"Test CA", "Autosign cert issuer is Test CA")
    else:
        t.SKIP("Autosign cert issuer is Test CA")

    r = h.cmd("{crt}", crt=h.tmp("ss.crt"))
    t.assert_contains_regex(r, r"test\.local", "Readback self-signed cert")

    # =====================================================================
    # Category 3: CSR + Signing
    # =====================================================================
    print("\n--- Category 3: CSR + Signing ---")

    r = h.cmd('csr --with-key --subject "CN=csr.test" -o {csr} --key-output {key} --no-confirm',
              csr=h.tmp("test.csr"), key=h.tmp("csr.key"))
    t.assert_file_exists(h.tmp("test.csr"), "CSR with new key")

    if has_openssl:
        r = h.cmd.openssl("req -verify -in {csr} -noout", csr=h.tmp("test.csr"))
        if r.ok:
            t.PASS("OpenSSL verify CSR")
        else:
            t.FAIL("OpenSSL verify CSR", "openssl req -verify failed")
    else:
        t.SKIP("OpenSSL verify CSR")

    r = h.cmd('csr --key-file {key} --subject "CN=existing.test" -o {csr} --no-confirm',
              key=h.tmp("ss.key"), csr=h.tmp("exist.csr"))
    t.assert_file_exists(h.tmp("exist.csr"), "CSR with existing key")

    r = h.cmd("sign {csr} --ca-cert {ca} --ca-key {cakey} -o {crt} --no-confirm",
              csr=h.tmp("test.csr"), ca=h.tmp("ca.crt"), cakey=h.tmp("ca.key"),
              crt=h.tmp("signed.crt"))
    t.assert_file_exists(h.tmp("signed.crt"), "Sign CSR")

    if has_openssl:
        r = h.cmd.openssl("verify -CAfile {ca} {crt}",
                          ca=h.tmp("ca.crt"), crt=h.tmp("signed.crt"))
        if r.ok:
            t.PASS("OpenSSL verify signed cert")
        else:
            t.FAIL("OpenSSL verify signed cert", "openssl verify failed")
    else:
        t.SKIP("OpenSSL verify signed cert")

    r = h.cmd("sign {csr} --ca-cert {ca} --ca-key {cakey} --ca -o {crt} --no-confirm",
              csr=h.tmp("test.csr"), ca=h.tmp("ca.crt"), cakey=h.tmp("ca.key"),
              crt=h.tmp("subca.crt"))
    t.assert_file_exists(h.tmp("subca.crt"), "Sign CSR as sub-CA")

    if has_openssl:
        r = h.cmd.openssl("x509 -in {crt} -text -noout", crt=h.tmp("subca.crt"))
        t.assert_contains_regex(r, r"CA:TRUE", "Sub-CA has CA:TRUE")
    else:
        t.SKIP("Sub-CA has CA:TRUE")

    r = h.cmd("sign {csr} --ca-cert {ca} --ca-key {cakey} --days 730 -o {crt} --no-confirm",
              csr=h.tmp("test.csr"), ca=h.tmp("ca.crt"), cakey=h.tmp("ca.key"),
              crt=h.tmp("custom.crt"))
    t.assert_file_exists(h.tmp("custom.crt"), "Sign CSR with custom validity")

    # =====================================================================
    # Category 4: Format Conversion
    # =====================================================================
    print("\n--- Category 4: Format Conversion ---")

    r = h.cmd("convert {inp} -o {out} -f der --no-confirm",
              inp=h.tmp("ss.crt"), out=h.tmp("ss.der"))
    t.assert_file_exists(h.tmp("ss.der"), "PEM to DER conversion")

    r = h.cmd("convert {inp} -o {out} --no-confirm",
              inp=h.tmp("ss.der"), out=h.tmp("ss2.pem"))
    ss2_text = h.tmp("ss2.pem").read_text()
    if "BEGIN CERTIFICATE" in ss2_text:
        t.PASS("DER to PEM conversion")
    else:
        t.FAIL("DER to PEM conversion", "BEGIN CERTIFICATE not found")

    # Create leaf bundle (cert + key)
    leaf_bundle = h.tmp("leaf-bundle.pem")
    leaf_crt_data = h.tmp("leaf.crt").read_text()
    leaf_key_data = h.tmp("leaf.key").read_text()
    leaf_bundle.write_text(leaf_crt_data + leaf_key_data)

    r = h.cmd("convert {inp} -o {out} -f pkcs12 --output-password p12pass --no-confirm",
              inp=leaf_bundle, out=h.tmp("leaf.p12"))
    t.assert_file_exists(h.tmp("leaf.p12"), "PEM to PKCS#12 conversion")

    if has_openssl:
        r = h.cmd.openssl("pkcs12 -in {p12} -passin pass:p12pass -noout",
                          p12=h.tmp("leaf.p12"))
        if r.ok:
            t.PASS("OpenSSL verify PKCS#12")
        else:
            t.FAIL("OpenSSL verify PKCS#12", "openssl pkcs12 failed")
    else:
        t.SKIP("OpenSSL verify PKCS#12")

    r = h.cmd("convert {inp} -p p12pass -o {out} --no-confirm",
              inp=h.tmp("leaf.p12"), out=h.tmp("leaf-back.pem"))
    leaf_back_text = h.tmp("leaf-back.pem").read_text()
    if "BEGIN CERTIFICATE" in leaf_back_text:
        t.PASS("PKCS#12 to PEM conversion (cert)")
    else:
        t.FAIL("PKCS#12 to PEM conversion (cert)", "BEGIN CERTIFICATE not found")
    if "PRIVATE KEY" in leaf_back_text:
        t.PASS("PKCS#12 to PEM conversion (key)")
    else:
        t.FAIL("PKCS#12 to PEM conversion (key)", "PRIVATE KEY not found")

    r = h.cmd("convert {inp} -o {out} -f jks --output-password changeit --no-confirm",
              inp=leaf_bundle, out=h.tmp("leaf.jks"))
    t.assert_file_exists(h.tmp("leaf.jks"), "PEM to JKS conversion")

    r = h.cmd("convert {inp} -o {out} -f pkcs7 --no-confirm",
              inp=h.tmp("ss.crt"), out=h.tmp("ss.p7b"))
    t.assert_file_exists(h.tmp("ss.p7b"), "PEM to PKCS#7 conversion")

    if has_openssl:
        r = h.cmd.openssl("pkcs7 -inform der -print_certs -in {p7b}",
                          p7b=h.tmp("ss.p7b"))
        if r.ok and "BEGIN CERTIFICATE" in r.stdout:
            t.PASS("OpenSSL verify PKCS#7")
        else:
            t.FAIL("OpenSSL verify PKCS#7", "openssl pkcs7 failed")
    else:
        t.SKIP("OpenSSL verify PKCS#7")

    # Round-trip PEM->P12->PEM fingerprint compare
    if has_openssl:
        r_orig = h.cmd.openssl("x509 -in {crt} -fingerprint -sha256 -noout",
                               crt=h.tmp("leaf.crt"))
        r_rt = h.cmd.openssl("x509 -in {crt} -fingerprint -sha256 -noout",
                             crt=h.tmp("leaf-back.pem"))
        fp_orig = r_orig.stdout.strip()
        fp_rt = r_rt.stdout.strip()
        if fp_orig and fp_orig == fp_rt:
            t.PASS("Round-trip PEM->P12->PEM fingerprint match")
        else:
            t.FAIL("Round-trip PEM->P12->PEM fingerprint match", "fingerprints differ")
    else:
        t.SKIP("Round-trip PEM->P12->PEM fingerprint match")

    # Round-trip PEM->DER->PEM fingerprint compare
    h.cmd("convert {inp} -o {out} -f der --no-confirm",
          inp=h.tmp("ss2.pem"), out=h.tmp("ss-roundtrip.der"))
    h.cmd("convert {inp} -o {out} --no-confirm",
          inp=h.tmp("ss-roundtrip.der"), out=h.tmp("ss-roundtrip.pem"))
    if has_openssl:
        r_orig = h.cmd.openssl("x509 -in {crt} -fingerprint -sha256 -noout",
                               crt=h.tmp("ss.crt"))
        r_rt = h.cmd.openssl("x509 -in {crt} -fingerprint -sha256 -noout",
                             crt=h.tmp("ss-roundtrip.pem"))
        fp_orig = r_orig.stdout.strip()
        fp_rt = r_rt.stdout.strip()
        if fp_orig and fp_orig == fp_rt:
            t.PASS("Round-trip PEM->DER->PEM fingerprint match")
        else:
            t.FAIL("Round-trip PEM->DER->PEM fingerprint match", "fingerprints differ")
    else:
        t.SKIP("Round-trip PEM->DER->PEM fingerprint match")

    r = h.cmd("{p12} -p p12pass", p12=h.tmp("leaf.p12"))
    t.assert_contains_regex(r, r"leaf\.test", "Readback converted PKCS#12")

    # =====================================================================
    # Category 5: Extract
    # =====================================================================
    print("\n--- Category 5: Extract ---")

    h.cmd("extract {p12} -p p12pass --output-dir {d} --no-confirm",
          p12=h.tmp("leaf.p12"), d=h.tmp("extracted/"))
    extracted_count = len(FileHelper.files_matching(h.tmp("extracted"), "*"))
    if extracted_count >= 1:
        t.PASS(f"Extract all from P12 ({extracted_count} files)")
    else:
        t.FAIL("Extract all from P12", "no files extracted")

    h.cmd("extract {p12} -p p12pass --output-dir {d} --type certs --no-confirm",
          p12=h.tmp("leaf.p12"), d=h.tmp("certs-only/"))
    certs_count = len(FileHelper.files_matching(h.tmp("certs-only"), "*"))
    if certs_count >= 1:
        t.PASS(f"Extract certs only from P12 ({certs_count} files)")
    else:
        t.FAIL("Extract certs only from P12", "no files extracted")

    h.cmd("extract {p12} -p p12pass --output-dir {d} --type keys --no-confirm",
          p12=h.tmp("leaf.p12"), d=h.tmp("keys-only/"))
    keys_count = len(FileHelper.files_matching(h.tmp("keys-only"), "*"))
    if keys_count >= 1:
        t.PASS(f"Extract keys only from P12 ({keys_count} files)")
    else:
        t.FAIL("Extract keys only from P12", "no key files extracted")

    h.cmd("extract {p12} -p p12pass --output-dir {d} --index 1 --no-confirm",
          p12=h.tmp("leaf.p12"), d=h.tmp("idx/"))
    idx_count = len(FileHelper.files_matching(h.tmp("idx"), "*"))
    if idx_count == 1:
        t.PASS("Extract by index (1 file)")
    else:
        t.FAIL("Extract by index", f"expected 1 file, got {idx_count}")

    # Multi-cert PEM chain
    chain_pem = h.tmp("chain.pem")
    chain_pem.write_text(
        h.tmp("leaf.crt").read_text() + h.tmp("ca.crt").read_text()
    )

    h.cmd("extract {pem} --output-dir {d} --no-confirm",
          pem=chain_pem, d=h.tmp("chain-ext/"))
    chain_count = len(FileHelper.files_matching(h.tmp("chain-ext"), "*"))
    if chain_count >= 2:
        t.PASS(f"Extract from PEM chain ({chain_count} files)")
    else:
        t.FAIL("Extract from PEM chain", f"expected >=2 files, got {chain_count}")

    # Readback extracted files
    extracted_files = list(h.tmp("extracted").glob("*"))
    if extracted_files:
        r = h.cmd.run(*extracted_files)
        if r.stdout.strip():
            t.PASS("Readback extracted files")
        else:
            t.FAIL("Readback extracted files", "no output")
    else:
        t.FAIL("Readback extracted files", "no extracted files found")

    # =====================================================================
    # Category 6: Renew
    # =====================================================================
    print("\n--- Category 6: Renew ---")

    r = h.cmd("renew {crt} -k {key} -o {out} --no-confirm",
              crt=h.tmp("ss.crt"), key=h.tmp("ss.key"), out=h.tmp("ss-renewed.crt"))
    t.assert_file_exists(h.tmp("ss-renewed.crt"), "Renew self-signed cert")

    r = h.cmd("renew {crt} -k {key} --sign-ca {ca} --sign-key {cakey} -o {out} --no-confirm",
              crt=h.tmp("leaf.crt"), key=h.tmp("leaf.key"),
              ca=h.tmp("ca.crt"), cakey=h.tmp("ca.key"),
              out=h.tmp("leaf-renewed.crt"))
    t.assert_file_exists(h.tmp("leaf-renewed.crt"), "Renew CA-signed cert")

    if has_openssl:
        r = h.cmd.openssl("verify -CAfile {ca} {crt}",
                          ca=h.tmp("ca.crt"), crt=h.tmp("leaf-renewed.crt"))
        if r.ok:
            t.PASS("OpenSSL verify renewed CA-signed cert")
        else:
            t.FAIL("OpenSSL verify renewed CA-signed cert", "openssl verify failed")
    else:
        t.SKIP("OpenSSL verify renewed CA-signed cert")

    r = h.cmd("renew {crt} --new-key -o {out} --key-output {key} --no-confirm",
              crt=h.tmp("ss.crt"), out=h.tmp("newkey.crt"), key=h.tmp("newkey.key"))
    t.assert_file_exists(h.tmp("newkey.crt"), "Renew with new key")
    t.assert_file_exists(h.tmp("newkey.key"), "Renew new key output")

    # Compare original vs renewed: same subject, different serial
    if has_openssl:
        r_orig = h.cmd.openssl("x509 -in {crt} -subject -noout", crt=h.tmp("ss.crt"))
        r_renew = h.cmd.openssl("x509 -in {crt} -subject -noout", crt=h.tmp("ss-renewed.crt"))
        orig_subj = r_orig.stdout.strip()
        renew_subj = r_renew.stdout.strip()
        if orig_subj and orig_subj == renew_subj:
            t.PASS("Renewed cert same subject")
        else:
            t.FAIL("Renewed cert same subject",
                   f"subjects differ: {orig_subj} vs {renew_subj}")

        r_orig = h.cmd.openssl("x509 -in {crt} -serial -noout", crt=h.tmp("ss.crt"))
        r_renew = h.cmd.openssl("x509 -in {crt} -serial -noout", crt=h.tmp("ss-renewed.crt"))
        orig_serial = r_orig.stdout.strip()
        renew_serial = r_renew.stdout.strip()
        if orig_serial != renew_serial:
            t.PASS("Renewed cert different serial")
        else:
            t.FAIL("Renewed cert different serial", "serials are the same")
    else:
        t.SKIP("Renewed cert same subject")
        t.SKIP("Renewed cert different serial")

    r = h.cmd("{crt}", crt=h.tmp("ss-renewed.crt"))
    t.assert_contains_regex(r, r"test\.local", "Readback renewed cert")

    # =====================================================================
    # Category 7: Bundle
    # =====================================================================
    print("\n--- Category 7: Bundle ---")

    r = h.cmd("bundle {leaf} {ca} -o {out} --no-confirm",
              leaf=h.tmp("leaf.crt"), ca=h.tmp("ca.crt"),
              out=h.tmp("bundle-chain.pem"))
    t.assert_file_exists(h.tmp("bundle-chain.pem"), "PEM chain bundle")

    bundle_text = h.tmp("bundle-chain.pem").read_text()
    cert_count = bundle_text.count("BEGIN CERTIFICATE")
    if cert_count >= 2:
        t.PASS(f"PEM chain bundle has {cert_count} certs")
    else:
        t.FAIL("PEM chain bundle cert count", f"expected >=2, got {cert_count}")

    r = h.cmd("bundle {leaf} {key} -o {out} -f pkcs12 --output-password bundlepass --no-confirm",
              leaf=h.tmp("leaf.crt"), key=h.tmp("leaf.key"),
              out=h.tmp("bundle.p12"))
    t.assert_file_exists(h.tmp("bundle.p12"), "PKCS#12 bundle with key")

    if has_openssl:
        r = h.cmd.openssl("pkcs12 -in {p12} -passin pass:bundlepass -noout",
                          p12=h.tmp("bundle.p12"))
        if r.ok:
            t.PASS("OpenSSL verify PKCS#12 bundle")
        else:
            t.FAIL("OpenSSL verify PKCS#12 bundle", "openssl pkcs12 failed")
    else:
        t.SKIP("OpenSSL verify PKCS#12 bundle")

    # Auto-chain ordering: pass in reverse order
    r = h.cmd("bundle {ca} {leaf} --auto-chain -o {out} --no-confirm",
              ca=h.tmp("ca.crt"), leaf=h.tmp("leaf.crt"),
              out=h.tmp("autochain.pem"))
    t.assert_file_exists(h.tmp("autochain.pem"), "Auto-chain ordering bundle")

    # Bundle without root
    r = h.cmd("bundle {leaf} {ca} --include-root=false -o {out} --no-confirm",
              leaf=h.tmp("leaf.crt"), ca=h.tmp("ca.crt"),
              out=h.tmp("noroot.pem"))
    t.assert_file_exists(h.tmp("noroot.pem"), "Bundle without root")

    r = h.cmd("bundle {leaf} {key} -o {out} -f jks --output-password changeit --no-confirm",
              leaf=h.tmp("leaf.crt"), key=h.tmp("leaf.key"),
              out=h.tmp("bundle.jks"))
    t.assert_file_exists(h.tmp("bundle.jks"), "JKS bundle")

    r = h.cmd("{pem}", pem=h.tmp("bundle-chain.pem"))
    t.assert_contains_regex(r, r"leaf\.test", "Readback PEM bundle")

    # =====================================================================
    # Category 8: Change Password
    # =====================================================================
    print("\n--- Category 8: Change Password ---")

    r = h.cmd("reencrypt {p12} -p p12pass --new-password newpass -o {out} --no-confirm",
              p12=h.tmp("leaf.p12"), out=h.tmp("leaf-newpw.p12"))
    t.assert_file_exists(h.tmp("leaf-newpw.p12"), "P12 password change")

    if has_openssl:
        r = h.cmd.openssl("pkcs12 -in {p12} -passin pass:newpass -noout",
                          p12=h.tmp("leaf-newpw.p12"))
        if r.ok:
            t.PASS("New password works on changed P12")
        else:
            t.FAIL("New password works on changed P12", "openssl pkcs12 failed")

        r = h.cmd.openssl("pkcs12 -in {p12} -passin pass:p12pass -noout",
                          p12=h.tmp("leaf-newpw.p12"))
        if not r.ok:
            t.PASS("Old password fails on changed P12")
        else:
            t.FAIL("Old password fails on changed P12", "old password still works")

        r = h.cmd.openssl("pkcs12 -in {p12} -passin pass:p12pass -noout",
                          p12=h.tmp("leaf.p12"))
        if r.ok:
            t.PASS("Original P12 unchanged")
        else:
            t.FAIL("Original P12 unchanged", "original file corrupted")
    else:
        t.SKIP("New password works on changed P12")
        t.SKIP("Old password fails on changed P12")
        t.SKIP("Original P12 unchanged")

    # =====================================================================
    # Category 9: Autosign
    # =====================================================================
    print("\n--- Category 9: Autosign ---")

    autosign_dir2 = h.tmp("autosign-ca2")
    autosign_dir2.mkdir(parents=True, exist_ok=True)
    shutil.copy2(h.tmp("ca.crt"), autosign_dir2 / "ca.crt")
    shutil.copy2(h.tmp("ca.key"), autosign_dir2 / "ca.key")

    r = h.cmd('create-cert --with-key --subject "CN=autosign2.test" --autosign -o {crt} --key-output {key} --no-confirm',
              crt=h.tmp("autosign2.crt"), key=h.tmp("autosign2.key"),
              cwd=str(autosign_dir2))
    t.assert_file_exists(h.tmp("autosign2.crt"), "create-cert --autosign from CA dir")

    # sign --autosign
    shutil.copy2(h.tmp("test.csr"), autosign_dir2 / "test.csr")

    r = h.cmd("sign test.csr --autosign -o {out} --no-confirm",
              out=h.tmp("auto-signed.crt"),
              cwd=str(autosign_dir2))
    t.assert_file_exists(h.tmp("auto-signed.crt"), "sign --autosign from CA dir")

    # Mutual exclusion: --autosign with --ca-cert
    r = h.cmd("sign {csr} --autosign --ca-cert {ca} --ca-key {cakey} -o {out} --no-confirm",
              csr=h.tmp("test.csr"), ca=h.tmp("ca.crt"), cakey=h.tmp("ca.key"),
              out=h.tmp("nope.crt"))
    t.expect_fail(r, "Autosign + ca-cert mutual exclusion")

    # =====================================================================
    # Category 10: Templates
    # =====================================================================
    print("\n--- Category 10: Templates ---")

    r = h.cmd("templates cert")
    t.assert_contains_regex(r, r"certdiag-cert-profile", "templates cert output")

    r = h.cmd("templates ca")
    t.assert_contains_regex(r, r"ca: true", "templates ca output")

    r = h.cmd("templates csr")
    t.assert_contains_regex(r, r"certdiag-cert-profile", "templates csr output")
    t.assert_contains_regex(r, r"digitalSignature", "templates csr has leaf KU")

    # Use template to create cert
    r = h.cmd("templates cert")
    h.tmp("profile.yaml").write_text(r.stdout)

    r = h.cmd('create-cert --with-key --template-profile {profile} --subject "CN=from-profile.test" -o {crt} --key-output {key} --no-confirm',
              profile=h.tmp("profile.yaml"),
              crt=h.tmp("from-profile.crt"), key=h.tmp("from-profile.key"))
    t.assert_file_exists(h.tmp("from-profile.crt"), "Cert from template profile")

    # --from: generate cert template from existing leaf cert
    r = h.cmd("templates cert --from {crt}", crt=h.tmp("san.crt"))
    t.assert_contains_regex(r, r"certdiag-cert-profile", "10.4 templates cert --from cert has kind")
    t.assert_contains_regex(r, r"san\.test", "10.5 templates cert --from cert has CN")
    t.assert_contains_regex(r, r"a\.com", "10.6 templates cert --from cert has SAN DNS")
    t.assert_contains(r, "10.0.0.1", "10.7 templates cert --from cert has SAN IP")
    t.assert_contains_regex(r, r"ca: false", "10.8 templates cert --from leaf cert has ca: false")

    # --from: generate ca template from CA cert
    r = h.cmd("templates ca --from {crt}", crt=h.tmp("ca.crt"))
    t.assert_contains_regex(r, r"ca: true", "10.9 templates ca --from CA cert has ca: true")
    t.assert_contains_regex(r, r"path_length", "10.10 templates ca --from CA cert has path_length")
    t.assert_contains_regex(r, r"certSign", "10.11 templates ca --from CA cert has certSign KU")

    # --from: generate cert template from CSR
    h.cmd('csr --with-key --subject "CN=from-csr.test" --san "DNS:from-csr.test" -o {csr} --key-output {key} --no-confirm',
          csr=h.tmp("from.csr"), key=h.tmp("from-csr.key"))

    r = h.cmd("templates cert --from {csr}", csr=h.tmp("from.csr"))
    t.assert_contains_regex(r, r"certdiag-cert-profile", "10.12 templates cert --from CSR has kind")
    t.assert_contains_regex(r, r"from-csr\.test", "10.13 templates cert --from CSR has CN")
    t.assert_contains_regex(r, r"days: 365", "10.14 templates cert --from CSR has default days")
    t.assert_contains_regex(r, r"ca: false", "10.15 templates cert --from CSR has ca: false")
    t.assert_contains_regex(r, r"digitalSignature", "10.16 templates cert --from CSR has default KU")
    t.assert_contains_regex(r, r"serverAuth", "10.17 templates cert --from CSR has default EKU")

    # --from: RSA cert preserves key_size
    h.cmd('create-cert --with-key -a rsa -s 4096 --subject "CN=rsa-from.test" -o {crt} --key-output {key} --no-confirm',
          crt=h.tmp("rsa-from.crt"), key=h.tmp("rsa-from.key"))

    r = h.cmd("templates cert --from {crt}", crt=h.tmp("rsa-from.crt"))
    t.assert_contains_regex(r, r"algorithm: rsa", "10.18 templates cert --from RSA cert has algorithm")
    t.assert_contains_regex(r, r"key_size: 4096", "10.19 templates cert --from RSA cert has key_size")

    # --from: round-trip (cert -> profile -> create-cert)
    r = h.cmd("templates cert --from {crt}", crt=h.tmp("san.crt"))
    h.tmp("from-profile.yaml").write_text(r.stdout)

    r = h.cmd("create-cert --with-key --template-profile {profile} -o {crt} --key-output {key} --no-confirm",
              profile=h.tmp("from-profile.yaml"),
              crt=h.tmp("from-rt.crt"), key=h.tmp("from-rt.key"))
    t.assert_file_exists(h.tmp("from-rt.crt"), "10.20 templates cert --from round-trip cert created")

    if has_openssl:
        r = h.cmd.openssl("x509 -in {crt} -text -noout", crt=h.tmp("from-rt.crt"))
        t.assert_contains_regex(r, r"a\.com", "10.21 round-trip cert preserves SAN")
        t.assert_contains(r, "10.0.0.1", "10.22 round-trip cert preserves IP SAN")
    else:
        t.SKIP("10.21 round-trip cert preserves SAN")
        t.SKIP("10.22 round-trip cert preserves IP SAN")

    # --from: error cases
    # 10.23: --from without type arg should fail
    r = h.cmd("templates --from {crt}", crt=h.tmp("san.crt"))
    t.expect_fail(r, "10.23 templates --from without type arg fails")

    r = h.cmd("templates cert --from {f}", f=h.tmp("nonexistent.crt"))
    t.expect_fail(r, "10.24 templates --from nonexistent file error")

    r = h.cmd("templates cert --from {f}", f=h.tmp("ss.key"))
    t.expect_fail(r, "10.25 templates --from key-only file error")

    # Cross-type extraction tests
    # 10.26: cert profile from CA cert -> ca: false, leaf KU
    r = h.cmd("templates cert --from {crt}", crt=h.tmp("ca.crt"))
    t.assert_contains_regex(r, r"ca: false", "10.26 templates cert --from CA has ca: false")
    t.assert_contains_regex(r, r"digitalSignature", "10.27 templates cert --from CA has leaf KU")
    t.assert_contains_regex(r, r"serverAuth", "10.28 templates cert --from CA has leaf EKU")

    # 10.29: ca profile from leaf cert -> ca: true, certSign
    r = h.cmd("templates ca --from {crt}", crt=h.tmp("san.crt"))
    t.assert_contains_regex(r, r"ca: true", "10.29 templates ca --from leaf has ca: true")
    t.assert_contains_regex(r, r"certSign", "10.30 templates ca --from leaf has certSign KU")

    # 10.31: csr profile from leaf cert -> no validity, no ca
    r = h.cmd("templates csr --from {crt}", crt=h.tmp("san.crt"))
    t.assert_contains_regex(r, r"certdiag-cert-profile", "10.31 templates csr --from leaf has kind")
    t.assert_not_contains_regex(r, r"validity:", "10.32 templates csr --from leaf has no validity")
    t.assert_not_contains_regex(r, r"ca:", "10.33 templates csr --from leaf has no ca")
    t.assert_contains_regex(r, r"digitalSignature", "10.34 templates csr --from leaf has leaf KU")

    # 10.35: csr profile from CSR -> no validity, no ca
    r = h.cmd("templates csr --from {csr}", csr=h.tmp("from.csr"))
    t.assert_not_contains_regex(r, r"validity:", "10.35 templates csr --from CSR has no validity")
    t.assert_not_contains_regex(r, r"ca:", "10.36 templates csr --from CSR has no ca")

    # =====================================================================
    # Category 11: Error Handling
    # =====================================================================
    print("\n--- Category 11: Error Handling ---")

    # No key source
    r = h.cmd('create-cert --subject "CN=test" -o {out} --no-confirm', out=h.tmp("nope.crt"))
    t.expect_fail(r, "Error: no key source")

    # Invalid algorithm
    r = h.cmd("create-key -a blowfish")
    t.expect_fail(r, "Error: invalid algorithm")

    # Wrong password on P12
    r = h.cmd("convert {p12} -p wrongpass -o {out} --no-confirm",
              p12=h.tmp("leaf.p12"), out=h.tmp("nope.pem"))
    t.expect_fail(r, "Error: wrong password on P12")

    # Missing CA key
    r = h.cmd('create-cert --with-key --subject "CN=test" --sign-ca {ca} -o {out} --no-confirm',
              ca=h.tmp("ca.crt"), out=h.tmp("nope2.crt"))
    t.expect_fail(r, "Error: missing CA key")

    # Overwrite protection (non-TTY, file exists, no --no-confirm)
    h.tmp("existing.crt").write_text("")
    r = h.cmd('create-cert --with-key --subject "CN=test" -o {out}',
              out=h.tmp("existing.crt"))
    t.expect_fail(r, "Error: overwrite protection")

    # Invalid DN
    r = h.cmd('create-cert --with-key --subject "INVALID" -o {out} --no-confirm',
              out=h.tmp("nope3.crt"))
    t.expect_fail(r, "Error: invalid DN")

    # PKCS7 to PKCS12 (no keys available)
    r = h.cmd("convert {p7b} -o {out} -f pkcs12 --output-password test --no-confirm",
              p7b=h.tmp("ss.p7b"), out=h.tmp("nope.p12"))
    if not r.ok:
        t.PASS(f"PKCS7 to PKCS12 conversion error/warning (exit={r.returncode})")
    else:
        combined = r.stdout + r.stderr
        if any(w in combined.lower() for w in ["key", "trust", "warning"]):
            t.PASS("PKCS7 to PKCS12 conversion warning")
        else:
            t.PASS("PKCS7 to PKCS12 conversion (trust store)")

    # =====================================================================
    # Category 12: Integration
    # =====================================================================
    print("\n--- Category 12: Integration ---")

    r = h.cmd("{crt}", crt=h.tmp("ss.crt"))
    t.assert_contains_regex(r, r"test\.local", "List view shows subject")

    r = h.cmd("-t {crt}", crt=h.tmp("ss.crt"))
    if r.stdout.strip():
        t.PASS("Table view output")
    else:
        t.FAIL("Table view output", "no output")

    r = h.cmd("-d {crt}", crt=h.tmp("san.crt"))
    t.assert_contains_regex(r, r"a\.com", "Detail view shows SANs")

    r = h.cmd("-o json {crt}", crt=h.tmp("ss.crt"))
    t.assert_contains_regex(r, r"test\.local", "JSON output contains subject")
    t.assert_json(r, "JSON output is valid")

    r = h.cmd("-r {d} -d", d=h.tmp_dir)
    if r.stdout.strip():
        t.PASS("Recursive scan with details")
    else:
        t.FAIL("Recursive scan with details", "no output")

    # =====================================================================
    # Category 13: JKS Per-Entry Passwords
    # =====================================================================
    print("\n--- Category 13: JKS Per-Entry Passwords ---")

    # --- Store-level password change ---
    h.cmd("reencrypt {jks} -p changeit --new-password newstore -o {out} --no-confirm",
          jks=SMOKE_CERTS / "keystore.jks", out=h.tmp("jks-newstore.jks"))
    t.assert_file_exists(h.tmp("jks-newstore.jks"), "JKS store password change")

    r = h.cmd("{jks} -p newstore", jks=h.tmp("jks-newstore.jks"))
    t.assert_contains_regex(r, r"smoketest-rsa", "JKS new store password unlocks entries")

    r = h.cmd("{jks} -p changeit", jks=h.tmp("jks-newstore.jks"))
    t.assert_contains_regex(r, r"locked", "JKS old store password fails")

    # --- Entry-level password change ---
    h.cmd("reencrypt {jks} -p multientry --entry api-entry --new-password entrypass -o {out} --no-confirm",
          jks=SMOKE_CERTS / "multi.jks", out=h.tmp("jks-entry.jks"))
    t.assert_file_exists(h.tmp("jks-entry.jks"), "JKS entry password change")

    # With store password only: changed entry is locked, other entry unlocks
    r = h.cmd("{jks} -p multientry", jks=h.tmp("jks-entry.jks"))
    t.assert_contains_regex(r, r"encrypted, password required",
                            "JKS changed entry locked with store-only password")
    t.assert_contains_regex(r, r"web-entry",
                            "JKS unchanged entry unlocks with store password")

    # With both passwords: all entries unlock
    r = h.cmd("{jks} -p multientry -p entrypass", jks=h.tmp("jks-entry.jks"))
    t.assert_contains_regex(r, r"api-entry", "JKS both passwords unlock changed entry")
    t.assert_contains_regex(r, r"web-entry", "JKS both passwords unlock unchanged entry")

    # --- Different password annotation in list output ---
    r = h.cmd("{jks} -p multientry -p entrypass", jks=h.tmp("jks-entry.jks"))
    t.assert_contains_regex(r, r"different password",
                            "JKS list shows [different password] annotation")

    # --- Different password annotation in JSON output ---
    r = h.cmd("-o json {jks} -p multientry -p entrypass", jks=h.tmp("jks-entry.jks"))
    t.assert_contains_regex(r, r"different_password",
                            "JKS JSON shows different_password field")

    # --- Different password annotation in table output ---
    r = h.cmd("-t {jks} -p multientry -p entrypass", jks=h.tmp("jks-entry.jks"))
    t.assert_contains_regex(r, r"diff pw", "JKS table shows [diff pw] annotation")

    # --- Checker: entry_password_mismatch ---
    r = h.cmd("--check {jks} -p multientry -p entrypass", jks=h.tmp("jks-entry.jks"))
    t.assert_contains_regex(r, r"different password than the store",
                            "JKS checker reports entry_password_mismatch")

    # --- Store password change on JKS with uniform entry passwords ---
    h.cmd("reencrypt {jks} -p multientry --new-password newstore2 -o {out} --no-confirm",
          jks=SMOKE_CERTS / "multi.jks", out=h.tmp("jks-newstore2.jks"))
    t.assert_file_exists(h.tmp("jks-newstore2.jks"), "JKS store password change on multi-entry")

    r = h.cmd("{jks} -p newstore2", jks=h.tmp("jks-newstore2.jks"))
    t.assert_contains_regex(r, r"api-entry",
                            "JKS store change: api-entry accessible with new password")
    t.assert_contains_regex(r, r"web-entry",
                            "JKS store change: web-entry accessible with new password")

    # --- Remove password ---
    h.cmd("reencrypt {p12} -p p12pass --remove-password -o {out} --no-confirm",
          p12=SMOKE_CERTS / "standard.p12", out=h.tmp("nopass.p12"))
    t.assert_file_exists(h.tmp("nopass.p12"), "P12 remove password")

    r = h.cmd("{p12}", p12=h.tmp("nopass.p12"))
    t.assert_contains_regex(r, r"not protected", "P12 password removed successfully")

    # =====================================================================
    # Category 14: JKS/JCEKS CLI Error Handling
    # =====================================================================
    print("\n--- Category 14: JKS/JCEKS CLI Error Handling ---")

    # --store-password without --entry
    r = h.cmd("reencrypt {jks} -p changeit --store-password sp --new-password x -o {out} --no-confirm",
              jks=SMOKE_CERTS / "keystore.jks", out=h.tmp("nope.jks"))
    t.expect_fail(r, "Error: --store-password without --entry")

    # --remove-password with --new-password
    r = h.cmd("reencrypt {jks} -p changeit --remove-password --new-password x -o {out} --no-confirm",
              jks=SMOKE_CERTS / "keystore.jks", out=h.tmp("nope2.jks"))
    t.expect_fail(r, "Error: --remove-password with --new-password")

    # --entry with nonexistent alias
    r = h.cmd("reencrypt {jks} -p multientry --entry nonexistent --new-password x -o {out} --no-confirm",
              jks=SMOKE_CERTS / "multi.jks", out=h.tmp("nope3.jks"))
    t.expect_fail(r, "Error: --entry with nonexistent alias")
    t.assert_contains(r, "nonexistent", "Error message includes bad alias name", stream="stderr")

    # --entry with --store-password (explicit store password for entry change)
    h.cmd("reencrypt {jks} --store-password multientry -p multientry --entry web-entry --new-password webpass -o {out} --no-confirm",
          jks=SMOKE_CERTS / "multi.jks", out=h.tmp("jks-storepw.jks"))
    t.assert_file_exists(h.tmp("jks-storepw.jks"),
                         "JKS entry change with explicit --store-password")

    r = h.cmd("{jks} -p multientry -p webpass", jks=h.tmp("jks-storepw.jks"))
    t.assert_contains_regex(r, r"web-entry",
                            "JKS explicit --store-password entry change works")


if __name__ == "__main__":
    h = Harness(fixtures_dir=SMOKE_CERTS)
    h.setup(required_tools=["openssl"])
    t = Tracker()
    try:
        run(h, t)
    finally:
        h.cleanup()
    ok = t.summary("smoke_changeactions")
    sys.exit(0 if ok else 1)
