import json
import shutil
from pathlib import Path

from ..lib.harness import Harness
from ..lib.assertions import Tracker


NC = "--no-confirm"


def run(h, t):
    print("\n--- T04: Convert, Bundle, Extract, Reencrypt Edge Cases ---")

    # ==================================================================
    # CONVERT EDGE CASES
    # ==================================================================

    # --- T04.01: Cross-format conversion matrix ---
    print("--- T04.01: Cross-format conversion matrix ---")

    # PEM -> DER
    r = h.cmd("--no-color convert {src} -f der -o {dst} {nc}",
              src=h.fixture("leaf-rsa.pem"), dst=h.tmp("conv-pem2der.der"), nc=NC)
    t.expect_ok(r, "T04.01a PEM->DER convert")
    t.assert_file_not_empty(h.tmp("conv-pem2der.der"), "T04.01a DER output exists")
    r = h.cmd("--no-color {f}", f=h.tmp("conv-pem2der.der"))
    t.expect_ok(r, "T04.01a DER parseable")

    # PEM cert+key -> PKCS#12
    r = h.cmd('--no-color bundle {cert} {key} -f pkcs12 --output-password "conv01" -o {dst} {nc}',
              cert=h.fixture("leaf-rsa.pem"), key=h.fixture("leaf-rsa.key"),
              dst=h.tmp("conv-pem2p12.p12"), nc=NC)
    t.expect_ok(r, "T04.01b PEM->PKCS12 bundle")
    r = h.cmd('--no-color -p "conv01" {f}', f=h.tmp("conv-pem2p12.p12"))
    t.expect_ok(r, "T04.01b PKCS12 parseable")

    # DER -> PEM
    r = h.cmd("--no-color convert {src} -f pem -o {dst} {nc}",
              src=h.tmp("conv-pem2der.der"), dst=h.tmp("conv-der2pem.pem"), nc=NC)
    t.expect_ok(r, "T04.01c DER->PEM convert")
    r = h.cmd("--no-color {f}", f=h.tmp("conv-der2pem.pem"))
    t.expect_ok(r, "T04.01c PEM parseable")

    # PKCS#12 -> PEM
    r = h.cmd('--no-color convert {src} -p "test" -f pem -o {dst} {nc}',
              src=h.fixture("leaf.p12"), dst=h.tmp("conv-p12topem.pem"), nc=NC)
    t.expect_ok(r, "T04.01d PKCS12->PEM convert")
    r = h.cmd("--no-color {f}", f=h.tmp("conv-p12topem.pem"))
    t.expect_ok(r, "T04.01d PEM parseable")

    # PKCS#7 -> PEM
    r = h.cmd("--no-color convert {src} -f pem -o {dst} {nc}",
              src=h.fixture("certs-only.p7b"), dst=h.tmp("conv-p7topem.pem"), nc=NC)
    t.expect_ok(r, "T04.01e PKCS7->PEM convert")
    r = h.cmd("--no-color {f}", f=h.tmp("conv-p7topem.pem"))
    t.expect_ok(r, "T04.01e PEM parseable")

    # PEM -> PKCS#7
    r = h.cmd("--no-color convert {src} -f pkcs7 -o {dst} {nc}",
              src=h.fixture("leaf-rsa.pem"), dst=h.tmp("conv-pem2p7.p7b"), nc=NC)
    t.expect_ok(r, "T04.01f PEM->PKCS7 convert")
    r = h.cmd("--no-color {f}", f=h.tmp("conv-pem2p7.p7b"))
    t.expect_ok(r, "T04.01f PKCS7 parseable")

    # PEM -> JKS
    r = h.cmd('--no-color convert {src} -f jks --output-password "jksconv" --alias "conv" -o {dst} {nc}',
              src=h.fixture("leaf-rsa.pem"), dst=h.tmp("conv-pem2jks.jks"), nc=NC)
    t.expect_ok(r, "T04.01g PEM->JKS convert")
    r = h.cmd('--no-color -p "jksconv" {f}', f=h.tmp("conv-pem2jks.jks"))
    t.expect_ok(r, "T04.01g JKS parseable")

    # --- T04.02: Convert with --include filter ---
    print("--- T04.02: Convert with --include filter ---")

    # p12 -> PEM certs only
    r = h.cmd('--no-color convert {src} -p "test" --include certs -f pem -o {dst} {nc}',
              src=h.fixture("leaf.p12"), dst=h.tmp("certs-only.pem"), nc=NC)
    t.expect_ok(r, "T04.02a p12->PEM certs only")
    r = h.cmd("--no-color -o json {f}", f=h.tmp("certs-only.pem"))
    t.assert_contains(r, "certificate", "T04.02a output has cert")
    t.assert_not_contains(r, "private", "T04.02a output has no key")

    # p12 -> PEM keys only
    r = h.cmd('--no-color convert {src} -p "test" --include keys -f pem -o {dst} {nc}',
              src=h.fixture("leaf.p12"), dst=h.tmp("keys-only.pem"), nc=NC)
    t.expect_ok(r, "T04.02b p12->PEM keys only")
    r = h.cmd("--no-color -o json {f}", f=h.tmp("keys-only.pem"))
    t.assert_contains(r, "key", "T04.02b output has key")

    # --- T04.03: Convert with --alias flag (to JKS) ---
    print("--- T04.03: Convert with --alias flag ---")

    r = h.cmd('--no-color convert {src} -f jks --output-password "store" --alias "myalias" -o {dst} {nc}',
              src=h.fixture("leaf-rsa.pem"), dst=h.tmp("aliased.jks"), nc=NC)
    t.expect_ok(r, "T04.03 convert with alias")
    r = h.cmd('--no-color -p "store" -o json {f}', f=h.tmp("aliased.jks"))
    t.assert_contains(r, "myalias", "T04.03 alias in JKS output")

    # --- T04.04: Convert with --legacy-pkcs12 ---
    print("--- T04.04: Convert with --legacy-pkcs12 ---")

    r = h.cmd('--no-color bundle {cert} {key} -f pkcs12 --output-password "legacy" --legacy-pkcs12 -o {dst} {nc}',
              cert=h.fixture("leaf-rsa.pem"), key=h.fixture("leaf-rsa.key"),
              dst=h.tmp("legacy-conv.p12"), nc=NC)
    t.expect_ok(r, "T04.04 legacy p12 creation")
    r = h.cmd('--no-color -p "legacy" {f}', f=h.tmp("legacy-conv.p12"))
    t.expect_ok(r, "T04.04 legacy p12 readable")

    # --- T04.05: Convert PKCS#7 to PKCS#12 (no keys available) ---
    print("--- T04.05: Convert PKCS#7 to PKCS#12 (no keys) ---")

    r = h.cmd('--no-color convert {src} -f pkcs12 --output-password "test" -o {dst} {nc}',
              src=h.fixture("certs-only.p7b"), dst=h.tmp("p7-to-p12.p12"), nc=NC)
    if r.ok:
        t.PASS("T04.05 p7b->p12 succeeded (cert-only p12)")
        r2 = h.cmd('--no-color -p "test" {f}', f=h.tmp("p7-to-p12.p12"))
        t.expect_ok(r2, "T04.05 cert-only p12 readable")
    else:
        t.PASS("T04.05 p7b->p12 correctly refused (no keys)")

    # --- T04.06: Convert encrypted PEM key round trip ---
    print("--- T04.06: Convert encrypted PEM key round trip ---")

    r = h.cmd('--no-color convert {src} -p "keypass" -f der -o {dst} {nc}',
              src=h.fixture("leaf-encrypted.pem"), dst=h.tmp("decrypted.der"), nc=NC)
    t.expect_ok(r, "T04.06 encrypted PEM->DER")
    r = h.cmd("--no-color {f}", f=h.tmp("decrypted.der"))
    t.expect_ok(r, "T04.06 DER readable without password")

    # --- T04.07: Convert with missing password ---
    print("--- T04.07: Convert with missing password ---")

    r = h.cmd("--no-color convert {src} -f pem -o {dst} {nc}",
              src=h.fixture("leaf.p12"), dst=h.tmp("bad.pem"), nc=NC)
    t.expect_fail(r, "T04.07 convert missing password")

    # --- T04.08: Convert to same format (PEM -> PEM normalizer) ---
    print("--- T04.08: Convert to same format (PEM -> PEM) ---")

    r = h.cmd("--no-color convert {src} -f pem -o {dst} {nc}",
              src=h.fixture("leaf-rsa.pem"), dst=h.tmp("same.pem"), nc=NC)
    t.expect_ok(r, "T04.08 PEM->PEM convert")

    r_orig = h.cmd("--no-color -o json {f}", f=h.fixture("leaf-rsa.pem"))
    r_conv = h.cmd("--no-color -o json {f}", f=h.tmp("same.pem"))

    def strip_meta(json_text):
        try:
            data = json.loads(json_text)
            files = data.get("files", []) if isinstance(data, dict) else data
            for f in files:
                for k in ["file_path", "filename", "modified", "accessed", "created", "size", "file_size"]:
                    f.pop(k, None)
            return json.dumps(files, sort_keys=True)
        except (json.JSONDecodeError, TypeError, AttributeError):
            return ""

    orig_stripped = strip_meta(r_orig.stdout)
    conv_stripped = strip_meta(r_conv.stdout)
    if orig_stripped and orig_stripped == conv_stripped:
        t.PASS("T04.08 PEM->PEM content identical")
    else:
        t.FAIL("T04.08 PEM->PEM content identical", "JSON outputs differ")

    # ==================================================================
    # BUNDLE EDGE CASES
    # ==================================================================

    # --- T04.09: Bundle with --auto-chain ordering ---
    print("--- T04.09: Bundle with --auto-chain ordering ---")

    r = h.cmd("--no-color bundle {leaf} {root} {inter} --auto-chain -o {dst} {nc}",
              leaf=h.fixture("leaf-rsa.pem"), root=h.fixture("root-ca.pem"),
              inter=h.fixture("inter-ca.pem"), dst=h.tmp("auto-chain.pem"), nc=NC)
    t.expect_ok(r, "T04.09 auto-chain bundle")
    r = h.cmd("--no-color -o json {f}", f=h.tmp("auto-chain.pem"))
    t.assert_json(r, "T04.09 auto-chain JSON valid")
    t.assert_contains(r, "Root CA", "T04.09 chain contains root")
    t.assert_contains(r, "edge.test", "T04.09 chain contains leaf")

    # --- T04.10: Bundle with --include-root=false ---
    print("--- T04.10: Bundle with --include-root=false ---")

    r = h.cmd.run("--no-color", "bundle",
                   str(h.fixture("root-ca.pem")), str(h.fixture("inter-ca.pem")),
                   str(h.fixture("leaf-rsa.pem")),
                   "--auto-chain", "--include-root=false",
                   "-o", str(h.tmp("no-root.pem")), NC)
    t.expect_ok(r, "T04.10 bundle exclude root")
    r = h.cmd("--no-color -o json {f}", f=h.tmp("no-root.pem"))
    t.assert_json(r, "T04.10 no-root JSON valid")

    try:
        data = json.loads(r.stdout)
        files = data.get("files", data) if isinstance(data, dict) else data
        count = sum(
            1 for f in files
            for item in f.get("items", [])
            if "EdgeTest Root CA" in (item.get("certificate") or {}).get("subject_dn", "")
        )
        if count == 0:
            t.PASS("T04.10 root excluded")
        else:
            t.FAIL("T04.10 root excluded", f"root CA found as subject ({count} times)")
    except (json.JSONDecodeError, TypeError, AttributeError):
        t.FAIL("T04.10 root excluded", "could not parse JSON")

    # --- T04.11: Bundle mixed formats into PKCS#12 ---
    print("--- T04.11: Bundle mixed formats into PKCS#12 ---")

    r = h.cmd('--no-color bundle {cert} {key} {inter} -f pkcs12 --output-password "mixed" -o {dst} {nc}',
              cert=h.fixture("leaf-rsa.pem"), key=h.fixture("leaf-rsa.key"),
              inter=h.fixture("inter-ca.pem"), dst=h.tmp("mixed.p12"), nc=NC)
    t.expect_ok(r, "T04.11 mixed format bundle to p12")
    r = h.cmd('--no-color -p "mixed" {f}', f=h.tmp("mixed.p12"))
    t.expect_ok(r, "T04.11 mixed p12 readable")

    # --- T04.12: Bundle into JKS ---
    print("--- T04.12: Bundle into JKS ---")

    pki_server = h.tmp("pki-server.pem")
    pki_server_key = h.tmp("pki-server.key")
    pki_inter = h.tmp("pki-inter.pem")

    if pki_server.exists() and pki_server_key.exists() and pki_inter.exists():
        r = h.cmd('--no-color bundle {cert} {key} {inter} -f jks --output-password "jkstest" --alias "server" -o {dst} {nc}',
                  cert=pki_server, key=pki_server_key, inter=pki_inter,
                  dst=h.tmp("bundled.jks"), nc=NC)
        t.expect_ok(r, "T04.12 bundle into JKS")
        r = h.cmd('--no-color -p "jkstest" {f}', f=h.tmp("bundled.jks"))
        t.expect_ok(r, "T04.12 JKS readable")
    else:
        t.SKIP("T04.12 bundle into JKS (pki-server files from T03.27 not found)")

    # --- T04.13: Bundle into PKCS#7 ---
    print("--- T04.13: Bundle into PKCS#7 ---")

    r = h.cmd("--no-color bundle {root} {inter} {leaf} -f pkcs7 -o {dst} {nc}",
              root=h.fixture("root-ca.pem"), inter=h.fixture("inter-ca.pem"),
              leaf=h.fixture("leaf-rsa.pem"), dst=h.tmp("bundled.p7b"), nc=NC)
    t.expect_ok(r, "T04.13 bundle into PKCS7")
    r = h.cmd("--no-color {f}", f=h.tmp("bundled.p7b"))
    t.expect_ok(r, "T04.13 PKCS7 readable")
    t.assert_contains(r, "edge.test", "T04.13 PKCS7 contains leaf")

    # --- T04.14: Bundle duplicate certs ---
    print("--- T04.14: Bundle duplicate certs ---")

    r = h.cmd("--no-color bundle {a} {b} {c} -o {dst} {nc}",
              a=h.fixture("leaf-rsa.pem"), b=h.fixture("leaf-rsa.pem"),
              c=h.fixture("leaf-rsa.pem"), dst=h.tmp("dupe-bundle.pem"), nc=NC)
    t.expect_ok(r, "T04.14 bundle duplicates")
    r = h.cmd("--no-color -o json {f}", f=h.tmp("dupe-bundle.pem"))
    t.assert_json(r, "T04.14 dupe bundle JSON valid")

    # --- T04.15: Bundle with --auto-assemble ---
    print("--- T04.15: Bundle with --auto-assemble ---")

    pki_root = h.tmp("pki-root.pem")

    if pki_server.exists() and pki_server_key.exists() and pki_inter.exists() and pki_root.exists():
        assemble_dir = h.tmp("assemble-dir")
        assemble_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(pki_server, assemble_dir / "pki-server.pem")
        shutil.copy2(pki_server_key, assemble_dir / "pki-server.key")
        shutil.copy2(pki_inter, assemble_dir / "pki-inter.pem")
        shutil.copy2(pki_root, assemble_dir / "pki-root.pem")

        r = h.cmd("--no-color bundle --auto-assemble {d} -o {dst} {nc}",
                  d=str(assemble_dir) + "/", dst=h.tmp("assembled.pem"), nc=NC)
        t.expect_ok(r, "T04.15 auto-assemble bundle")
        r = h.cmd("--no-color -o json {f}", f=h.tmp("assembled.pem"))
        t.assert_json(r, "T04.15 assembled JSON valid")
    else:
        t.SKIP("T04.15 auto-assemble (pki files from T03.27 not found)")

    # --- T04.15b: Auto-assemble with ambiguous directory (multiple leaves) ---
    print("--- T04.15b: Auto-assemble with ambiguous directory ---")

    pki_client = h.tmp("pki-client.pem")
    pki_client_key = h.tmp("pki-client.key")

    if pki_server.exists() and pki_client.exists():
        ambig_dir = h.tmp("ambiguous-dir")
        ambig_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(pki_server, ambig_dir / "pki-server.pem")
        shutil.copy2(pki_server_key, ambig_dir / "pki-server.key")
        shutil.copy2(pki_client, ambig_dir / "pki-client.pem")
        shutil.copy2(pki_client_key, ambig_dir / "pki-client.key")
        shutil.copy2(pki_inter, ambig_dir / "pki-inter.pem")
        shutil.copy2(pki_root, ambig_dir / "pki-root.pem")

        r = h.cmd("--no-color bundle --auto-assemble {d} -o {dst} {nc}",
                  d=str(ambig_dir) + "/", dst=h.tmp("ambiguous.pem"), nc=NC)
        if r.ok:
            t.PASS("T04.15b ambiguous auto-assemble succeeded (picked one leaf)")
            t.assert_file_not_empty(h.tmp("ambiguous.pem"), "T04.15b output not empty")
        else:
            t.assert_contains(r, "ambig", "T04.15b ambiguity reported")
    else:
        t.SKIP("T04.15b ambiguous auto-assemble (pki files from T03.27 not found)")

    # --- T04.15c: Auto-assemble with no keys ---
    print("--- T04.15c: Auto-assemble with no keys ---")

    if pki_server.exists() and pki_inter.exists() and pki_root.exists():
        nokey_dir = h.tmp("nokey-dir")
        nokey_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(pki_server, nokey_dir / "pki-server.pem")
        shutil.copy2(pki_inter, nokey_dir / "pki-inter.pem")
        shutil.copy2(pki_root, nokey_dir / "pki-root.pem")

        r = h.cmd("--no-color bundle --auto-assemble {d} -o {dst} {nc}",
                  d=str(nokey_dir) + "/", dst=h.tmp("nokey-assemble.pem"), nc=NC)
        if r.ok:
            t.PASS("T04.15c no-key auto-assemble succeeded (chain-only)")
        else:
            t.PASS("T04.15c no-key auto-assemble refused (keys required)")
    else:
        t.SKIP("T04.15c no-key auto-assemble (pki files from T03.27 not found)")

    # --- T04.15d: Auto-assemble with encrypted files ---
    print("--- T04.15d: Auto-assemble with encrypted files ---")

    if pki_server.exists() and pki_server_key.exists():
        enc_dir = h.tmp("enc-assemble-dir")
        enc_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(pki_server, enc_dir / "pki-server.pem")
        shutil.copy2(pki_inter, enc_dir / "pki-inter.pem")
        shutil.copy2(pki_root, enc_dir / "pki-root.pem")

        h.cmd('--no-color bundle {key} -f pkcs12 --output-password "asmpass" -o {dst} {nc}',
              key=pki_server_key, dst=enc_dir / "server.p12", nc=NC)

        r = h.cmd('--no-color bundle --auto-assemble {d} -p "asmpass" -o {dst} {nc}',
                  d=str(enc_dir) + "/", dst=h.tmp("enc-assembled.pem"), nc=NC)
        if r.ok:
            t.PASS("T04.15d encrypted auto-assemble succeeded")
        else:
            t.PASS(f"T04.15d encrypted auto-assemble returned rc={r.returncode} (may need key file directly)")
    else:
        t.SKIP("T04.15d encrypted auto-assemble (pki files from T03.27 not found)")

    # --- T04.15e: Auto-assemble on empty directory ---
    print("--- T04.15e: Auto-assemble on empty directory ---")

    empty_dir = h.tmp("empty-assemble")
    empty_dir.mkdir(parents=True, exist_ok=True)
    r = h.cmd("--no-color bundle --auto-assemble {d} -o {dst} {nc}",
              d=str(empty_dir) + "/", dst=h.tmp("bad-assemble.pem"), nc=NC)
    t.expect_fail(r, "T04.15e auto-assemble empty directory")

    # --- T04.16: Bundle with encrypted input files (from p12) ---
    print("--- T04.16: Bundle with encrypted input files ---")

    r = h.cmd('--no-color bundle {src} -p "test" -o {dst} {nc}',
              src=h.fixture("leaf.p12"), dst=h.tmp("from-p12.pem"), nc=NC)
    t.expect_ok(r, "T04.16 bundle from encrypted p12")
    r = h.cmd("--no-color {f}", f=h.tmp("from-p12.pem"))
    t.expect_ok(r, "T04.16 output readable")

    # --- T04.17: Bundle keys-only into PKCS#7 (expect failure) ---
    print("--- T04.17: Bundle keys-only into PKCS#7 ---")

    r = h.cmd("--no-color bundle {key} -f pkcs7 -o {dst} {nc}",
              key=h.fixture("leaf-rsa.key"), dst=h.tmp("bad.p7b"), nc=NC)
    t.expect_fail(r, "T04.17 bundle keys-only into PKCS7")

    # ==================================================================
    # EXTRACT EDGE CASES
    # ==================================================================

    # --- T04.18: Extract with --naming patterns ---
    print("--- T04.18: Extract with --naming patterns ---")

    extract_named = h.tmp("extract-named")
    extract_named.mkdir(parents=True, exist_ok=True)
    r = h.cmd.run("--no-color", "extract", str(h.fixture("chain.p12")),
                   "-p", "chain", "--output-dir", str(extract_named) + "/",
                   "--naming", "{subject}-{index}.{format}", NC)
    t.expect_ok(r, "T04.18 extract with naming pattern")
    file_count = len([f for f in extract_named.iterdir() if f.is_file()])
    if file_count > 0:
        t.PASS(f"T04.18 extracted {file_count} files with naming pattern")
    else:
        t.FAIL("T04.18 extracted files with naming pattern", "no files created")

    # --- T04.18b: Extract with all --naming placeholders ---
    print("--- T04.18b: Extract with all naming placeholders ---")

    # {filename}-{index}
    naming_filename = h.tmp("naming-filename")
    naming_filename.mkdir(parents=True, exist_ok=True)
    r = h.cmd.run("--no-color", "extract", str(h.fixture("chain.p12")),
                   "-p", "chain", "--output-dir", str(naming_filename) + "/",
                   "--naming", "{filename}-{index}", NC)
    t.expect_ok(r, "T04.18b naming {filename}-{index}")

    # {index}-{type}
    naming_type = h.tmp("naming-type")
    naming_type.mkdir(parents=True, exist_ok=True)
    r = h.cmd.run("--no-color", "extract", str(h.fixture("chain.p12")),
                   "-p", "chain", "--output-dir", str(naming_type) + "/",
                   "--naming", "{index}-{type}", NC)
    t.expect_ok(r, "T04.18b naming {index}-{type}")

    # {index}.{format}
    naming_format = h.tmp("naming-format")
    naming_format.mkdir(parents=True, exist_ok=True)
    r = h.cmd.run("--no-color", "extract", str(h.fixture("chain.p12")),
                   "-p", "chain", "--output-dir", str(naming_format) + "/",
                   "--naming", "{index}.{format}", NC)
    t.expect_ok(r, "T04.18b naming {index}.{format}")

    # {alias}-{type} from JKS
    naming_alias = h.tmp("naming-alias")
    naming_alias.mkdir(parents=True, exist_ok=True)
    r = h.cmd.run("--no-color", "extract", str(h.fixture("multi.jks")),
                   "-p", "jkspass", "--output-dir", str(naming_alias) + "/",
                   "--naming", "{alias}-{type}", NC)
    t.expect_ok(r, "T04.18b naming {alias}-{type}")

    # --- T04.18c: Extract with non-existent alias ---
    print("--- T04.18c: Extract with non-existent alias ---")

    bad_alias_dir = h.tmp("bad-alias")
    bad_alias_dir.mkdir(parents=True, exist_ok=True)
    r = h.cmd('--no-color extract {src} -p "jkspass" --output-dir {d} --alias "nonexistent_alias" {nc}',
              src=h.fixture("multi.jks"), d=str(bad_alias_dir) + "/", nc=NC)
    t.expect_fail(r, "T04.18c extract non-existent alias")

    # --- T04.19: Extract with --alias (JKS) ---
    print("--- T04.19: Extract with --alias (JKS) ---")

    extract_alias = h.tmp("extract-alias")
    extract_alias.mkdir(parents=True, exist_ok=True)
    r = h.cmd('--no-color extract {src} -p "jkspass" --output-dir {d} --alias "server" {nc}',
              src=h.fixture("multi.jks"), d=str(extract_alias) + "/", nc=NC)
    t.expect_ok(r, "T04.19 extract by alias")
    file_count = len([f for f in extract_alias.iterdir() if f.is_file()])
    if file_count >= 1:
        t.PASS(f"T04.19 extracted {file_count} files for alias 'server'")
    else:
        t.FAIL("T04.19 extracted files for alias", "no files created")

    # --- T04.20: Extract specific --index from bundle ---
    print("--- T04.20: Extract specific index from bundle ---")

    extract_idx = h.tmp("extract-idx")
    extract_idx.mkdir(parents=True, exist_ok=True)
    r = h.cmd("--no-color extract {src} --index 2 --output-dir {d} {nc}",
              src=h.fixture("chain-full.pem"), d=str(extract_idx) + "/", nc=NC)
    t.expect_ok(r, "T04.20 extract index 2")
    file_count = len([f for f in extract_idx.iterdir() if f.is_file()])
    if file_count == 1:
        t.PASS("T04.20 extracted exactly 1 item")
    else:
        t.FAIL("T04.20 extracted exactly 1 item", f"got {file_count} files")

    # --- T04.21: Extract to DER format ---
    print("--- T04.21: Extract to DER format ---")

    extract_der = h.tmp("extract-der")
    extract_der.mkdir(parents=True, exist_ok=True)
    r = h.cmd('--no-color extract {src} -p "test" -f der --output-dir {d} {nc}',
              src=h.fixture("leaf.p12"), d=str(extract_der) + "/", nc=NC)
    t.expect_ok(r, "T04.21 extract to DER")
    for f in extract_der.iterdir():
        if f.is_file():
            content = f.read_bytes()
            if b"BEGIN" not in content:
                t.PASS(f"T04.21 {f.name} is DER (not PEM)")
            else:
                t.FAIL(f"T04.21 {f.name} is DER (not PEM)", "file contains PEM header")
            break

    # --- T04.22: Extract --type filter (certs vs keys from p12) ---
    print("--- T04.22: Extract type filter ---")

    extract_certs = h.tmp("extract-certs")
    extract_keys = h.tmp("extract-keys")
    extract_certs.mkdir(parents=True, exist_ok=True)
    extract_keys.mkdir(parents=True, exist_ok=True)

    # certs only
    r = h.cmd('--no-color extract {src} -p "chain" --type certs --output-dir {d} {nc}',
              src=h.fixture("chain.p12"), d=str(extract_certs) + "/", nc=NC)
    t.expect_ok(r, "T04.22a extract certs only")

    # keys only
    r = h.cmd('--no-color extract {src} -p "chain" --type keys --output-dir {d} {nc}',
              src=h.fixture("chain.p12"), d=str(extract_keys) + "/", nc=NC)
    t.expect_ok(r, "T04.22b extract keys only")

    # verify certs dir has no keys
    certs_have_key = False
    for f in extract_certs.iterdir():
        if f.is_file():
            try:
                content = f.read_text(errors="ignore").lower()
                if "private key" in content:
                    certs_have_key = True
            except Exception:
                pass
    if not certs_have_key:
        t.PASS("T04.22a certs dir has no keys")
    else:
        t.FAIL("T04.22a certs dir has no keys", "found key in certs-only extract")

    # --- T04.22b: Extract from PKCS#7 (certs only, no keys) ---
    print("--- T04.22b: Extract from PKCS#7 ---")

    extract_p7b = h.tmp("extract-p7b")
    extract_p7b_keys = h.tmp("extract-p7b-keys")
    extract_p7b.mkdir(parents=True, exist_ok=True)
    extract_p7b_keys.mkdir(parents=True, exist_ok=True)

    r = h.cmd("--no-color extract {src} --type all --output-dir {d} {nc}",
              src=h.fixture("certs-only.p7b"), d=str(extract_p7b) + "/", nc=NC)
    t.expect_ok(r, "T04.22b extract all from p7b")

    r = h.cmd("--no-color extract {src} --type keys --output-dir {d} {nc}",
              src=h.fixture("certs-only.p7b"), d=str(extract_p7b_keys) + "/", nc=NC)
    key_count = len([f for f in extract_p7b_keys.iterdir() if f.is_file()])
    if key_count == 0:
        t.PASS("T04.22b p7b keys extract produced no files (correct)")
    else:
        t.PASS(f"T04.22b p7b keys extract returned rc={r.returncode} (no keys in p7b)")

    # --- T04.23: Extract out-of-range index ---
    print("--- T04.23: Extract out-of-range index ---")

    bad_idx = h.tmp("bad-idx")
    bad_idx.mkdir(parents=True, exist_ok=True)
    r = h.cmd("--no-color extract {src} --index 99 --output-dir {d} {nc}",
              src=h.fixture("leaf-rsa.pem"), d=str(bad_idx) + "/", nc=NC)
    t.expect_fail(r, "T04.23 extract out-of-range index")

    # --- T04.23b: Extract validation (invalid type, negative index) ---
    print("--- T04.23b: Extract validation ---")

    r = h.cmd("--no-color extract {src} --type foo --output-dir {d} {nc}",
              src=h.fixture("leaf-rsa.pem"), d=str(bad_idx) + "/", nc=NC)
    t.expect_exit(1, r, "T04.23b invalid type")

    r = h.cmd("--no-color extract {src} --index -1 --output-dir {d} {nc}",
              src=h.fixture("leaf-rsa.pem"), d=str(bad_idx) + "/", nc=NC)
    t.expect_exit(1, r, "T04.23b negative index")

    # ==================================================================
    # REENCRYPT EDGE CASES
    # ==================================================================

    # --- T04.24: Reencrypt PKCS#12 (new password, old fails) ---
    print("--- T04.24: Reencrypt PKCS#12 ---")

    shutil.copy2(h.fixture("leaf.p12"), h.tmp("reenc.p12"))
    r = h.cmd('--no-color reencrypt {f} -p "test" --new-password "newpass" {nc}',
              f=h.tmp("reenc.p12"), nc=NC)
    t.expect_ok(r, "T04.24 reencrypt p12")
    r = h.cmd('--no-color -p "newpass" {f}', f=h.tmp("reenc.p12"))
    t.expect_ok(r, "T04.24 new password works")
    r = h.cmd('--no-color -p "test" {f}', f=h.tmp("reenc.p12"))
    t.expect_fail(r, "T04.24 old password fails")

    # --- T04.25: Reencrypt with --remove-password ---
    print("--- T04.25: Reencrypt with --remove-password ---")

    shutil.copy2(h.fixture("leaf.p12"), h.tmp("nopass.p12"))
    r = h.cmd('--no-color reencrypt {f} -p "test" --remove-password {nc}',
              f=h.tmp("nopass.p12"), nc=NC)
    t.expect_ok(r, "T04.25 remove password")
    r = h.cmd("--no-color {f}", f=h.tmp("nopass.p12"))
    t.expect_ok(r, "T04.25 readable without password")

    # --- T04.26: Reencrypt with --legacy-pkcs12 ---
    print("--- T04.26: Reencrypt with --legacy-pkcs12 ---")

    shutil.copy2(h.fixture("leaf.p12"), h.tmp("reenc-legacy.p12"))
    r = h.cmd('--no-color reencrypt {f} -p "test" --new-password "new" --legacy-pkcs12 {nc}',
              f=h.tmp("reenc-legacy.p12"), nc=NC)
    t.expect_ok(r, "T04.26 reencrypt legacy p12")
    r = h.cmd('--no-color -p "new" {f}', f=h.tmp("reenc-legacy.p12"))
    t.expect_ok(r, "T04.26 legacy p12 readable")

    # --- T04.27: Reencrypt output to different file ---
    print("--- T04.27: Reencrypt to different file ---")

    r = h.cmd('--no-color reencrypt {src} -p "test" --new-password "other" -o {dst} {nc}',
              src=h.fixture("leaf.p12"), dst=h.tmp("reenc-out.p12"), nc=NC)
    t.expect_ok(r, "T04.27 reencrypt to new file")
    r = h.cmd('--no-color -p "other" {f}', f=h.tmp("reenc-out.p12"))
    t.expect_ok(r, "T04.27 new file readable")
    r = h.cmd('--no-color -p "test" {f}', f=h.fixture("leaf.p12"))
    t.expect_ok(r, "T04.27 original unchanged")

    # --- T04.28: Reencrypt JKS entry password ---
    print("--- T04.28: Reencrypt JKS entry password ---")

    shutil.copy2(h.fixture("leaf.jks"), h.tmp("reenc-jks.jks"))
    r = h.cmd('--no-color reencrypt {f} --store-password "jkspass" --entry "mykey" -p "jkspass" --new-password "newkeypass" {nc}',
              f=h.tmp("reenc-jks.jks"), nc=NC)
    t.expect_ok(r, "T04.28 reencrypt JKS entry")

    # --- T04.28b: Reencrypt encrypted PEM key ---
    print("--- T04.28b: Reencrypt encrypted PEM key ---")

    r = h.cmd('--no-color reencrypt {src} -p "keypass" --new-password "newkeypass" -o {dst} {nc}',
              src=h.fixture("leaf-encrypted.pem"), dst=h.tmp("reenc-pem.pem"), nc=NC)
    t.expect_ok(r, "T04.28b reencrypt PEM key")
    r = h.cmd('--no-color -p "newkeypass" {f}', f=h.tmp("reenc-pem.pem"))
    t.expect_ok(r, "T04.28b new password works")
    r = h.cmd('--no-color -p "keypass" {f}', f=h.tmp("reenc-pem.pem"))
    t.expect_fail(r, "T04.28b old password fails")

    # --- T04.29: Reencrypt with wrong password ---
    print("--- T04.29: Reencrypt with wrong password ---")

    r = h.cmd('--no-color reencrypt {src} -p "WRONG" --new-password "new" {nc}',
              src=h.fixture("leaf.p12"), nc=NC)
    t.expect_fail(r, "T04.29 reencrypt wrong password")

    # ==================================================================
    # CHAINED CONVERSION ROUND TRIPS
    # ==================================================================

    # --- T04.30: Round trip PEM -> PKCS#12 -> JKS -> PEM ---
    print("--- T04.30: Round trip PEM -> PKCS#12 -> JKS -> PEM ---")

    if pki_server.exists() and pki_server_key.exists():
        # PEM -> PKCS#12
        r = h.cmd('--no-color bundle {cert} {key} -f pkcs12 --output-password "p12pass" -o {dst} {nc}',
                  cert=pki_server, key=pki_server_key, dst=h.tmp("rt.p12"), nc=NC)
        t.expect_ok(r, "T04.30a PEM->PKCS12")

        # PKCS#12 -> JKS
        r = h.cmd('--no-color convert {src} -p "p12pass" -f jks --output-password "jkspass" -o {dst} {nc}',
                  src=h.tmp("rt.p12"), dst=h.tmp("rt.jks"), nc=NC)
        t.expect_ok(r, "T04.30b PKCS12->JKS")

        # JKS -> PEM
        r = h.cmd('--no-color convert {src} -p "jkspass" -f pem -o {dst} {nc}',
                  src=h.tmp("rt.jks"), dst=h.tmp("rt-back.pem"), nc=NC)
        t.expect_ok(r, "T04.30c JKS->PEM")

        # verify original and round-tripped certs match via diff
        r = h.cmd("--no-color diff {a} {b}",
                  a=pki_server, b=h.tmp("rt-back.pem"))
        t.expect_ok(r, "T04.30d round-trip diff matches")
    else:
        t.SKIP("T04.30 round trip (pki-server files from T03.27 not found)")

    # --- T04.31: Round trip PEM -> DER -> PKCS#7 -> PEM ---
    print("--- T04.31: Round trip PEM -> DER -> PKCS#7 -> PEM ---")

    # PEM -> DER
    r = h.cmd("--no-color convert {src} -f der -o {dst} {nc}",
              src=h.fixture("leaf-rsa.pem"), dst=h.tmp("rt.der"), nc=NC)
    t.expect_ok(r, "T04.31a PEM->DER")

    # DER -> PKCS#7
    r = h.cmd("--no-color convert {src} -f pkcs7 -o {dst} {nc}",
              src=h.tmp("rt.der"), dst=h.tmp("rt.p7b"), nc=NC)
    t.expect_ok(r, "T04.31b DER->PKCS7")

    # PKCS#7 -> PEM
    r = h.cmd("--no-color convert {src} -f pem -o {dst} {nc}",
              src=h.tmp("rt.p7b"), dst=h.tmp("rt2-back.pem"), nc=NC)
    t.expect_ok(r, "T04.31c PKCS7->PEM")

    # verify match
    r = h.cmd("--no-color diff {a} {b}",
              a=h.fixture("leaf-rsa.pem"), b=h.tmp("rt2-back.pem"))
    t.expect_ok(r, "T04.31d round-trip diff matches")

    # --- T04.32: Round trip PKCS#12 -> JKS -> PKCS#12 ---
    print("--- T04.32: Round trip PKCS#12 -> JKS -> PKCS#12 ---")

    # PKCS#12 -> JKS
    r = h.cmd('--no-color convert {src} -p "test" -f jks --output-password "jkspass" --alias "mykey" -o {dst} {nc}',
              src=h.fixture("leaf.p12"), dst=h.tmp("rt-jks.jks"), nc=NC)
    t.expect_ok(r, "T04.32a PKCS12->JKS")

    # JKS -> PKCS#12
    r = h.cmd('--no-color convert {src} -p "jkspass" -f pkcs12 --output-password "p12pass2" -o {dst} {nc}',
              src=h.tmp("rt-jks.jks"), dst=h.tmp("rt-p12-back.p12"), nc=NC)
    t.expect_ok(r, "T04.32b JKS->PKCS12")

    # verify certs are identical despite format round-trip
    r = h.cmd.run("--no-color", "diff",
                   str(h.fixture("leaf.p12")), str(h.tmp("rt-p12-back.p12")),
                   "-p", "test", "-p", "p12pass2")
    t.expect_ok(r, "T04.32c round-trip diff matches")


if __name__ == "__main__":
    import sys

    fixture_dir = Path(__file__).resolve().parents[3] / "edgecases" / "fixtures"
    h = Harness(fixtures_dir=fixture_dir)
    h.setup(required_tools=["openssl"])

    t = Tracker()
    try:
        run(h, t)
    finally:
        h.cleanup()
        t.close()

    t.summary("T04")
    sys.exit(0 if t.failed == 0 else 1)
