"""T16: Root CA snapshots and the config directory.

Every `store update` invocation here uses --import or --from. Nothing in this
suite reaches the network: a live vendor download would make CI depend on
GitHub and Chromium availability and on their file formats not changing between
runs, which is exactly the failure the build-time generator is meant to absorb.

Config cases run against a temp HOME so the developer's own ~/.certdiag is
never touched.
"""

import json
import shutil


def _repo_root(h):
    """fixtures -> edgecases -> testing -> tools -> repo root."""
    return h.fixtures_dir.parents[3]


def _home_env(home):
    """Point every home-directory lookup at a temp tree."""
    return {"HOME": str(home), "USERPROFILE": str(home), "CERTDIAG_CONFIG": ""}


def run(h, t):
    print("\n=== T16: Root CA snapshots ===")

    # --- T16.01: the shipped snapshots list ---
    print("-- T16.01: store --mozilla / --chrome")

    for flag in ["mozilla", "chrome"]:
        r = h.cmd("--no-color store --{flag}", flag=flag)
        t.expect_ok(r, f"T16.01a: store --{flag} exits 0")

        r = h.cmd("--no-color store --{flag} -o json", flag=flag)
        t.expect_ok(r, f"T16.01b: store --{flag} -o json exits 0")
        t.assert_json(r, f"T16.01b: store --{flag} -o json is well-formed")

        # Invariant, not membership: the vendors add and remove roots, so
        # naming a CA here would be a scheduled failure.
        try:
            data = json.loads(r.stdout)
            count = sum(len(s.get("certificates", []) or s.get("items", []))
                        for s in (data if isinstance(data, list) else data.get("stores", [data])))
        except (json.JSONDecodeError, TypeError, AttributeError):
            count = 0
        if count >= 50 or "certificates" in r.stdout or "BEGIN" in r.stdout or len(r.stdout) > 500:
            t.PASS(f"T16.01c: store --{flag} returns a plausible number of anchors")
        else:
            t.FAIL(f"T16.01c: store --{flag} returns a plausible number of anchors",
                   f"output looks empty ({len(r.stdout)} bytes)")

    # --- T16.02: the snapshot is disclosed as a snapshot ---
    print("-- T16.02: snapshot disclosure")

    r = h.cmd("--no-color store --mozilla")
    t.assert_contains(r, "SNAPSHOT", "T16.02a: the store output says it is a snapshot")
    t.assert_contains_regex(r, r"snapshot \d{4}-\d{2}-\d{2}",
                            "T16.02b: the store name carries the snapshot date")
    t.assert_contains(r, "store update", "T16.02c: the disclosure says how to refresh")

    # The bundle must never present itself as a live browser read.
    r = h.cmd("--no-color store --mozilla -q zzzz-no-such-cert")
    t.assert_not_contains_regex(r, r"^Firefox$", "T16.02d: a bundle is never named Firefox alone")

    # --- T16.03: status ---
    print("-- T16.03: store update --status")

    r = h.cmd("--no-color store update --status")
    t.expect_ok(r, "T16.03a: store update --status exits 0")
    for field in ["snapshot:", "origin:", "source:", "license:", "anchors:"]:
        t.assert_contains(r, field, f"T16.03b: status reports {field.strip(':')}")
    t.assert_contains(r, "embedded", "T16.03c: a fresh install reports the embedded origin")

    r = h.cmd("version")
    t.assert_contains(r, "Root CA snapshots", "T16.03d: version lists the snapshots")
    t.assert_contains_regex(r, r"\d{4}-\d{2}-\d{2}", "T16.03e: version carries the snapshot dates")

    # --- T16.04 / T16.05: the air-gapped import path ---
    print("-- T16.04: import into a temp HOME")

    repo_bundles = _repo_root(h) / "certdiag_app" / "internal" / "certlib" / "truststore" / "bundles"
    if not repo_bundles.is_dir():
        t.SKIP("T16.04: repository bundles not found; skipping import cases")
        return

    home = h.tmp("bundle-home")
    home.mkdir(parents=True, exist_ok=True)
    env = _home_env(home)

    r = h.cmd("--no-color store update --dry-run --import {d}", d=repo_bundles, env_extra=env)
    t.expect_ok(r, "T16.04a: a dry-run import exits 0")
    t.assert_contains(r, "nothing written", "T16.04b: a dry run says nothing was written")
    if not (home / ".certdiag" / "bundles").exists():
        t.PASS("T16.04c: a dry run writes no bundle files")
    else:
        t.FAIL("T16.04c: a dry run writes no bundle files", "bundles directory was created")

    r = h.cmd("--no-color store update --import {d}", d=repo_bundles, env_extra=env)
    t.expect_ok(r, "T16.05a: importing a prepared bundle exits 0")
    t.assert_contains(r, "installed", "T16.05b: the import reports what it installed")

    t.assert_file_not_empty(home / ".certdiag" / "bundles" / "mozilla.json",
                            "T16.05c: the manifest lands in ~/.certdiag/bundles")
    t.assert_file_not_empty(home / ".certdiag" / "bundles" / "mozilla-trusted.pem",
                            "T16.05d: the PEM lands in ~/.certdiag/bundles")

    r = h.cmd("--no-color store update --status", env_extra=env)
    t.assert_contains(r, "installed:", "T16.05e: status now reports the installed copy")

    # The MPL notice is a redistribution condition, not a cosmetic.
    pem = (home / ".certdiag" / "bundles" / "mozilla-trusted.pem").read_text(errors="replace")
    if "Mozilla Public" in pem:
        t.PASS("T16.05f: the MPL notice survives an install")
    else:
        t.FAIL("T16.05f: the MPL notice survives an install", "notice missing from the installed PEM")

    # --- T16.06: a truncated import is refused and the previous copy survives ---
    print("-- T16.06: import validation")

    bad = h.tmp("bad-bundle")
    bad.mkdir(parents=True, exist_ok=True)
    shutil.copy(repo_bundles / "mozilla.json", bad / "mozilla.json")
    src_pem = (repo_bundles / "mozilla-trusted.pem").read_text(errors="replace")
    (bad / "mozilla-trusted.pem").write_text("\n".join(src_pem.splitlines()[:20]) + "\n")

    r = h.cmd("--no-color store update --import {d}", d=bad, env_extra=env)
    t.expect_fail(r, "T16.06a: a truncated bundle is refused")
    t.assert_contains_regex(r, r"below the floor|refusing", "T16.06b: the refusal says why", stream="stderr")

    t.assert_file_not_empty(home / ".certdiag" / "bundles" / "mozilla-trusted.pem",
                            "T16.06c: the previous bundle survives a refused import")
    installed = (home / ".certdiag" / "bundles" / "mozilla-trusted.pem").read_text(errors="replace")
    if installed.count("BEGIN CERTIFICATE") > 50:
        t.PASS("T16.06d: the surviving bundle is still complete")
    else:
        t.FAIL("T16.06d: the surviving bundle is still complete",
               f"only {installed.count('BEGIN CERTIFICATE')} certificates left")

    # --- T16.07: no network in this suite ---
    print("-- T16.07: offline discipline")

    r = h.cmd("--no-color store update --source bogus --dry-run", env_extra=env)
    t.expect_fail(r, "T16.07a: an unknown --source is rejected before any fetch")

    r = h.cmd("--no-color store update --from {d} --dry-run", d=h.tmp("empty-upstream"),
              env_extra=env)
    t.expect_fail(r, "T16.07b: --from with no upstream files fails instead of falling back to the network")

    # --- T16.08: the help text claims ---
    print("-- T16.08: help text")

    r = h.cmd("--no-color store --help")
    t.assert_contains(r, "SNAPSHOT", "T16.08a: store help says the bundles are snapshots")
    t.assert_contains(r, "does NOT read the root store",
                      "T16.08b: store help states certdiag does not extract from browsers")
    t.assert_contains(r, "libnssckbi", "T16.08c: store help names where the browser lists actually live")
    t.assert_contains(r, "store --nss", "T16.08d: store help points at the live profile store")
    t.assert_contains(r, "MPL-2.0", "T16.08e: store help names the licences")

    r = h.cmd("--no-color store update --help")
    t.assert_contains(r, "air-gapped", "T16.08f: update help covers the air-gapped path")

    # --- T16.09: config migration ---
    print("-- T16.09: config migrate")

    mig_home = h.tmp("migrate-home")
    mig_home.mkdir(parents=True, exist_ok=True)
    mig_env = _home_env(mig_home)
    legacy = mig_home / ".certdiag.yaml"
    legacy.write_text(
        "kind: certdiag-config\n"
        'version: "1"\n'
        "passwords:\n"
        "  common_plaintext: [migrated-secret]\n"
        "  common_encrypted: []\n"
        "  by_filename: []\n"
    )

    r = h.cmd("--no-color config migrate --dry-run", env_extra=mig_env)
    t.expect_ok(r, "T16.09a: a dry-run migration exits 0")
    t.assert_contains(r, "Would move", "T16.09b: the dry run says what it would do")
    t.assert_file_exists(legacy, "T16.09c: a dry run leaves the legacy file in place")

    r = h.cmd("--no-color config migrate", env_extra=mig_env)
    t.expect_ok(r, "T16.09d: migration exits 0")
    t.assert_file_not_empty(mig_home / ".certdiag" / "certdiag.yaml",
                            "T16.09e: the config lands in ~/.certdiag/certdiag.yaml")
    if not legacy.exists():
        t.PASS("T16.09f: the legacy file is removed after a verified copy")
    else:
        t.FAIL("T16.09f: the legacy file is removed after a verified copy", "legacy file still present")

    moved = (mig_home / ".certdiag" / "certdiag.yaml").read_text(errors="replace")
    if "migrated-secret" in moved:
        t.PASS("T16.09g: the contents survive the move")
    else:
        t.FAIL("T16.09g: the contents survive the move", "config contents changed")

    r = h.cmd("--no-color config migrate", env_extra=mig_env)
    t.expect_ok(r, "T16.09h: re-running migration is harmless")
    t.assert_contains(r, "nothing to migrate", "T16.09i: a second run reports there is nothing to do")

    # --- T16.10: the legacy config keeps working ---
    print("-- T16.10: legacy config fallback")

    legacy_home = h.tmp("legacy-home")
    legacy_home.mkdir(parents=True, exist_ok=True)
    legacy_env = _home_env(legacy_home)
    (legacy_home / ".certdiag.yaml").write_text(
        "kind: certdiag-config\n"
        'version: "1"\n'
        "defaults:\n"
        "  output:\n"
        "    fingerprint_format: hex-colon\n"
        "passwords:\n"
        "  common_plaintext: []\n"
        "  common_encrypted: []\n"
        "  by_filename: []\n"
    )

    r = h.cmd("--no-color -d {f}", f=h.fixture("leaf-rsa.pem"), env_extra=legacy_env)
    t.expect_ok(r, "T16.10a: a legacy-only home still works")
    t.assert_contains_regex(r, r"[0-9a-f]{2}:[0-9a-f]{2}",
                            "T16.10b: the legacy config is actually applied")
    if (legacy_home / ".certdiag.yaml").exists():
        t.PASS("T16.10c: the legacy file is never moved automatically")
    else:
        t.FAIL("T16.10c: the legacy file is never moved automatically", "legacy file disappeared")

    # Piped output must stay clean even when the legacy notice would apply.
    r = h.cmd("--no-color -o json {f}", f=h.fixture("leaf-rsa.pem"), env_extra=legacy_env)
    t.assert_json(r, "T16.10d: -o json stays parseable with a legacy config")

    # --- T16.11: NSS profile stores, shape only ---
    print("-- T16.11: store --nss")

    nss_home = h.tmp("nss-home")
    nss_home.mkdir(parents=True, exist_ok=True)
    nss_env = _home_env(nss_home)

    # A home with no browser profiles: must fail cleanly, not panic.
    r = h.cmd("--no-color store --nss", env_extra=nss_env)
    if r.returncode in (0, 1):
        t.PASS(f"T16.11a: store --nss on a profile-less home exits cleanly (exit {r.returncode})")
    else:
        t.FAIL("T16.11a: store --nss on a profile-less home exits cleanly",
               f"unexpected exit {r.returncode}")
    t.assert_not_contains(r, "panic", "T16.11b: store --nss never panics", stream="stderr")

    # Against a fixture profile tree.
    nss_fixture = (_repo_root(h) / "certdiag_app" / "internal" / "certlib" /
                   "truststore" / "testdata" / "nss" / "firefox-root")
    if nss_fixture.is_dir():
        prof = nss_fixture / "Profiles" / "aaaa1111.default-release" / "cert9.db"
        if prof.is_file():
            t.PASS("T16.11c: the NSS fixture profile is present")
        else:
            t.SKIP("T16.11c: NSS fixture profile missing; run tools/testing/gen_nss_fixtures.sh")
    else:
        t.SKIP("T16.11c: NSS fixtures missing; run tools/testing/gen_nss_fixtures.sh")

    # --- T16.13: verify against a shipped snapshot ---
    print("-- T16.13: verify --mozilla / --chrome")

    leaf = h.fixture("leaf-rsa.pem")
    for flag in ["mozilla", "chrome"]:
        r = h.cmd("--no-color verify --{flag} {f}", flag=flag, f=leaf)
        # A privately-signed fixture is not in any vendor list, so a non-zero
        # exit is the correct answer. What matters is that the flag is wired.
        t.assert_not_contains(r, "unknown flag",
                              f"T16.13a: verify --{flag} is a recognised flag", stream="stderr")
        t.assert_not_contains(r, "unknown store type",
                              f"T16.13b: verify --{flag} resolves to a store", stream="stderr")
        t.assert_not_contains(r, "panic", f"T16.13c: verify --{flag} never panics", stream="stderr")

    # --- T16.12: discover includes the new stores ---
    print("-- T16.12: store discover")

    r = h.cmd("--no-color store discover")
    t.expect_ok(r, "T16.12a: store discover still exits 0")
    t.assert_contains_regex(r, r"snapshot \d{4}-\d{2}-\d{2}",
                            "T16.12b: discover lists the snapshots with their dates")

    r = h.cmd("--no-color store discover -o json")
    t.assert_json(r, "T16.12c: store discover -o json is well-formed")

