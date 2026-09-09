#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BINARY="${REPO_ROOT}/certdiag_app/dist/certdiag"
PASSED=0
FAILED=0
SKIPPED=0
TMPDIR=""

# Base host for badssl endpoints. Override to point at a local VM/Docker instance.
# Example: BADSSL_HOST=192.168.1.100 ./badssl_remote_test.sh
BADSSL_HOST="${BADSSL_HOST:-badssl.com}"

setup() {
    TMPDIR="$(mktemp -d)"
    if [[ ! -x "${BINARY}" ]]; then
        echo "ERROR: certdiag binary not found. Run: cd certdiag_app && make build"
        exit 1
    fi
}

cleanup() {
    [[ -n "${TMPDIR}" && -d "${TMPDIR}" ]] && rm -rf "${TMPDIR}"
    echo ""
    echo "========================================="
    echo "Results: ${PASSED} passed, ${FAILED} failed, ${SKIPPED} skipped"
    echo "========================================="
    [[ ${FAILED} -eq 0 ]]
}
trap cleanup EXIT

PASS() { echo "  PASS: $1"; PASSED=$((PASSED+1)); }
FAIL() { echo "  FAIL: $1 -- $2"; FAILED=$((FAILED+1)); }
SKIP() { echo "  SKIP: $1"; SKIPPED=$((SKIPPED+1)); }

assert_exit_code() {
    if [[ "$1" -eq "$2" ]]; then PASS "$3"; else FAIL "$3" "expected exit $1, got $2"; fi
}

assert_output_contains() {
    if echo "$1" | grep -qi "$2"; then PASS "$3"; else FAIL "$3" "output missing '$2'"; fi
}

assert_output_not_contains() {
    if ! echo "$1" | grep -qi "$2"; then PASS "$3"; else FAIL "$3" "output unexpectedly contains '$2'"; fi
}

assert_file_exists() {
    if [[ -f "$1" ]]; then PASS "$2"; else FAIL "$2" "file not found: $1"; fi
}

assert_file_not_empty() {
    if [[ -s "$1" ]]; then PASS "$2"; else FAIL "$2" "file empty or missing: $1"; fi
}

# Run certdiag remote and capture output + exit code
run_remote() {
    local output exit_code
    set +e
    output=$("$BINARY" remote --no-color "$@" 2>&1)
    exit_code=$?
    set -e
    echo "$output"
    return $exit_code
}

# Check if a badssl endpoint is reachable (quick TLS probe)
check_reachable() {
    local host="$1"
    local port="${2:-443}"
    if command -v curl &>/dev/null; then
        curl -s -o /dev/null --connect-timeout 5 -k "https://${host}:${port}/" 2>/dev/null
    elif command -v openssl &>/dev/null; then
        echo | openssl s_client -connect "${host}:${port}" -servername "$host" 2>/dev/null | grep -q "CONNECTED"
    else
        # Assume reachable
        return 0
    fi
}

# =========================================================================
setup
echo "badssl.com Remote Tests -- $(date)"
echo "Binary: ${BINARY}"
echo "Host:   ${BADSSL_HOST}"
echo ""

# Pre-flight: check badssl host is reachable at all
if ! check_reachable "${BADSSL_HOST}"; then
    echo "FATAL: ${BADSSL_HOST} is unreachable. Skipping all tests."
    exit 0
fi
echo "${BADSSL_HOST} is reachable"
echo ""

# =========================================================================
echo "=== 1. Valid Certificates (positive tests) ==="

echo "--- sha256.${BADSSL_HOST} ---"
set +e; output=$(run_remote fetch "sha256.${BADSSL_HOST}" 2>&1); rc=$?; set -e
assert_exit_code 0 "$rc" "sha256: fetch exits 0"
assert_output_contains "$output" "remote/tls" "sha256: output contains TLS version"
assert_output_contains "$output" "Chain" "sha256: output contains chain"
assert_output_contains "$output" "Subject:" "sha256: output contains Subject"
assert_output_contains "$output" "Issuer:" "sha256: output contains Issuer"
assert_output_contains "$output" "Validity:" "sha256: output contains Validity"
assert_output_contains "$output" "SHA256-RSA" "sha256: cert uses SHA256-RSA signature"
assert_output_contains "$output" "SANs:" "sha256: output contains SANs"

echo "--- rsa2048.${BADSSL_HOST} ---"
set +e; output=$(run_remote fetch "rsa2048.${BADSSL_HOST}" 2>&1); rc=$?; set -e
assert_exit_code 0 "$rc" "rsa2048: fetch exits 0"
assert_output_contains "$output" "RSA-2048" "rsa2048: shows RSA-2048 key"

echo "--- rsa4096.${BADSSL_HOST} ---"
set +e; output=$(run_remote fetch "rsa4096.${BADSSL_HOST}" 2>&1); rc=$?; set -e
assert_exit_code 0 "$rc" "rsa4096: fetch exits 0"
assert_output_contains "$output" "RSA-4096" "rsa4096: shows RSA-4096 key"

echo "--- ecc256.${BADSSL_HOST} ---"
set +e; output=$(run_remote fetch "ecc256.${BADSSL_HOST}" 2>&1); rc=$?; set -e
assert_exit_code 0 "$rc" "ecc256: fetch exits 0"
assert_output_contains "$output" "ECDSA" "ecc256: shows ECDSA key"

echo "--- ecc384.${BADSSL_HOST} ---"
set +e; output=$(run_remote fetch "ecc384.${BADSSL_HOST}" 2>&1); rc=$?; set -e
assert_exit_code 0 "$rc" "ecc384: fetch exits 0"
assert_output_contains "$output" "ECDSA" "ecc384: shows ECDSA key"

# =========================================================================
echo ""
echo "=== 2. Certificate Issues (fetch + check) ==="

echo "--- expired.${BADSSL_HOST} ---"
set +e; output=$(run_remote fetch "expired.${BADSSL_HOST}" 2>&1); rc=$?; set -e
assert_exit_code 0 "$rc" "expired: fetch exits 0 (no --expiry-warn)"
assert_output_contains "$output" "Subject:" "expired: shows cert despite expiry"

set +e; output=$(run_remote fetch --expiry-warn 3650 "expired.${BADSSL_HOST}" 2>&1); rc=$?; set -e
assert_exit_code 2 "$rc" "expired: fetch --expiry-warn exits 2 (expired)"
assert_output_contains "$output" "EXPIRED" "expired: shows EXPIRED status"

set +e; output=$(run_remote check "expired.${BADSSL_HOST}" 2>&1); rc=$?; set -e
assert_exit_code 2 "$rc" "expired: check exits 2 (critical)"
assert_output_contains "$output" "expired" "expired: check reports expired issue"

echo "--- wrong.host.${BADSSL_HOST} ---"
set +e; output=$(run_remote fetch "wrong.host.${BADSSL_HOST}" 2>&1); rc=$?; set -e
assert_exit_code 0 "$rc" "wrong.host: fetch exits 0"
assert_output_contains "$output" "Subject:" "wrong.host: shows cert despite mismatch"

set +e; output=$(run_remote check "wrong.host.${BADSSL_HOST}" 2>&1); rc=$?; set -e
assert_exit_code 2 "$rc" "wrong.host: check exits 2 (critical)"
assert_output_contains "$output" "remote_hostname_mismatch" "wrong.host: check reports hostname mismatch"

echo "--- self-signed.${BADSSL_HOST} ---"
set +e; output=$(run_remote fetch "self-signed.${BADSSL_HOST}" 2>&1); rc=$?; set -e
assert_exit_code 0 "$rc" "self-signed: fetch exits 0"
assert_output_contains "$output" "Chain (1 certificate" "self-signed: chain has 1 cert"

set +e; output=$(run_remote check "self-signed.${BADSSL_HOST}" 2>&1); rc=$?; set -e
# self-signed gets remote_self_signed (WARNING) at minimum
if [[ "$rc" -ge 1 ]]; then PASS "self-signed: check exits >= 1"; else FAIL "self-signed: check exits >= 1" "got exit $rc"; fi
assert_output_contains "$output" "remote_self_signed" "self-signed: check reports self-signed"

echo "--- untrusted-root.${BADSSL_HOST} ---"
set +e; output=$(run_remote fetch "untrusted-root.${BADSSL_HOST}" 2>&1); rc=$?; set -e
assert_exit_code 0 "$rc" "untrusted-root: fetch exits 0"
assert_output_contains "$output" "Chain" "untrusted-root: shows chain"

set +e; output=$(run_remote check "untrusted-root.${BADSSL_HOST}" 2>&1); rc=$?; set -e
if [[ "$rc" -ge 1 ]]; then PASS "untrusted-root: check exits >= 1"; else FAIL "untrusted-root: check exits >= 1" "got exit $rc"; fi
assert_output_contains "$output" "remote_chain_untrusted" "untrusted-root: check reports untrusted chain"

echo "--- incomplete-chain.${BADSSL_HOST} ---"
set +e; output=$(run_remote fetch "incomplete-chain.${BADSSL_HOST}" 2>&1); rc=$?; set -e
assert_exit_code 0 "$rc" "incomplete-chain: fetch exits 0"

set +e; output=$(run_remote check "incomplete-chain.${BADSSL_HOST}" 2>&1); rc=$?; set -e
if [[ "$rc" -ge 1 ]]; then PASS "incomplete-chain: check exits >= 1"; else FAIL "incomplete-chain: check exits >= 1" "got exit $rc"; fi
assert_output_contains "$output" "remote_chain_incomplete" "incomplete-chain: check reports incomplete chain"

# =========================================================================
echo ""
echo "=== 3. Remote check details ==="

echo "--- check with category filter ---"
set +e; output=$(run_remote check --category remote "self-signed.${BADSSL_HOST}" 2>&1); rc=$?; set -e
assert_output_contains "$output" "remote_self_signed" "category filter: shows remote issues"
assert_output_not_contains "$output" "expired" "category filter: excludes non-remote issues"

echo "--- check with severity filter ---"
set +e; output=$(run_remote check --severity critical "wrong.host.${BADSSL_HOST}" 2>&1); rc=$?; set -e
assert_output_contains "$output" "remote_hostname_mismatch" "severity filter: shows critical issues"

echo "--- check with --strict flag ---"
set +e; output=$(run_remote check --strict "self-signed.${BADSSL_HOST}" 2>&1); rc=$?; set -e
assert_exit_code 2 "$rc" "strict: warnings promoted to exit 2"

# =========================================================================
echo ""
echo "=== 4. JSON output format ==="

if ! command -v jq &>/dev/null; then
    SKIP "JSON validation tests (jq not installed)"
else
    echo "--- fetch JSON ---"
    set +e; output=$(run_remote fetch -o json "sha256.${BADSSL_HOST}" 2>&1); rc=$?; set -e
    assert_exit_code 0 "$rc" "json fetch: exits 0"

    if echo "$output" | jq . >/dev/null 2>&1; then
        PASS "json fetch: valid JSON"
    else
        FAIL "json fetch: valid JSON" "jq parse failed"
    fi

    # Validate JSON structure
    targets=$(echo "$output" | jq '.targets | length')
    if [[ "$targets" -ge 1 ]]; then PASS "json fetch: has targets array"; else FAIL "json fetch: has targets array" "got $targets"; fi

    target_name=$(echo "$output" | jq -r '.targets[0].target')
    assert_output_contains "$target_name" "sha256.${BADSSL_HOST}" "json fetch: target field correct"

    tls_ver=$(echo "$output" | jq -r '.targets[0].connection.tls_version')
    if [[ "$tls_ver" != "null" && -n "$tls_ver" ]]; then PASS "json fetch: has tls_version"; else FAIL "json fetch: has tls_version" "got $tls_ver"; fi

    cert_count=$(echo "$output" | jq '.targets[0].certificates | length')
    if [[ "$cert_count" -ge 1 ]]; then PASS "json fetch: has certificates"; else FAIL "json fetch: has certificates" "got $cert_count"; fi

    cert_subject=$(echo "$output" | jq -r '.targets[0].certificates[0].subject')
    if [[ "$cert_subject" != "null" && -n "$cert_subject" ]]; then PASS "json fetch: cert has subject"; else FAIL "json fetch: cert has subject" "got $cert_subject"; fi

    cert_role=$(echo "$output" | jq -r '.targets[0].certificates[0].role')
    assert_output_contains "$cert_role" "leaf" "json fetch: first cert is leaf"

    echo "--- check JSON ---"
    set +e; output=$(run_remote check -o json "self-signed.${BADSSL_HOST}" 2>&1); rc=$?; set -e

    if echo "$output" | jq . >/dev/null 2>&1; then
        PASS "json check: valid JSON"
    else
        FAIL "json check: valid JSON" "jq parse failed"
    fi

    issue_count=$(echo "$output" | jq '.targets[0].issues | length')
    if [[ "$issue_count" -ge 1 ]]; then PASS "json check: has issues"; else FAIL "json check: has issues" "got $issue_count"; fi

    has_self_signed=$(echo "$output" | jq '[.targets[0].issues[].check_id] | any(. == "remote_self_signed")')
    if [[ "$has_self_signed" == "true" ]]; then
        PASS "json check: has remote_self_signed issue"
    else
        FAIL "json check: has remote_self_signed issue" "not found in issues"
    fi

    summary_total=$(echo "$output" | jq '.summary.total')
    if [[ "$summary_total" -ge 1 ]]; then PASS "json check: summary has total"; else FAIL "json check: summary has total" "got $summary_total"; fi

    echo "--- fetch JSON: expired cert ---"
    set +e; output=$(run_remote fetch -o json "expired.${BADSSL_HOST}" 2>&1); rc=$?; set -e

    if echo "$output" | jq . >/dev/null 2>&1; then
        PASS "json expired: valid JSON"
    else
        FAIL "json expired: valid JSON" "jq parse failed"
    fi

    not_after=$(echo "$output" | jq -r '.targets[0].certificates[0].not_after')
    if [[ "$not_after" != "null" && -n "$not_after" ]]; then PASS "json expired: has not_after"; else FAIL "json expired: has not_after" "got $not_after"; fi
fi

# =========================================================================
echo ""
echo "=== 5. YAML output format ==="

echo "--- fetch YAML ---"
set +e; output=$(run_remote fetch -o yaml "sha256.${BADSSL_HOST}" 2>&1); rc=$?; set -e
assert_exit_code 0 "$rc" "yaml fetch: exits 0"
assert_output_contains "$output" "targets:" "yaml fetch: has targets key"
assert_output_contains "$output" "tls_version:" "yaml fetch: has tls_version"
assert_output_contains "$output" "certificates:" "yaml fetch: has certificates"

echo "--- check YAML ---"
set +e; output=$(run_remote check -o yaml "self-signed.${BADSSL_HOST}" 2>&1); rc=$?; set -e
assert_output_contains "$output" "targets:" "yaml check: has targets key"
assert_output_contains "$output" "issues:" "yaml check: has issues key"
assert_output_contains "$output" "remote_self_signed" "yaml check: has self-signed issue"

# =========================================================================
echo ""
echo "=== 6. Save chain and save leaf ==="

echo "--- save-chain ---"
set +e; output=$(run_remote fetch --save-chain -O "${TMPDIR}" "sha256.${BADSSL_HOST}" 2>&1); rc=$?; set -e
assert_exit_code 0 "$rc" "save-chain: exits 0"
assert_output_contains "$output" "Saved:" "save-chain: prints saved path"

chain_files=$(find "${TMPDIR}" -name "*.pem" -type f 2>/dev/null | wc -l | tr -d ' ')
if [[ "$chain_files" -ge 1 ]]; then PASS "save-chain: created PEM file"; else FAIL "save-chain: created PEM file" "found $chain_files files"; fi

# Verify saved file contains a PEM certificate
saved_file=$(find "${TMPDIR}" -name "*.pem" -type f | head -1)
if [[ -n "$saved_file" ]]; then
    if grep -q "BEGIN CERTIFICATE" "$saved_file"; then
        PASS "save-chain: file contains PEM certificate"
    else
        FAIL "save-chain: file contains PEM certificate" "no BEGIN CERTIFICATE found"
    fi
fi

# Clean up for next save test
rm -f "${TMPDIR}"/*.pem

echo "--- save-leaf ---"
set +e; output=$(run_remote fetch --save-leaf -O "${TMPDIR}" "sha256.${BADSSL_HOST}" 2>&1); rc=$?; set -e
assert_exit_code 0 "$rc" "save-leaf: exits 0"
assert_output_contains "$output" "Saved:" "save-leaf: prints saved path"

leaf_file=$(find "${TMPDIR}" -name "*.pem" -type f | head -1)
assert_file_exists "$leaf_file" "save-leaf: PEM file created"
if [[ -n "$leaf_file" ]]; then
    cert_count=$(grep -c "BEGIN CERTIFICATE" "$leaf_file" || true)
    if [[ "$cert_count" -eq 1 ]]; then PASS "save-leaf: file contains exactly 1 cert"; else FAIL "save-leaf: file contains exactly 1 cert" "found $cert_count certs"; fi
fi

rm -f "${TMPDIR}"/*.pem

echo "--- save-to specific path ---"
set +e; output=$(run_remote fetch --save-to "${TMPDIR}/mychain.pem" "sha256.${BADSSL_HOST}" 2>&1); rc=$?; set -e
assert_exit_code 0 "$rc" "save-to: exits 0"
assert_file_exists "${TMPDIR}/mychain.pem" "save-to: file at specified path"
assert_file_not_empty "${TMPDIR}/mychain.pem" "save-to: file is not empty"

rm -f "${TMPDIR}"/*.pem

echo "--- save-all (individual certs) ---"
set +e; output=$(run_remote fetch --save-all -O "${TMPDIR}" "sha256.${BADSSL_HOST}" 2>&1); rc=$?; set -e
assert_exit_code 0 "$rc" "save-all: exits 0"

all_files=$(find "${TMPDIR}" -name "*.pem" -type f 2>/dev/null | wc -l | tr -d ' ')
if [[ "$all_files" -ge 1 ]]; then PASS "save-all: created individual PEM files"; else FAIL "save-all: created individual PEM files" "found $all_files files"; fi

rm -f "${TMPDIR}"/*.pem

# =========================================================================
echo ""
echo "=== 7. TLS version tests ==="

echo "--- tls-v1-2.${BADSSL_HOST}:1012 ---"
if check_reachable "tls-v1-2.${BADSSL_HOST}" 1012; then
    set +e; output=$(run_remote fetch "tls-v1-2.${BADSSL_HOST}:1012" 2>&1); rc=$?; set -e
    assert_exit_code 0 "$rc" "tls12: fetch exits 0"
    assert_output_contains "$output" "TLS 1.2" "tls12: shows TLS 1.2"
else
    SKIP "tls12: endpoint unreachable"
fi

echo "--- tls-v1-0.${BADSSL_HOST}:1010 (deprecated) ---"
if check_reachable "tls-v1-0.${BADSSL_HOST}" 1010; then
    set +e; output=$(run_remote fetch --tls-version tls1.0 "tls-v1-0.${BADSSL_HOST}:1010" 2>&1); rc=$?; set -e
    if [[ "$rc" -eq 0 ]]; then
        PASS "tls10: fetch connects with --tls-version tls1.0"
        assert_output_contains "$output" "TLS 1.0" "tls10: shows TLS 1.0"
    elif [[ "$rc" -eq 3 ]]; then
        SKIP "tls10: connection failed (Go may not support TLS 1.0)"
    else
        FAIL "tls10: fetch exit code" "expected 0 or 3, got $rc"
    fi

    # Check should warn about weak TLS
    set +e; output=$(run_remote check --tls-version tls1.0 "tls-v1-0.${BADSSL_HOST}:1010" 2>&1); rc=$?; set -e
    if [[ "$rc" -eq 0 || "$rc" -eq 1 ]]; then
        assert_output_contains "$output" "remote_weak_tls" "tls10 check: reports weak TLS"
    elif [[ "$rc" -eq 3 ]]; then
        SKIP "tls10 check: connection failed"
    fi
else
    SKIP "tls10: endpoint unreachable"
fi

echo "--- tls-v1-1.${BADSSL_HOST}:1011 (deprecated) ---"
if check_reachable "tls-v1-1.${BADSSL_HOST}" 1011; then
    set +e; output=$(run_remote fetch --tls-version tls1.1 "tls-v1-1.${BADSSL_HOST}:1011" 2>&1); rc=$?; set -e
    if [[ "$rc" -eq 0 ]]; then
        PASS "tls11: fetch connects with --tls-version tls1.1"
        assert_output_contains "$output" "TLS 1.1" "tls11: shows TLS 1.1"
    elif [[ "$rc" -eq 3 ]]; then
        SKIP "tls11: connection failed (Go may not support TLS 1.1)"
    else
        FAIL "tls11: fetch exit code" "expected 0 or 3, got $rc"
    fi
else
    SKIP "tls11: endpoint unreachable"
fi

# =========================================================================
echo ""
echo "=== 8. Key algorithm and size display ==="

echo "--- rsa8192.${BADSSL_HOST} ---"
if check_reachable "rsa8192.${BADSSL_HOST}"; then
    set +e; output=$(run_remote fetch "rsa8192.${BADSSL_HOST}" 2>&1); rc=$?; set -e
    assert_exit_code 0 "$rc" "rsa8192: fetch exits 0"
    assert_output_contains "$output" "RSA-8192" "rsa8192: shows RSA-8192 key"
else
    SKIP "rsa8192: endpoint unreachable"
fi

echo "--- extended-validation.${BADSSL_HOST} ---"
if check_reachable "extended-validation.${BADSSL_HOST}"; then
    set +e; output=$(run_remote fetch "extended-validation.${BADSSL_HOST}" 2>&1); rc=$?; set -e
    assert_exit_code 0 "$rc" "ev: fetch exits 0"
    assert_output_contains "$output" "Chain" "ev: shows certificate chain"
    assert_output_contains "$output" "Subject:" "ev: shows Subject"
else
    SKIP "ev: endpoint unreachable"
fi

# =========================================================================
echo ""
echo "=== 9. Connection options ==="

echo "--- fetch with --details ---"
set +e; output=$(run_remote fetch --details "sha256.${BADSSL_HOST}" 2>&1); rc=$?; set -e
assert_exit_code 0 "$rc" "details: fetch exits 0"
assert_output_contains "$output" "Subject:" "details: shows certificate subject"

echo "--- fetch with --single-ip ---"
set +e; output=$(run_remote fetch --single-ip "sha256.${BADSSL_HOST}" 2>&1); rc=$?; set -e
assert_exit_code 0 "$rc" "single-ip: fetch exits 0"
assert_output_not_contains "$output" "Multi-IP" "single-ip: no multi-ip section"

echo "--- fetch with SNI override ---"
set +e; output=$(run_remote fetch --hostname "sha256.${BADSSL_HOST}" "sha256.${BADSSL_HOST}" 2>&1); rc=$?; set -e
assert_exit_code 0 "$rc" "sni-override: fetch exits 0"

echo "--- fetch with timeout ---"
set +e; output=$(run_remote fetch --timeout 15s "sha256.${BADSSL_HOST}" 2>&1); rc=$?; set -e
assert_exit_code 0 "$rc" "timeout: fetch exits 0"

# =========================================================================
echo ""
echo "=== 10. Connection errors ==="

echo "--- unreachable host (non-existent domain) ---"
set +e; output=$(run_remote fetch --timeout 3s this-domain-does-not-exist-certdiag-test.invalid 2>&1); rc=$?; set -e
if [[ "$rc" -ne 0 ]]; then PASS "unreachable: non-zero exit"; else FAIL "unreachable: non-zero exit" "got exit 0"; fi

echo "--- wrong port ---"
set +e; output=$(run_remote fetch --timeout 3s "sha256.${BADSSL_HOST}:12345" 2>&1); rc=$?; set -e
if [[ "$rc" -ne 0 ]]; then PASS "wrong-port: non-zero exit"; else FAIL "wrong-port: non-zero exit" "got exit 0"; fi

# =========================================================================
echo ""
echo "=== 11. Multi-target fetch ==="

echo "--- fetch multiple targets ---"
set +e; output=$(run_remote fetch "sha256.${BADSSL_HOST}" "rsa2048.${BADSSL_HOST}" 2>&1); rc=$?; set -e
assert_exit_code 0 "$rc" "multi-target: fetch exits 0"
assert_output_contains "$output" "sha256.${BADSSL_HOST}" "multi-target: shows first target"
assert_output_contains "$output" "rsa2048.${BADSSL_HOST}" "multi-target: shows second target"
assert_output_contains "$output" "Summary:" "multi-target: shows summary"
assert_output_contains "$output" "2 of 2" "multi-target: summary shows 2/2"

echo "--- check multiple targets ---"
set +e; output=$(run_remote check "sha256.${BADSSL_HOST}" "self-signed.${BADSSL_HOST}" 2>&1); rc=$?; set -e
if [[ "$rc" -ge 1 ]]; then PASS "multi-target check: exits >= 1 (self-signed has issues)"; else FAIL "multi-target check: exits >= 1" "got exit $rc"; fi
assert_output_contains "$output" "Targets: 2 total" "multi-target check: shows 2 targets"

# =========================================================================
echo ""
echo "=== 12. 1000-sans.${BADSSL_HOST} ==="

if check_reachable "1000-sans.${BADSSL_HOST}"; then
    set +e; output=$(run_remote fetch "1000-sans.${BADSSL_HOST}" 2>&1); rc=$?; set -e
    assert_exit_code 0 "$rc" "1000-sans: fetch exits 0"
    assert_output_contains "$output" "SANs:" "1000-sans: shows SANs"

    if command -v jq &>/dev/null; then
        set +e; output=$(run_remote fetch -o json "1000-sans.${BADSSL_HOST}" 2>&1); rc=$?; set -e
        san_count=$(echo "$output" | jq '.targets[0].certificates[0].sans | length')
        if [[ "$san_count" -ge 100 ]]; then
            PASS "1000-sans json: has $san_count SANs"
        else
            FAIL "1000-sans json: expected many SANs" "got $san_count"
        fi
    fi
else
    SKIP "1000-sans: endpoint unreachable"
fi

# =========================================================================
echo ""
echo "=== 13. no-common-name / no-subject ==="

echo "--- no-common-name.${BADSSL_HOST} ---"
if check_reachable "no-common-name.${BADSSL_HOST}"; then
    set +e; output=$(run_remote fetch "no-common-name.${BADSSL_HOST}" 2>&1); rc=$?; set -e
    assert_exit_code 0 "$rc" "no-cn: fetch exits 0"
    assert_output_contains "$output" "Chain" "no-cn: shows chain"
else
    SKIP "no-cn: endpoint unreachable"
fi

echo "--- no-subject.${BADSSL_HOST} ---"
if check_reachable "no-subject.${BADSSL_HOST}"; then
    set +e; output=$(run_remote fetch "no-subject.${BADSSL_HOST}" 2>&1); rc=$?; set -e
    assert_exit_code 0 "$rc" "no-subject: fetch exits 0"
    assert_output_contains "$output" "Chain" "no-subject: shows chain"
else
    SKIP "no-subject: endpoint unreachable"
fi

# =========================================================================
echo ""
echo "=== 14. HTTP subcommand with badssl ==="

echo "--- http sha256.${BADSSL_HOST} ---"
set +e; output=$(run_remote http "sha256.${BADSSL_HOST}" 2>&1); rc=$?; set -e
assert_exit_code 0 "$rc" "http: exits 0"
assert_output_contains "$output" "200" "http: shows status 200"

echo ""
echo "All badssl remote tests completed."
