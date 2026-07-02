#!/usr/bin/env bash
# Integration test: verify --patches selective patching across all
# available WoW Classic client binaries.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_DIR/target/debug/wow-patcher"
SOURCE_DIR="$HOME/Downloads/battle.net/wow_classic"
WORK_DIR="$PROJECT_DIR/tests/scratch"
PASS=0
FAIL=0
TIMEOUT_SEC=15

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"

# Find all executables
shopt -s nullglob
declare -a BUILD_ENTRIES=()
while IFS= read -r -d '' exe; do
    BUILD_ENTRIES+=("$exe")
done < <(find "$SOURCE_DIR" \( -name 'Wow.exe' -o -name 'WowClassic.exe' \) ! -name '*.dump.exe' -print0 2>/dev/null)

if [ ${#BUILD_ENTRIES[@]} -eq 0 ]; then
    echo "ERROR: No executables found in $SOURCE_DIR"
    exit 1
fi

echo "Found ${#BUILD_ENTRIES[@]} executables"
echo

# Helper: extract build name from path
build_label() {
    echo "$1" | sed -n 's|.*/wow_classic/\([^/]*\)/.*|\1|p'
}

# Helper: check if the standalone portal suffix survived in output.
# The cert-bundle JSON (1.14.x / 2.5.3) has URI entries like
# "cn.actual.battle.net", so we need to ensure we're matching the
# standalone ".actual.battle.net" that the patcher targets, not the
# longer prefixed variants inside the JSON.
portal_survived() {
    local file="$1"
    # Pattern: ".actual.battle.net" appears as a standalone suffix.
    # Cert bundle URIs like "cn.actual.battle.net" won't match because
    # we anchor to a non-alpha character before the dot.
    (
        set +o pipefail
        strings "$file" 2>/dev/null | grep -qP '(?<![a-zA-Z])\.actual\.battle\.net\b'
    )
}

# Helper: check if Blizzard version strings survived.
version_survived() {
    local file="$1"
    (
        set +o pipefail
        strings "$file" 2>/dev/null | grep -qF "patch.battle.net:1119"
    ) ||
        (
            set +o pipefail
            strings "$file" 2>/dev/null | grep -qF "version.battle.net"
        )
}

# =========================================================================
# Phase 1: Discover available patterns on all builds
# =========================================================================
echo "=== Phase 1: Discover available patterns (--patches all) ==="
echo

for exe in "${BUILD_ENTRIES[@]}"; do
    label=$(build_label "$exe")
    echo "--- $label ($(basename "$exe")) ---"
    timeout "$TIMEOUT_SEC" "$BINARY" -l "$exe" -o /dev/null --patches all --dry-run -v 2>&1 |
        grep -E '^\s*(✓|✗|⚠|ℹ|⋯|Detected|Patch groups:)' || echo "  (no output)"
    echo
done

# =========================================================================
# Phase 2: --patches version,cdns
# =========================================================================
echo "=== Phase 2: --patches version,cdns ==="
echo "Expected: version and CDNs patched; RSA, portal, Ed25519 untouched."
echo

for exe in "${BUILD_ENTRIES[@]}"; do
    label=$(build_label "$exe")
    safe=$(echo "$label" | tr '.-' '__')
    input_copy="$WORK_DIR/${safe}_input.exe"
    output="$WORK_DIR/${safe}_vcdns.exe"

    cp "$exe" "$input_copy"

    set +e
    timeout "$TIMEOUT_SEC" "$BINARY" -l "$input_copy" -o "$output" --patches "version,cdns" -v 2>&1
    rc=$?
    set -e

    echo "--- $label (rc=$rc) ---"

    if [ -f "$output" ]; then
        if portal_survived "$output"; then
            echo "  ✓ portal NOT patched"
            PASS=$((PASS + 1))
        else
            echo "  ✗ portal WAS patched (should NOT have been)"
            FAIL=$((FAIL + 1))
        fi
    else
        echo "  ⚠ output file missing"
    fi
    echo
done

# =========================================================================
# Phase 3: --patches rsa,portal
# =========================================================================
echo "=== Phase 3: --patches rsa,portal ==="
echo "Expected: RSA and portal patched; version/CDN URLs untouched."
echo

for exe in "${BUILD_ENTRIES[@]}"; do
    label=$(build_label "$exe")
    safe=$(echo "$label" | tr '.-' '__')
    input_copy="$WORK_DIR/${safe}_input_rp.exe"
    output="$WORK_DIR/${safe}_rp.exe"

    cp "$exe" "$input_copy"

    set +e
    timeout "$TIMEOUT_SEC" "$BINARY" -l "$input_copy" -o "$output" --patches "rsa,portal" -v 2>&1
    rc=$?
    set -e

    echo "--- $label (rc=$rc) ---"

    if [ -f "$output" ]; then
        if portal_survived "$output"; then
            echo "  ✗ portal NOT patched"
            FAIL=$((FAIL + 1))
        else
            echo "  ✓ portal patched"
            PASS=$((PASS + 1))
        fi
        if version_survived "$output"; then
            echo "  ✓ version URL retained (not patched)"
        else
            echo "  ⚠ no version URL strings in output"
        fi
    else
        echo "  ⚠ output file missing"
    fi
    echo
done

# =========================================================================
# Phase 4: Single-group tests on 1.13.2
# =========================================================================
echo "=== Phase 4: Single-group tests on 1.13.2 ==="

REFERENCE="$SOURCE_DIR/1.13.2.31650.windows-win64/_classic_/Wow.exe"
if [ ! -f "$REFERENCE" ]; then
    echo "SKIP: 1.13.2 reference not found"
else
    echo "Reference: $REFERENCE"
    cp "$REFERENCE" "$WORK_DIR/ref_1132.exe"

    for group in rsa portal version cdns; do
        cp "$WORK_DIR/ref_1132.exe" "$WORK_DIR/ref_1132_${group}.exe"
        echo "--- --patches $group (dry-run) ---"
        "$BINARY" -l "$WORK_DIR/ref_1132_${group}.exe" -o /dev/null --patches "$group" --dry-run -v 2>&1 |
            grep -E '^\s*(✓|✗|⚠|⋯)'
        echo
    done

    # Invalid group name
    echo "--- Invalid group name ---"
    set +e
    "$BINARY" -l "$REFERENCE" -o "$WORK_DIR/bad.exe" --patches "bogus" --dry-run 2>&1
    echo "  (expected: error about unknown patch group)"
    set -e
    echo
fi

# =========================================================================
# Summary
# =========================================================================
echo "=========================================="
echo "Results: $PASS passed, $FAIL failed"
echo "Work dir: $WORK_DIR"
echo "=========================================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
