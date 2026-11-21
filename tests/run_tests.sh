#!/usr/bin/env bash
# pcapstat integration test suite. Run from anywhere; invoked by `make test`.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BIN="./bin/pcapstat"
ASAN_BIN="./bin/pcapstat-asan"
SAMPLE="samples/demo.pcap"
PNGS=(traffic_timeline.png protocol_ports.png packet_sizes.png tcp_flags.png)

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/pcapstat_test.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT INT TERM

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); printf '  [PASS] %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  [FAIL] %s\n' "$1"; }

# expect_rc <expected: 0|nonzero> <description> <cmd...>
expect_rc() {
    local want="$1" desc="$2"; shift 2
    local rc=0
    "$@" >"$TMP_ROOT/last.log" 2>&1 || rc=$?
    if { [ "$want" = 0 ] && [ "$rc" -eq 0 ]; } ||
       { [ "$want" = nonzero ] && [ "$rc" -ne 0 ]; }; then
        pass "$desc (rc=$rc)"
    else
        fail "$desc (rc=$rc, expected $want)"
        sed 's/^/        /' "$TMP_ROOT/last.log"
    fi
}

# check_outputs <dir> <label>
check_outputs() {
    local dir="$1" label="$2" f
    for f in "${PNGS[@]}"; do
        if [ -s "$dir/$f" ] && file -b "$dir/$f" | grep -q '^PNG image data'; then
            pass "$label: $f is a non-empty PNG"
        else
            fail "$label: $f missing, empty, or not a PNG"
        fi
    done
    if [ -s "$dir/report.pdf" ] && file -b "$dir/report.pdf" | grep -q '^PDF document'; then
        pass "$label: report.pdf is a non-empty PDF"
    else
        fail "$label: report.pdf missing, empty, or not a PDF"
    fi
}

# check_sanitizers <log> <label>
check_sanitizers() {
    if grep -qE 'ERROR: (Address|Leak)Sanitizer|runtime error:' "$1"; then
        fail "$2: sanitizer errors reported"
        sed 's/^/        /' "$1"
    else
        pass "$2: no ASan/UBSan errors"
    fi
}

for b in "$BIN" "$ASAN_BIN"; do
    [ -x "$b" ] || { echo "missing $b (run 'make all asan')" >&2; exit 1; }
done
[ -f "$SAMPLE" ] || { echo "missing $SAMPLE (run 'make gen-sample')" >&2; exit 1; }

# Unit tests: `make test` already runs them as a prerequisite, so only
# run them here when the script is invoked standalone.
if [ -z "${MAKELEVEL:-}" ]; then
    echo "== Unit tests =="
    expect_rc 0 "make unit-test" make --no-print-directory unit-test
fi

echo "== CLI error handling =="
expect_rc nonzero "no arguments"                "$BIN"
expect_rc nonzero "nonexistent input file"      "$BIN" -i "$TMP_ROOT/does_not_exist.pcap" -o "$TMP_ROOT/err1"
expect_rc nonzero "invalid --portscan-threshold" "$BIN" -i "$SAMPLE" --portscan-threshold abc -o "$TMP_ROOT/err2"
expect_rc nonzero "unknown option"              "$BIN" --bogus-flag
expect_rc 0       "--help"                      "$BIN" --help
expect_rc 0       "--version"                   "$BIN" --version

echo "== Release binary: single input =="
OUT_REL="$TMP_ROOT/release"
expect_rc 0 "pcapstat -i $SAMPLE -o <tmp>" "$BIN" -i "$SAMPLE" -o "$OUT_REL"
check_outputs "$OUT_REL" "release"

echo "== Release binary: multiple inputs =="
OUT_MULTI="$TMP_ROOT/multi"
expect_rc 0 "pcapstat -i $SAMPLE -i $SAMPLE" "$BIN" -i "$SAMPLE" -i "$SAMPLE" -o "$OUT_MULTI"
check_outputs "$OUT_MULTI" "multi"

export ASAN_OPTIONS="detect_leaks=1:abort_on_error=0:exitcode=99"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1:exitcode=98"
export LSAN_OPTIONS="suppressions=$ROOT/tests/lsan.supp"

echo "== ASan/UBSan binary: single input =="
OUT_ASAN="$TMP_ROOT/asan"
expect_rc 0 "pcapstat-asan -i $SAMPLE" "$ASAN_BIN" -i "$SAMPLE" -o "$OUT_ASAN"
check_sanitizers "$TMP_ROOT/last.log" "asan single"
check_outputs "$OUT_ASAN" "asan"

echo "== ASan/UBSan binary: multiple inputs =="
OUT_ASAN_MULTI="$TMP_ROOT/asan_multi"
expect_rc 0 "pcapstat-asan -i $SAMPLE -i $SAMPLE" "$ASAN_BIN" -i "$SAMPLE" -i "$SAMPLE" -o "$OUT_ASAN_MULTI"
check_sanitizers "$TMP_ROOT/last.log" "asan multi"
check_outputs "$OUT_ASAN_MULTI" "asan multi"

echo "== ASan/UBSan binary: error path =="
expect_rc nonzero "pcapstat-asan nonexistent input" "$ASAN_BIN" -i "$TMP_ROOT/missing.pcap" -o "$TMP_ROOT/err3"
check_sanitizers "$TMP_ROOT/last.log" "asan error path"

echo
echo "Integration tests: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
