#!/usr/bin/env bash
# pcapstat integration test suite. Run from anywhere; invoked by `make test`.
#
# Needs bin/pcapstat, bin/pcapstat-asan and bin/gen_fixture_pcaps
# (`make all asan fixtures`). Edge-case captures are generated into a
# temporary directory that is removed on exit. Every fixture is run through
# the release and the ASan/UBSan binary; the expected exit codes, summary
# lines and report contents below were checked against the intended
# behavior documented in README.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BIN="./bin/pcapstat"
ASAN_BIN="./bin/pcapstat-asan"
GEN_FIXTURES="./bin/gen_fixture_pcaps"
SAMPLE="samples/demo.pcap"
PNGS=(traffic_timeline.png protocol_ports.png packet_sizes.png tcp_flags.png)

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/pcapstat_test.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT INT TERM
FIX="$TMP_ROOT/fixtures"

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); printf '  [PASS] %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  [FAIL] %s\n' "$1"; }

# run_cmd <cmd...>: run with stdout/stderr captured in $TMP_ROOT/last.{out,err};
# sets RC.
run_cmd() {
    RC=0
    "$@" >"$TMP_ROOT/last.out" 2>"$TMP_ROOT/last.err" || RC=$?
}

dump_last() {
    sed 's/^/        out| /' "$TMP_ROOT/last.out"
    sed 's/^/        err| /' "$TMP_ROOT/last.err"
}

# expect_rc <expected: 0|1|nonzero> <description> <cmd...>
expect_rc() {
    local want="$1" desc="$2"; shift 2
    run_cmd "$@"
    if { [ "$want" = nonzero ] && [ "$RC" -ne 0 ]; } ||
       { [ "$want" != nonzero ] && [ "$RC" -eq "$want" ]; }; then
        pass "$desc (rc=$RC)"
    else
        fail "$desc (rc=$RC, expected $want)"
        dump_last
    fi
}

# expect_line <file> <exact line> <description>
expect_line() {
    if grep -Fxq -- "$2" "$1"; then
        pass "$3"
    else
        fail "$3: missing line '$2'"
        sed 's/^/        | /' "$1"
    fi
}

# expect_grep <file> <ERE> <description>
expect_grep() {
    if grep -Eq -- "$2" "$1"; then
        pass "$3"
    else
        fail "$3: no match for /$2/"
        sed 's/^/        | /' "$1"
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

# check_sanitizers <label>: the last command printed no ASan/LSan/UBSan report.
check_sanitizers() {
    if grep -qE 'ERROR: (Address|Leak)Sanitizer|runtime error:|SUMMARY: (Address|Undefined)' \
            "$TMP_ROOT/last.out" "$TMP_ROOT/last.err"; then
        fail "$1: sanitizer errors reported"
        dump_last
    else
        pass "$1: no ASan/UBSan errors"
    fi
}

# ── PDF inspection without poppler ────────────────────────────────────
# cairo writes Flate-compressed streams (recent versions also put the page
# dictionaries into compressed object streams). Each stream is inflated
# with gzip by replacing its 2-byte zlib header with a gzip header; gzip
# then complains about the missing gzip trailer, which is ignored.
pdf_inflate() {
    local pdf="$1" i s e
    local -a starts ends
    mapfile -t starts < <(LC_ALL=C grep -abx 'stream' "$pdf" | cut -d: -f1)
    mapfile -t ends   < <(LC_ALL=C grep -abx 'endstream' "$pdf" | cut -d: -f1)
    for i in "${!starts[@]}"; do
        s=$((starts[i] + 7))      # skip "stream\n"
        e=${ends[i]}              # data ends with "\n" before "endstream"
        { printf '\037\213\010\000\000\000\000\000\000\003'
          tail -c +$((s + 3)) "$pdf" | head -c $((e - s - 3)); } |
            gzip -dc 2>/dev/null || true
        echo
    done
}

# pdf_text <pdf>: the text strings shown on the pages, one per Tj/TJ
# operator. cairo's Latin font subsets encode glyphs as their ASCII codes,
# so the literal string operands are the visible text. In a TJ array small
# (kerning) adjustments join the pieces; a large gap (>= 100 units, i.e. a
# new table column) starts a new line.
pdf_text() {
    pdf_inflate "$1" | LC_ALL=C tr '\000\r\n' '   ' |
        LC_ALL=C grep -ao '\[\(([^)\\]*\(\\.[^)\\]*\)*)\|[-0-9. ]\)*\][[:space:]]*TJ\|(\([^)\\]\|\\.\)*)[[:space:]]*Tj' |
        LC_ALL=C sed -e 's/^\[//' -e 's/\][[:space:]]*TJ$//' -e 's/)[[:space:]]*Tj$/)/' \
            -e 's/\([^\\]\))[[:space:]]*-[0-9]\{3,\}[.0-9]*[[:space:]]*(/\1)\n(/g' |
        LC_ALL=C sed -e 's/\([^\\]\))[-0-9. ]*(/\1/g' \
            -e 's/^(//' -e 's/)$//' -e 's/\\\([()\\]\)/\1/g' || true
}

# check_pdf <pdf> <label> <expected pages>: the number of /Type /Page
# objects equals the page tree /Count and the expected page count, and the
# footers read "Page 1 of N" .. "Page N of N". Text checks (here and in
# expect_pdf_text) are skipped if this cairo build does not emit plain
# ASCII strings (the report title cannot be found).
PDF_TEXT_OK=1
check_pdf() {
    local pdf="$1" label="$2" want="$3" objs text n_obj count footers expect i
    objs="$({ LC_ALL=C tr -c '[:print:]\n' '.' <"$pdf"; pdf_inflate "$pdf" |
              LC_ALL=C tr -c '[:print:]\n' '.'; } | grep -o '/Type */Pages\?\|/Count [0-9]*' || true)"
    n_obj=$(printf '%s\n' "$objs" | grep -c 'Page$' || true)
    count=$(printf '%s\n' "$objs" | grep '/Count' | head -n1 | cut -d' ' -f2)
    if [ "$n_obj" -eq "$want" ] && [ "${count:-}" = "$want" ]; then
        pass "$label: PDF has $want pages"
    else
        fail "$label: PDF has $n_obj /Page objects, /Count ${count:-?}, expected $want"
    fi

    text="$(pdf_text "$pdf")"
    printf '%s\n' "$text" >"$TMP_ROOT/last.pdftext"
    if ! grep -Fxq 'pcapstat - Network Traffic Analysis Report' "$TMP_ROOT/last.pdftext"; then
        PDF_TEXT_OK=0
        echo "  [SKIP] $label: cannot extract PDF text with this cairo build"
        return
    fi
    footers=$(printf '%s\n' "$text" | grep -E '^Page [0-9]+ of [0-9]+$' | tr '\n' ',' || true)
    expect=""
    for ((i = 1; i <= want; i++)); do expect+="Page $i of $want,"; done
    if [ "$footers" = "$expect" ]; then
        pass "$label: footers 'Page X of $want' match the page count"
    else
        fail "$label: footers [$footers], expected [$expect]"
    fi
}

# expect_pdf_text <exact string> <label>: string shown in the last checked PDF.
expect_pdf_text() {
    if [ "$PDF_TEXT_OK" -eq 0 ]; then
        return
    elif grep -Fxq -- "$1" "$TMP_ROOT/last.pdftext"; then
        pass "$2: report shows '$1'"
    else
        fail "$2: report does not show '$1'"
    fi
}

for b in "$BIN" "$ASAN_BIN" "$GEN_FIXTURES"; do
    [ -x "$b" ] || { echo "missing $b (run 'make all asan fixtures')" >&2; exit 1; }
done
[ -f "$SAMPLE" ] || { echo "missing $SAMPLE (run 'make gen-sample')" >&2; exit 1; }

# Unit tests: `make test` already runs them as a prerequisite, so only
# run them here when the script is invoked standalone.
if [ -z "${MAKELEVEL:-}" ]; then
    echo "== Unit tests =="
    expect_rc 0 "make unit-test" make --no-print-directory unit-test
fi

export ASAN_OPTIONS="detect_leaks=1:abort_on_error=0:exitcode=99"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1:exitcode=98"
export LSAN_OPTIONS="suppressions=$ROOT/tests/lsan.supp:print_suppressions=0"

echo "== Fixture generation =="
mkdir -p "$FIX"
expect_rc 0 "gen_fixture_pcaps <tmp>" "$GEN_FIXTURES" "$FIX"

echo "== CLI error handling =="
expect_rc 1 "no arguments"                 "$BIN"
expect_line "$TMP_ROOT/last.err" "pcapstat: no input files specified" "no arguments: message"
expect_rc 1 "nonexistent input file"       "$BIN" -i "$TMP_ROOT/does_not_exist.pcap" -o "$TMP_ROOT/err1"
expect_rc 1 "invalid --portscan-threshold" "$BIN" -i "$SAMPLE" --portscan-threshold abc -o "$TMP_ROOT/err2"
expect_rc 1 "unknown option"               "$BIN" --bogus-flag
expect_rc 0 "--help"                       "$BIN" --help
expect_grep "$TMP_ROOT/last.out" '^Usage: ' "--help: usage text"
expect_rc 0 "--version"                    "$BIN" --version
expect_grep "$TMP_ROOT/last.out" '^pcapstat [0-9]+\.[0-9]+\.[0-9]+$' "--version: version string"

echo "== Output directory handling =="
: >"$TMP_ROOT/regular_file"
expect_rc 1 "-o pointing at a regular file" "$BIN" -i "$SAMPLE" -o "$TMP_ROOT/regular_file"
expect_line "$TMP_ROOT/last.err" \
    "pcapstat: output path '$TMP_ROOT/regular_file' exists and is not a directory" \
    "-o regular file: clear error message"
expect_rc 0 "-o with missing parent directories" "$BIN" -i "$SAMPLE" -o "$TMP_ROOT/a/b/c/"
check_outputs "$TMP_ROOT/a/b/c" "mkdir -p"

# ── Golden numbers for samples/demo.pcap ──────────────────────────────
# 183 frames from tests/gen_demo_pcap.c: 55 TCP (52 IPv4 + 3 IPv6),
# 126 UDP, 2 malformed; 3 retransmissions; 6 findings.
DEMO_PACKETS="  Packets         : 183 (18075 bytes)"
DEMO_ANOMALIES="  Anomalies       : 6 (critical 3, warning 3, info 0)"

for variant in release asan; do
    if [ "$variant" = release ]; then b="$BIN"; else b="$ASAN_BIN"; fi

    echo "== Demo capture ($variant) =="
    out="$TMP_ROOT/demo_$variant"
    expect_rc 0 "$variant: pcapstat -i $SAMPLE" "$b" -i "$SAMPLE" -o "$out"
    if [ "$variant" = asan ]; then check_sanitizers "$variant demo"; fi
    expect_line "$TMP_ROOT/last.out" "  Files processed : 1" "$variant demo: files processed"
    expect_line "$TMP_ROOT/last.out" "$DEMO_PACKETS" "$variant demo: packet/byte totals"
    expect_line "$TMP_ROOT/last.out" "$DEMO_ANOMALIES" "$variant demo: anomaly counts"
    expect_line "$TMP_ROOT/last.out" "    $out/report.pdf" "$variant demo: report path listed"
    check_outputs "$out" "$variant demo"
    check_pdf "$out/report.pdf" "$variant demo" 4
    if [ "$variant" = release ]; then
        for s in "Files Processed: 1  |  Packets: 183  |  Duration: 3.07 s  |  Active Flows: 43  |  Unique Hosts: 5" \
                 "59.6 pps | 47.1 kbps" "3 Retrans" "Out-of-order: 0 | SYN: 30 | RST: 0" \
                 "Other 0 | Non-IP 0 | Malformed 2" "TCP 30.1% | UDP 68.9%" \
                 "Non-IP frames (ARP/LLDP/...)" "Other IP" "9999/udp (Unknown)" "53/udp (DNS)" \
                 "Suspicious" "10.0.0.100" "Null Scan" "Xmas Scan" "Malformed Packets" \
                 "TCP Retransmissions" "UDP Burst" "2024-01-01 00:00:02 UTC" \
                 "Host scanned 25 unique destination ports (threshold: 20)"; do
            expect_pdf_text "$s" "demo"
        done
        if grep -Fxq "SYN Flood" "$TMP_ROOT/last.pdftext"; then
            fail "demo: port scanner must not also be reported as SYN Flood"
        else
            pass "demo: no SYN Flood finding for the port scanner"
        fi
    fi
done

echo "== Multiple inputs =="
for variant in release asan; do
    if [ "$variant" = release ]; then b="$BIN"; else b="$ASAN_BIN"; fi
    out="$TMP_ROOT/multi_$variant"
    expect_rc 0 "$variant: demo + udp_only (-i and positional)" \
        "$b" -i "$SAMPLE" -o "$out" "$FIX/udp_only.pcap"
    if [ "$variant" = asan ]; then check_sanitizers "$variant multi"; fi
    expect_line "$TMP_ROOT/last.out" "  Files processed : 2" "$variant multi: files processed"
    expect_line "$TMP_ROOT/last.out" "  Packets         : 203 (20215 bytes)" "$variant multi: totals add up"
    expect_line "$TMP_ROOT/last.out" "$DEMO_ANOMALIES" "$variant multi: anomaly counts"
    check_outputs "$out" "$variant multi"
done

echo "== Duplicate inputs =="
ln -s "$ROOT/$SAMPLE" "$TMP_ROOT/demo_link.pcap"
expect_rc 0 "same file via path, ../ path and symlink" \
    "$BIN" -i "$SAMPLE" -i "./samples/../$SAMPLE" -i "$TMP_ROOT/demo_link.pcap" -o "$TMP_ROOT/dup"
expect_line "$TMP_ROOT/last.err" \
    "pcapstat: warning: skipping duplicate input './samples/../$SAMPLE' (same file as '$SAMPLE')" \
    "duplicate: ../ path skipped with warning"
expect_line "$TMP_ROOT/last.err" \
    "pcapstat: warning: skipping duplicate input '$TMP_ROOT/demo_link.pcap' (same file as '$SAMPLE')" \
    "duplicate: symlink skipped with warning"
expect_line "$TMP_ROOT/last.out" "  Files processed : 1" "duplicate: counted once"
expect_line "$TMP_ROOT/last.out" "$DEMO_PACKETS" "duplicate: totals not doubled"

# ── Edge-case fixtures ────────────────────────────────────────────────
# name | exit code | "Packets" value | "Anomalies" value | stderr ERE ("" = empty)
FIXTURE_CASES=(
    "empty.pcap|0|0 (0 bytes)|0 (critical 0, warning 0, info 0)|"
    "one_packet.pcap|0|1 (54 bytes)|0 (critical 0, warning 0, info 0)|"
    "tcp_only.pcap|0|16 (4464 bytes)|0 (critical 0, warning 0, info 0)|"
    "udp_only.pcap|0|20 (2140 bytes)|0 (critical 0, warning 0, info 0)|"
    "arp_tcp.pcap|0|20 (4632 bytes)|0 (critical 0, warning 0, info 0)|"
    "truncated_tail.pcap|0|15 (4410 bytes)|1 (critical 0, warning 1, info 0)|^pcapstat: warning: '.*truncated_tail\.pcap': .* \(stopped after 15 packets\)$"
    "corrupt_first.pcap|1|||^pcapstat: cannot read '.*corrupt_first\.pcap': "
    "dlt_null.pcap|1|||^pcapstat: unsupported link type 0 in "
    "extreme_ts.pcap|0|4 (328 bytes)|0 (critical 0, warning 0, info 0)|"
    "unsorted_days.pcap|0|15 (2928 bytes)|0 (critical 0, warning 0, info 0)|"
    "ipv4_fragments.pcap|0|34 (4292 bytes)|0 (critical 0, warning 0, info 0)|"
    "tso_totlen0.pcap|0|13 (18118 bytes)|0 (critical 0, warning 0, info 0)|"
    "udp_burst.pcap|0|154 (21728 bytes)|1 (critical 0, warning 1, info 0)|"
    "reorder_subms.pcap|0|33 (4782 bytes)|0 (critical 0, warning 0, info 0)|"
    "sll.pcap|0|18 (4714 bytes)|0 (critical 0, warning 0, info 0)|"
    "sll2.pcap|0|18 (4786 bytes)|0 (critical 0, warning 0, info 0)|"
    "raw.pcap|0|18 (4466 bytes)|0 (critical 0, warning 0, info 0)|"
    "qinq.pcap|0|18 (4822 bytes)|0 (critical 0, warning 0, info 0)|"
    "ipv6.pcap|0|18 (5038 bytes)|0 (critical 0, warning 0, info 0)|"
)

# Report contents that pin the fixed behaviors (release run only).
# name | exact string shown in the PDF
FIXTURE_PDF_TEXT=(
    "empty.pcap|Files Processed: 1  |  Packets: 0  |  Duration: 0.00 s  |  Active Flows: 0  |  Unique Hosts: 0"
    "arp_tcp.pcap|Other 0 | Non-IP 4 | Malformed 0"
    "arp_tcp.pcap|Files Processed: 1  |  Packets: 20  |  Duration: 2.00 s  |  Active Flows: 2  |  Unique Hosts: 2"
    "truncated_tail.pcap|Capture Integrity"
    "truncated_tail.pcap|1 of 1 file(s)"
    "extreme_ts.pcap|Files Processed: 1  |  Packets: 4  |  Duration: 49710d 06:28:15  |  Active Flows: 4  |  Unique Hosts: 2"
    "unsorted_days.pcap|Files Processed: 1  |  Packets: 15  |  Duration: 2d 00:00:00  |  Active Flows: 7  |  Unique Hosts: 3"
    "unsorted_days.pcap|0 Retrans"
    "ipv4_fragments.pcap|Files Processed: 1  |  Packets: 34  |  Duration: 1.03 s  |  Active Flows: 1  |  Unique Hosts: 3"
    "ipv4_fragments.pcap|Out-of-order: 0 | SYN: 0 | RST: 0"
    "tso_totlen0.pcap|Other 0 | Non-IP 0 | Malformed 0"
    "tso_totlen0.pcap|213.1 pps | 2.38 Mbps"
    "udp_burst.pcap|UDP Burst"
    "udp_burst.pcap|2024-01-01 00:00:01 UTC"
    "reorder_subms.pcap|0 Retrans"
    "reorder_subms.pcap|Out-of-order: 10 | SYN: 1 | RST: 0"
    "sll2.pcap|Other 0 | Non-IP 0 | Malformed 0"
    "raw.pcap|Files Processed: 1  |  Packets: 18  |  Duration: 2.10 s  |  Active Flows: 4  |  Unique Hosts: 4"
    "qinq.pcap|Other 0 | Non-IP 0 | Malformed 0"
    "ipv6.pcap|Other 0 | Non-IP 0 | Malformed 0"
)

for variant in release asan; do
    if [ "$variant" = release ]; then b="$BIN"; else b="$ASAN_BIN"; fi
    echo "== Edge-case fixtures ($variant) =="
    for entry in "${FIXTURE_CASES[@]}"; do
        IFS='|' read -r name want_rc want_pkts want_anom want_err <<<"$entry"
        if [ ! -f "$FIX/$name" ]; then
            # sll2.pcap is skipped by the generator if libpcap lacks SLL2.
            echo "  [SKIP] $name not generated"
            continue
        fi
        label="$variant $name"
        out="$TMP_ROOT/fx_${variant}_${name%.pcap}"
        expect_rc "$want_rc" "$label: exit code" "$b" -i "$FIX/$name" -o "$out"
        if [ "$variant" = asan ]; then check_sanitizers "$label"; fi
        if [ -n "$want_err" ]; then
            expect_grep "$TMP_ROOT/last.err" "$want_err" "$label: stderr message"
        elif [ -s "$TMP_ROOT/last.err" ]; then
            fail "$label: unexpected stderr output"
            dump_last
        else
            pass "$label: stderr empty"
        fi
        if [ "$want_rc" = 0 ]; then
            expect_line "$TMP_ROOT/last.out" "  Packets         : $want_pkts" "$label: packet/byte totals"
            expect_line "$TMP_ROOT/last.out" "  Anomalies       : $want_anom" "$label: anomaly counts"
            if [ "$variant" = release ]; then
                check_outputs "$out" "$label"
                check_pdf "$out/report.pdf" "$label" 4
                for pentry in "${FIXTURE_PDF_TEXT[@]}"; do
                    if [ "${pentry%%|*}" = "$name" ]; then
                        expect_pdf_text "${pentry#*|}" "$label"
                    fi
                done
            fi
        elif [ -s "$TMP_ROOT/last.out" ]; then
            fail "$label: failed run printed a summary"
        fi
    done
done

echo "== ASan/UBSan binary: error path =="
expect_rc 1 "pcapstat-asan nonexistent input" "$ASAN_BIN" -i "$TMP_ROOT/missing.pcap" -o "$TMP_ROOT/err3"
check_sanitizers "asan error path"

echo
echo "Integration tests: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
