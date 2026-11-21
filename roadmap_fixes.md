# `pcapstat` Fix Roadmap (post-audit, v1)

Source: pre-submission audit of 2026-11-20 against commit `0f96ed7`. Every task lists the audit IDs it closes (`C*` critical, `H*` high, `M*` medium, `L*` low); each requirement below is self-contained, so an agent does not need the audit text.

Usage mirrors `roadmap.md`: give one agent **Global Context & Rules**, **Shared Contracts**, **File Ownership**, and exactly **one** task. Ready-to-paste prompts are in the last section.

## Execution Plan

```
Wave 1 (parallel, disjoint files)    FIX-01   FIX-02   FIX-03   FIX-04   FIX-05
                                       build    parser   stats    anomaly  charts
                                          \        \       |        /       /
Merge into main in order FIX-01 → FIX-05; run `make clean && make test` after each merge
                                                      |
Wave 2                                              FIX-06   integration: stats classification,
                                                      |      truncation plumbing, report, main, CLI
Wave 3                                              FIX-07   fixtures, end-to-end tests, docs, screenshots
```

Known, intended intermediate state between Wave 1 and Wave 2: the parser already flags non-IP frames and IPv4 fragments (FIX-02), but the stats engine only learns to classify them in FIX-06. Until then non-IP frames land in `other_packets` and fragments are counted as TCP/UDP with zero flags. Do not release between the waves.

## Global Context & Rules (give to every agent)

* **Project:** Linux C11 CLI (`-std=c11 -D_DEFAULT_SOURCE`) analyzing TCP/UDP traffic from one or more `.pcap` files; outputs 4 PNG charts and a multi-page A4 PDF report (libcairo). Dependencies: libpcap, libcairo, libm only. No `system()`, no Python in production code.
* **Code quality (unchanged from `roadmap.md`):** zero warnings under `-Wall -Wextra -Wpedantic -Wshadow`; ASan/UBSan/Valgrind clean; packet headers read only via `memcpy()` into locals after an `offset + needed <= caplen` check; functions return `0` or a negative `enum pcapstat_err`; resources released via `goto cleanup`; every public function/struct in `include/*.h` has Doxygen with `@return` and memory ownership.
* **Fix-phase rules:**
  1. **Scope:** fix only the defects listed in your task. No drive-by refactors, renames or reformatting.
  2. **Ownership:** edit only files your task owns (table below). If another file must change, do not touch it; list it under *Follow-ups* in your final report.
  3. **Regression tests:** every fixed defect gets a test that fails on the old code and passes on the new code (where testable). Prefer synthetic inputs built inside the test (temp files via `mkstemp`/`mkdtemp`; pcaps via `pcap_open_dead()` + `pcap_dump_open()` or raw `fwrite`).
  4. **Do not modify** `samples/demo.pcap`, `tests/gen_demo_pcap.c`, `roadmap.md`, `roadmap_fixes.md`. Demo-based assertions must keep passing unless your task deliberately changes that behavior; then update the assertion and explain why in a comment.
  5. **Docs:** update Doxygen in headers you own. `README.md` and `ARCHITECTURE.md` belong to FIX-07; list needed doc changes in your final report instead.
  6. **Verification:** `make && make debug && make asan && make unit-test` (zero warnings), then `bash tests/run_tests.sh`. Report exact pass/fail counts. Never claim a check you did not run.
  7. **Environment:** repo lives on NTFS under WSL with `core.fileMode=false` (use `git update-index --chmod=+x` for exec bits). GCC 13.3, libpcap 1.10.4, cairo 1.18, valgrind 3.22; no clang, no `pdftotext`. PNGs can be inspected visually by reading the image file.
  8. **Git:** work and commit only on your own worktree branch. Never commit to `main`, never push, never rebase/merge other branches. Commit subject `FIX-0X: <summary>`, body lists audit IDs, last line `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
  9. **Manual-check fixtures** (crafted during the audit, read-only, may be deleted at any time; never reference them from committed tests):
     `/tmp/claude-1000/-mnt-c-Users-Juliusz-Desktop-studia-hackaton-pcapstat/bbd3ec61-0124-48c6-bfea-bbb114e64fe6/scratchpad/pcaps/`
     (`empty`, `one`, `udp_only`, `tcp_only`, `arp_only`, `clean_with_arp`, `truncated`, `corrupt_caplen`, `extreme_ts2`, `unsorted_days`, `udp_fragments`, `tcp_fragments`, `tso`, `dns_tcp_udp`, `reorder`, `udp_flood_3s`, `spoofed_synflood_100k`, `sweep_16`, `dlt_null` — all `.pcap`).

## Shared Contracts (fixed up front so parallel tasks agree)

**Parser (`include/parser.h`, implemented by FIX-02, consumed by FIX-06):**

```c
/* New fields in parsed_packet_t (all zero/false by default): */
bool is_non_ip;    /* L2 decoded fine, but EtherType/SLL protocol is not IPv4/IPv6
                      (ARP, LLDP, STP, ...). is_malformed == false, ip_version == 0. */
bool is_fragment;  /* IPv4 non-first fragment (frag offset != 0). L3 fields valid,
                      proto set; ports, TCP fields and payload_len are 0. */

typedef struct {
    uint64_t packets;     /* frames delivered to the callback */
    bool     truncated;   /* read stopped on PCAP_ERROR after >= 1 packet */
    char     error[256];  /* pcap_geterr() text if truncated/failed, else "" */
} parser_file_info_t;

/* info may be NULL. parser_process_file(f, cb, ud) == parser_process_file_ex(f, cb, ud, NULL). */
int parser_process_file_ex(const char *filepath, packet_handler_fn cb,
                           void *user_data, parser_file_info_t *info);
```

Return policy: `PCAP_ERROR` before any packet → print error, return `PCAPSTAT_ERR_PCAP`. `PCAP_ERROR` after ≥ 1 packet (truncated/corrupt tail, e.g. capture killed with Ctrl-C) → print `pcapstat: warning: '<file>': <pcap error> (stopped after N packets)` to stderr, set `info->truncated`, return `PCAPSTAT_OK`. A non-zero callback return still stops parsing and is returned unchanged (any sign).

**Stats (`include/stats.h`):**

* FIX-03 adds to `stats_ctx_t`: `uint64_t tcp_retransmissions;` and `uint64_t tcp_out_of_order;` (global sums of the per-flow counters); adds `uint64_t out_of_order;` to `flow_stats_t`.
* FIX-03: `avg_bps` becomes **bits per second** (`8 * total_bytes / duration_sec`). Document the unit.
* FIX-03: packet-size histogram bins become `[0,64) [64,128) [128,256) [256,512) [512,1024) [1024,1514) [1514,∞)`, matching the existing chart labels `<64 … 1024-1513, >=1514`.
* FIX-03: `host_stats_t` keeps `unique_dst_ports` with identical semantics; the 8 KB inline bitmap is replaced by a compact representation (layout is FIX-03's choice). Host objects are freed only via the stats module.
* FIX-06 adds: `uint64_t non_ip_packets;`, `uint64_t ip_fragments;` (informational, also counted in tcp/udp/other by `proto`), `uint64_t truncated_files;` (caller-maintained, like `files_processed`). New category invariant: `tcp + udp + other + non_ip + malformed == total_packets`.

## File Ownership

| Task | Wave | May edit |
| :--- | :--- | :--- |
| FIX-01 | 1 | `makefile` (optionally renamed to `Makefile`), `tests/run_tests.sh` (exec bit + invocation only), `tests/lsan.supp`, `tests/valgrind.supp` |
| FIX-02 | 1 | `src/parser.c`, `include/parser.h`, `tests/test_parser.c` |
| FIX-03 | 1 | `src/stats.c`, `include/stats.h`, `src/hashtable.c`, `include/hashtable.h`, `tests/test_stats.c`, `tests/test_hashtable.c` |
| FIX-04 | 1 | `src/anomaly.c`, `include/anomaly.h`, `tests/test_anomaly.c` |
| FIX-05 | 1 | `src/charts.c`, `include/charts.h`, `tests/test_charts.c` |
| FIX-06 | 2 | `src/stats.c`, `include/stats.h` (classification only), `src/report.c`, `include/report.h`, `src/main.c`, `src/cli.c`, `include/cli.h`, `include/common.h`, `src/anomaly.c` (one new rule), tests `test_stats.c`, `test_report.c`, `test_cli.c`, `test_anomaly.c` |
| FIX-07 | 3 | `tests/gen_fixture_pcaps.c` (new), `tests/run_tests.sh`, `makefile`, `README.md`, `ARCHITECTURE.md`, `docs/*.png` |

## Audit → Task Map

| Audit | Task | Audit | Task | Audit | Task |
| :--- | :--- | :--- | :--- | :--- | :--- |
| C1 | 01 | H5 | 03 → 06 | M6 | every task + 07 |
| C2 | 05 | H6 | 03 | M7 | 01 |
| C3 | 03 | H7 | 04 | M8 | 02 |
| H1 | 02 → 06 | M1 | 03 | M9 | 05 → 07 |
| H2 | 02 → 06 | M2, M3 | 05 | M10 | owner decision (see end) |
| H3 | 02 → 06 | M4, M5 | 04 | L* | spread, see tasks |
| H4 | 03 → 06 | | | | |

---

## Wave 1

### FIX-01: Build & Test Infrastructure

* **Audit:** C1, M7, build-polish lows.
* **Dependencies:** none.
* **Goal:** `make test` on a fresh clone really runs every suite, and sanitizer findings fail the build instead of scrolling past.
* **Requirements:**
  1. **C1:** `tests/run_tests.sh` is committed as `100644` and `makefile:89-94` silently prints `(no integration test script yet)` when it is not executable. Set the bit in the index (`git update-index --chmod=+x tests/run_tests.sh`) **and** make the `test` target run `bash $(TESTDIR)/run_tests.sh` unconditionally (a missing script must fail).
  2. **M7:** GCC's `-fsanitize=undefined` excludes `float-cast-overflow`, and UBSan recovers by default, so UB in unit tests prints a message but the test still passes (`makefile:53-54`, `makefile:83` only sets `LSAN_OPTIONS`). For the `asan`, test and generator builds use `-fsanitize=address,undefined,float-cast-overflow -fno-sanitize-recover=all` (compile and link). In `unit-test`, export `UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1` and add `print_suppressions=0` to `LSAN_OPTIONS` (removes the noisy "Suppressions used" blocks).
  3. **Portability:** introduce `WERROR ?= -Werror` and use it in the debug/asan flags so a recruiter on a newer compiler can run `make test WERROR=`. Make `CC` overridable: `ifeq ($(origin CC),default)` → `CC := gcc` (note: `CC ?= gcc` does not work because make predefines `CC`).
  4. **Release hardening** (README claims a "hardened build"): add `-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-strong` to the release flags only (fortify needs optimization; do not add it to `-O0` debug). Must stay warning-free.
  5. **Noise:** add `.SECONDARY:` (or equivalent) so `make test` no longer ends with `rm build/test/*.o`; build `bin/gen_demo_pcap` without `-MMD` so no stray `bin/gen_demo_pcap.d` appears.
  6. *(Optional)* rename `makefile` → `Makefile` (all docs say `Makefile`). Only if `git mv -f makefile Makefile` works cleanly on this filesystem and `git ls-files` then shows exactly `Makefile`; otherwise skip and say so.
* **Acceptance Criteria:**
  * After committing, `git clone <your worktree> <tmpdir> && cd <tmpdir> && make test` prints `Integration tests: N passed, 0 failed` and exits `0`; `git ls-files -s tests/run_tests.sh` shows `100755`.
  * A temporary, uncommitted UB injection (e.g. a signed overflow inside one unit test) makes `make unit-test` exit non-zero; revert it afterwards.
  * `make test WERROR=` and `make CC=gcc test` work; second `make unit-test` prints no `rm` lines; no LSan suppression tables in output.
  * If the stricter sanitizers expose a defect in a file you do not own (e.g. `src/charts.c`), do not fix it: report it under Follow-ups.

### FIX-02: Parser Correctness & Input Integrity

* **Audit:** H1, H2, H3 (parser side), M8, parser doc lows.
* **Dependencies:** none.
* **Goal:** the parser reports damaged files, and stops mislabeling non-IP frames and IPv4 fragments.
* **Requirements:**
  1. **H1:** `src/parser.c:87` loops while `pcap_next_ex() == 1` and ignores `PCAP_ERROR` afterwards (`:168-169`): truncated or corrupt files currently exit 0 with no message. Implement `parser_process_file_ex()` + `parser_file_info_t` exactly per Shared Contracts (call `pcap_geterr()` before `pcap_close()`); keep `parser_process_file()` as a thin wrapper.
  2. **H2:** `decode_ip()` (`src/parser.c:198-202`) marks every non-IPv4/IPv6 EtherType as malformed (and its comment says the opposite). Set `is_non_ip = true`, leave `is_malformed = false`, `ip_version = 0`. VLAN tags that run past `caplen` remain malformed.
  3. **H3:** IPv4 non-first fragments are decoded as TCP/UDP, so random payload bytes become ports/flags (one fragmented datagram produced a CRITICAL "Port Scan"; TCP fragments produced fake Xmas/SYN+FIN/SYN+RST). If `ntohs(frag_off) & 0x1FFF` is non-zero: fill L3 fields, set `is_fragment = true`, skip L4 decoding. First fragments (offset 0, MF set) are still decoded.
  4. **M8:** IPv4 `tot_len == 0` (TCP segmentation offload / BIG TCP captures on the sending host) is currently malformed (`src/parser.c:226`). Treat it as "length taken from the frame": effective `tot_len = wire_len - offset`, still malformed if that is smaller than the IP header. Same idea for IPv6 `ip6_plen == 0` when computing L4 payload length.
  5. **Docs (`include/parser.h`):** document the new fields, `_ex`, the return policy, and fix the callback `@return` text (non-zero of any sign stops parsing; currently says "positive" and "all packets processed").
* **Tests (`tests/test_parser.c`), each with a synthetic pcap:** ARP frame → `is_non_ip`, not malformed; IPv4 TCP fragment with offset > 0 → `is_fragment`, ports/flags 0; first fragment still decoded; `tot_len == 0` → not malformed, sane `payload_len`; empty pcap → OK, 0 packets; file cut mid-record → OK, `info.truncated`, correct packet count, warning on stderr; corrupt first record → `PCAPSTAT_ERR_PCAP`; plus coverage that is missing today: `DLT_LINUX_SLL`, `DLT_LINUX_SLL2` (guard with `#ifdef`), `DLT_RAW` v4 and v6, QinQ double tag, IPv4 options (`ihl = 6`), `doff < 5`, `udp_len < 8`, `tot_len < ihl*4`. Fix the false file-header claim at `tests/test_parser.c:5-6` by making it true.
* **Acceptance Criteria:**
  * Existing demo counts unchanged (183 total, 52 TCPv4, 126 UDPv4, 3 TCPv6, 2 malformed); all parser tests pass under ASan/UBSan.
  * Manual check with the audit fixtures: `truncated.pcap` and `corrupt_caplen.pcap` now print a warning; `clean_with_arp.pcap` yields 4 `is_non_ip` frames.
  * Do not touch `src/stats.c` (classification is FIX-06).

### FIX-03: Stats Engine Correctness & Memory

* **Audit:** C3, H4, H5 (counter), H6, M1, hash-mixer low, demo-tailored service name.
* **Dependencies:** none.
* **Goal:** bounded per-host memory, correct units, and retransmission counts that do not include reordering.
* **Requirements:**
  1. **C3:** every host embeds `uint8_t dst_ports_bitmap[8192]` (`include/stats.h:100`), and a host is created for every source *and* destination (`src/stats.c:419,435`). Measured: 100k spoofed-source SYNs (6.7 MB pcap) → 856 MB RSS; a /16 SYN sweep (4.4 MB) → 564 MB. Replace it with a compact set: a small inline array (e.g. 16 ports) promoted to a lazily `malloc`ed 8 KB bitmap only when exceeded. Receive-only hosts must not allocate any port storage. Use a dedicated host destructor in `ht_destroy()` and on all error paths. `unique_dst_ports` semantics stay identical (port 0 ignored, TCP and UDP share one set).
  2. **H4:** `avg_bps` (`src/stats.c:777-778`) is bytes/s, yet the report prints it as Kbps/Mbps (8× too low). Make it bits/s and document the unit in `stats.h`.
  3. **H5 (data side):** add global `tcp_retransmissions` and `tcp_out_of_order` counters to `stats_ctx_t` (Shared Contracts), maintained in `update_flow()`. The report currently sums only the top-128 flows; FIX-06 switches it to this counter.
  4. **H6:** the retransmission rule (`src/stats.c:552-563`) stores only the last new `seq`, so any reordered segment counts as a retransmission (30 segments with 10 adjacent swaps → "33% retransmissions"). Implement a Wireshark-style classification per directional flow, wrap-safe (`(int32_t)` differences), for payload-bearing segments:
     * track `next_seq` = highest `seq + payload_len` seen;
     * `seq` at or beyond `next_seq` → new data; if `seq` is beyond `next_seq`, record the hole `[next_seq, seq)` (a single hole interval is enough);
     * a segment inside the recorded hole arriving less than `STATS_OOO_WINDOW_SEC` (0.003 s) after the segment that opened it → `out_of_order` (shrink/clear the hole);
     * anything else entirely below `next_seq` → `retransmissions`.
     Keep the existing rule that a packet with a timestamp earlier than the flow baseline rebases instead of counting (multi-file merges; pinned by `test_unsorted_48h_and_retransmission`).
  5. **M1:** `histogram_bin()` (`src/stats.c:23-38`) uses `<=64 … <=1500`, but the chart labels say `<64, 64-127, …, 1024-1513, >=1514`, so a 64-byte frame shows as "<64". Switch to the bins in Shared Contracts and update `test_histogram_boundaries` (`tests/test_stats.c:193`).
  6. **Hash quality:** `ht_bucket_index()` (`src/hashtable.c:31-34`) masks the low bits of unseeded FNV-1a directly; those bits mix poorly and keys come from untrusted pcaps. Add a 64-bit finalizer (e.g. murmur3 `fmix64`) before masking; update `test_fnv1a_bucket_placement` accordingly.
  7. **Demo tailoring:** `stats_port_service_name()` maps port 9999 to a made-up "UDP-Data" service "for demo traffic only" (`src/stats.c:72-74`). Remove it (returns "Unknown") and update tests.
* **Acceptance Criteria:**
  * New tests: receive-only host allocates no port storage; promotion past the inline capacity keeps exact `unique_dst_ports`; sub-millisecond adjacent swaps → 0 retransmissions, N out-of-order; exact duplicate segment → retransmission; wrap-around cases still pass; `avg_bps == 8 * bytes / duration`; global counters equal the per-flow sums.
  * Demo still yields exactly 3 retransmissions (the same segment repeated 10 ms apart) and 25 scanner ports.
  * Manual memory check with the release binary: `/usr/bin/time -v ./bin/pcapstat -i <fixtures>/spoofed_synflood_100k.pcap -o <tmp>` peak RSS ≤ 150 MB (was 856 MB); `sweep_16.pcap` ≤ 100 MB (was 564 MB). Report the numbers.
  * Do not edit `tests/test_anomaly.c`; if it breaks because of the new semantics, explain in Follow-ups.

### FIX-04: Anomaly Heuristics

* **Audit:** H7, M4, M5, `anomaly.h` doc lows.
* **Dependencies:** none (uses only existing `stats_ctx_t` fields).
* **Goal:** short UDP bursts are detected, port scanners are not double-reported, and burst findings are readable.
* **Requirements:**
  1. **H7:** `mean_udp = udp_packets / num_buckets` (`src/anomaly.c:348`) includes the burst itself; with ≤ 3 active seconds `b > 3·mean` is mathematically impossible, so short bursts are never flagged. Use a leave-one-out baseline per bucket: `(udp_total - b) / (n - 1)` for `n ≥ 2`, `0` for `n == 1`. Keep the absolute `udp_burst_min` gate. A capture that is *entirely* a constant flood has no baseline and stays undetected — document that limitation in `anomaly.h`.
  2. **M4:** the per-host SYN-flood rule (`src/anomaly.c:146-176`) is sender-centric, so a port scanner that sends ≥ 50 SYNs to closed ports also gets a CRITICAL "SYN Flood" (seen when the demo is loaded twice). Skip the host-level SYN-flood finding for hosts that already meet the port-scan threshold. Leave the global rule unchanged.
  3. **M5:** one "UDP Burst" finding per second (`src/anomaly.c:356-375`) means a 10-minute flood fills about 30 PDF pages, each titled with a raw epoch (`Second 1704067202`). Merge consecutive flagged seconds into one finding: subject = start time as UTC `YYYY-MM-DD HH:MM:SS` (`gmtime_r`), description = duration, peak pkt/s, baseline, thresholds. Must fit the existing 128/256-byte fields.
  4. **Docs (`include/anomaly.h`):** the `ANOMALY_INFO` example says "malformed frame" but malformed packets are `WARNING` and no rule emits `INFO` — fix the text; the tie-break text should also mention description; document the new burst baseline and SYN-flood dedup.
  5. The `else if (stats->timeline != NULL)` fallback branch is unreachable after `stats_init()`; remove it only if no test depends on it, otherwise leave it and note it.
* **Acceptance Criteria:**
  * New tests: 1 s × 1000 UDP + 2 s × 5 UDP → one burst finding (failed before); 5 consecutive burst seconds → exactly one finding with "5 s"; scanner host (≥ 20 ports, ≥ 50 SYNs, 0 SYN-ACK) → Port Scan only; a host flooding one port with ≥ 50 SYNs → SYN Flood.
  * Demo still yields the same 6 findings (update only the expected burst subject text).
  * Do not modify `stats.h`/`stats.c`.

### FIX-05: Charts Correctness

* **Audit:** C2, M2, M3, M9 (chart side), `charts.h` doc lows, charts path join.
* **Dependencies:** none.
* **Goal:** no undefined behavior, and charts that do not mislead on sparse, long, low-rate or mixed-protocol captures.
* **Requirements:**
  1. **C2:** `int sec_int = (int)offset_sec;` (`src/charts.c:335`) is UB when the capture span exceeds `INT_MAX` seconds (timestamps `INT32_MIN` and `INT32_MAX` → `runtime error: 2.14748e+09 is outside the range of representable values of type 'int'`; release build renders `+-2147483648s`). Replace with a span-aware formatter on `int64_t`/`double` with clamping: `+12s`, `+05:30`, `+3h05m`, `+2d04h`.
  2. **M2:** the timeline polyline connects sparse buckets across gaps, so 4 packets spread over 3 days render as a flat 1 pkt/s line for 72 h. When bucket `i` does not start where bucket `i-1` ends (`sec > prev.sec + prev.span_sec`), drop the line to 0 at the end of the previous bucket and rise from 0 at the start of the next one (no traffic during gaps is the truth).
  3. **M3:** `format_metric()` uses `%.0f` below 1000 (`src/charts.c:103`), so ticks 0.25/0.5/0.75 render as `0 0 0 1 1`. Use one decimal (or `%g`) when the axis maximum is < 10, and keep integers otherwise.
  4. **M9 (chart side):** port bars are labelled `"%u (%s)"` (`src/charts.c:524`), so TCP/53 and UDP/53 show as two identical "53 (DNS)" bars. Label as `53/udp (DNS)`. README promises "suspicious combinations" in `tcp_flags.png`: add an 8th red "Suspicious" bar = null + xmas + SYN+FIN + SYN+RST.
  5. **Errors & docs:** `charts.h` promises `PCAPSTAT_ERR_RENDER`, but nothing returns it: check `cairo_status(cr)` after drawing in `export_chart_to_png()` (`src/charts.c:888-893`) and return `PCAPSTAT_ERR_RENDER`. `charts_generate_all()` joins with `"%s/%s"` (`src/charts.c:945`), giving `out//x.png` for `-o out/`: trim trailing slashes like `main.c`'s `join_path()`. Update the `tcp_flags` and histogram docs in `charts.h`.
* **Acceptance Criteria:**
  * New test in `tests/test_charts.c`: a stats context with two buckets at `INT32_MIN` and `INT32_MAX` seconds renders all four charts. Verify locally with `-fsanitize=undefined,float-cast-overflow -fno-sanitize-recover=all` (FIX-01 adds these flags to the makefile in parallel; do not edit the makefile yourself).
  * Visual check (read the PNGs): demo output still looks right; `unsorted_days.pcap` shows three isolated spikes and readable day-scale ticks; `tcp_only.pcap` has distinct y-ticks; `dns_tcp_udp.pcap` shows `53/udp` and `53/tcp`; `extreme_ts2.pcap` has no negative labels.
  * `cairo_save()`/`cairo_restore()` state preservation test still passes.

---

## Wave 2

### FIX-06: Integration — Classification, Truncation Plumbing, Report, Main, CLI

* **Audit:** H1/H2/H3 (stats + report side), H4/H5 (display), CLI & report lows.
* **Dependencies:** FIX-01 … FIX-05 merged into the base branch.
* **Goal:** wire the new parser signals and stats counters end-to-end, and fix the report/CLI defects.
* **Requirements:**
  1. **Classification (`src/stats.c`, `include/stats.h`):** add `non_ip_packets`, `ip_fragments`, `truncated_files` (Shared Contracts). `is_non_ip` → `non_ip_packets` only (no hosts/ports/flows). `is_fragment` → counted in tcp/udp/other by `proto` plus `ip_fragments`; host tx/rx updated; **never** TCP flag counters, ports, flows, port-scan marking or retransmission logic. Update the invariant (`tcp + udp + other + non_ip + malformed == total`) in docs and in `test_category_invariant`.
  2. **Truncation (`src/main.c`, `src/anomaly.c`):** call `parser_process_file_ex()`; increment `stats.truncated_files` when `info.truncated`. Add one anomaly rule "Capture Integrity" (WARNING, subject = file count, description = "N input file(s) truncated or corrupt; statistics cover only the readable part").
  3. **Report (`src/report.c`):**
     * Protocol table rows: TCP, UDP, Other IP, Non-IP frames (ARP/LLDP/…), Malformed, Total.
     * Retransmission card uses `stats->tcp_retransmissions` (subtext includes out-of-order) instead of summing the top-128 flows (`src/report.c:598-603`).
     * Confirm the rate card is correct now that `avg_bps` is bits/s (`src/report.c:555-559`); use `kbps`/`Mbps` labels.
     * Human-readable duration (`3d 04:05:06`) instead of raw seconds.
     * Remove the fabricated `"demo.pcap"` source fallback (`src/report.c:507`): show `(none)`.
     * Replace `%lu` + `(unsigned long)` casts for `uint64_t` with `PRIu64` throughout.
     * Use `ht_count()` instead of reading `->count` directly (`src/report.c:522-523,589,591`).
  4. **Main (`src/main.c`):** use `CHART_FILE_*` and `REPORT_DEFAULT_FILENAME` instead of the duplicated name list (`src/main.c:21-26,122`).
  5. **CLI (`src/cli.c`):** `-o` pointing at an existing non-directory passes validation (`EEXIST`) and later fails with an opaque "chart generation failed (error -2)" — check `S_ISDIR` and print a clear error. Create missing parent directories (`mkdir -p` semantics) to match the README promise. Detect duplicate input files (same `realpath`) and skip them with a warning (merging a file with itself doubles every counter and creates fake findings).
  6. **`include/common.h`:** `PCAPSTAT_MIN/MAX` claim "evaluated once each" — false; fix the comment.
* **Acceptance Criteria:**
  * All unit and integration tests pass on the merged base with the stricter FIX-01 sanitizers.
  * Manual checks with the audit fixtures: `clean_with_arp.pcap` → 0 anomalies, 4 non-IP frames; `udp_fragments.pcap` / `tcp_fragments.pcap` → no Port Scan / Suspicious Flags findings; `truncated.pcap` → exit 0, stderr warning, "Capture Integrity" finding; `-i demo.pcap -i demo.pcap` → duplicate skipped with a warning.
  * Resolve any Follow-ups reported by Wave 1 agents that fall into these files (see "Wave 1 Results & Follow-ups" below).

---

## Wave 3

### FIX-07: End-to-End Tests, Docs, Screenshots

* **Audit:** M6 (integration part), M9 (README), M10 (ARCHITECTURE cleanup), doc lows.
* **Dependencies:** FIX-06 merged.
* **Goal:** a recruiter's `make test` exercises the edge cases, and every doc claim matches the binary.
* **Requirements:**
  1. **Fixture generator:** new `tests/gen_fixture_pcaps.c` (C + libpcap, like `gen_demo_pcap.c`) writing into a directory given on the command line: empty, one-packet, tcp-only, udp-only, ARP + clean TCP, truncated tail, corrupt first record, extreme timestamps, unsorted multi-day, IPv4 UDP/TCP fragments, `tot_len == 0`, short burst in quiet traffic, sub-ms reordering, SLL, SLL2, RAW, QinQ, IPv6. Build it from the makefile.
  2. **`tests/run_tests.sh`:** generate fixtures into the temp dir; for every fixture run release and ASan binaries and assert exit code, summary lines (`Packets :`, `Anomalies :` with exact counts) and no sanitizer output; assert golden demo numbers; check the PDF page count (`/Type /Page` objects, excluding `/Pages`) equals the `Page X of Y` total.
  3. **README.md:** sync every claim with the code: output table (`protocol_ports.png` = top ports with protocol labels; `tcp_flags.png` incl. Suspicious bar), heuristics table (burst baseline, SYN-flood dedup, retransmission vs out-of-order, Capture Integrity rule), bitrate unit, known limitations (non-IP and fragments now handled; all-flood captures have no burst baseline), `make test WERROR=` note, "hardened build" wording matching the real flags, replace the `-i demo -i demo` "merge" example.
  4. **ARCHITECTURE.md:** update the Parser, Stats, Anomaly and Rendering sections; remove stale process notes ("Living document. Updated at milestone tasks (TASK-…)", "not fixed in TASK-06", "despite the comment in decode_ip()").
  5. **Screenshots:** regenerate `docs/traffic_timeline.png` and `docs/protocol_ports.png` from `samples/demo.pcap` and update the README sample output block.
* **Acceptance Criteria:**
  * Fresh clone: `make && make test && make valgrind ARGS="-i samples/demo.pcap -o /tmp/pcapstat_vg"` all exit 0 and follow the README verbatim.
  * Every number, flag, filename and threshold in README/ARCHITECTURE checked against the binary output.
  * `roadmap.md` / `roadmap_fixes.md` untouched (owner decision below).

---

## Wave 1 Results & Follow-ups (recorded 2026-11-20)

| Task | Branch | Commit | Result |
| :--- | :--- | :--- | :--- |
| FIX-01 | `worktree-agent-a857b59f2c4ae00d6` | `ed801b1` | fresh-clone `make test` runs integration suite (34/0); strict sanitizers; `makefile` renamed to `Makefile` |
| FIX-02 | `worktree-agent-a9aa2215a17aa05ec` | `d7d1bbd` | `parser_process_file_ex`, `is_non_ip`, `is_fragment`, TSO lengths; test_parser 18/18 |
| FIX-03 | `worktree-agent-a7a3edcff8ca5ef88` | `2ffcebf` | spoofed flood 856 → 61 MB RSS; bits/s; `tcp_retransmissions`/`tcp_out_of_order`; histogram bins; fmix64 |
| FIX-04 | `worktree-agent-aa8fedc3233251ab5` | `e90a6a1` | leave-one-out burst baseline, merged UTC burst findings, SYN-flood dedup; test_anomaly 19/19 |
| FIX-05 | `worktree-agent-a86111056600181d5` | `b9f4635` | no float-cast UB, gaps drop to 0, `%g` ticks, `53/udp` labels, Suspicious bar, ERR_RENDER |

Merge order stays FIX-01 → FIX-05 (FIX-01 contains a case-only rename `makefile` → `Makefile`).

**Owner decision for FIX-06:** a capture with only **one** active second has no burst baseline and must produce **no** UDP Burst finding. Change `udp_leave_one_out_baseline()` / `detect_udp_bursts()` in `src/anomaly.c` accordingly (n == 1 → skip), update `include/anomaly.h` docs and the `test_udp_flood_without_baseline` expectation (single 100-packet second → 0 findings).

**Follow-ups for FIX-06:**
* `src/stats.c`: `is_fragment` must skip TCP flag counters, ports, flows, port-scan and retransmission logic — until then `tcp_fragments.pcap` yields a false CRITICAL "Null Scan" (fragments arrive with flags 0).
* `src/main.c`: switch to `parser_process_file_ex()`; the parser already prints the truncation warning, so do not print a second one; update the comment at the positive-return-code conversion.
* `src/report.c`: retransmission card from `stats->tcp_retransmissions` (out-of-order in subtext); rate label `kbps` (lowercase) — values are already correct since `avg_bps` is bits/s; optionally an out-of-order column in the flows table.
* `include/stats.h`: the `udp_packets_max` comment ("kept for burst detection") is stale — `anomaly.c` no longer reads it.
* Path joining exists twice (`main.c` `join_path()`, `charts.c` `join_output_path()`); consider one shared helper. `mkdir -p` for `-o` is still missing (already in scope).
* Optional: global retransmission rule in `anomaly.c` may read `stats->tcp_retransmissions` (same value).
* Verify `test_demo_pcap_anomalies` (exactly 6 findings) on the merged base.

**Follow-ups for FIX-07 (docs/tests):**
* README: sanitizer flags line (`-fsanitize=address,undefined,float-cast-overflow -fno-sanitize-recover=all`), "Hardened build" = `-D_FORTIFY_SOURCE=2 -fstack-protector-strong` in release, document `make test WERROR=` and `make CC=...`; file is now `Makefile`.
* README/ARCHITECTURE: non-IP frames no longer malformed; non-first IPv4 fragments flagged; TSO/BIG TCP length handling; truncated files analyzed with a warning; corrupt first record is a hard error (**process exit code 1**, internal `PCAPSTAT_ERR_PCAP`).
* README/ARCHITECTURE: inline-16 + lazy bitmap (no 8 KB per host), `next_seq` + hole + 3 ms out-of-order window, bits/s, half-open histogram bins, fmix64.
* README/ARCHITECTURE: burst = leave-one-out baseline, merged runs, UTC subject, no finding for single-second or all-flood captures; SYN-flood dedup for port scanners.
* README: Suspicious bar, `port/proto (service)` labels, timeline drops to 0 across gaps, day-scale axis labels; regenerate `docs/protocol_ports.png` (and re-check `docs/traffic_timeline.png`).
* Fixtures: a sub-ms reorder fixture must not swap the very first data segment (SYN is not tracked), or must expect 1 retransmission.
* Optional: `$(WERROR)` in `TEST_CFLAGS`; `print_suppressions=0` in `run_tests.sh` `LSAN_OPTIONS`.

## Merge Procedure (coordinator)

1. Wait for all Wave 1 reports; read each *Deviations* and *Follow-ups* section.
2. Merge the branches into `main` (or an integration branch) in order FIX-01, 02, 03, 04, 05; after each merge: `make clean && make test`.
3. Expected conflicts: none textual (disjoint files). Expected semantic issues: demo-based expectations in `test_anomaly.c` vs the new retransmission semantics (FIX-03), and fragments counted as zero-flag TCP until FIX-06. Hand both to FIX-06.
4. Launch FIX-06 on the merged base, merge it, then FIX-07.

## Agent Prompts

### Prompt template (any agent/tool with file access)

```
You are the implementation agent for task {TASK_ID} ("{TITLE}") of the pcapstat fix roadmap:
a C11 Linux CLI (libpcap + cairo) that analyzes .pcap files and writes PNG charts and a PDF report.

Your working directory is your own isolated git worktree of the pcapstat repo. Other agents work
on other tasks in parallel in their own worktrees.

1. Read in full (read-only, never edit it):
   /mnt/c/Users/Juliusz/Desktop/studia/hackaton/pcapstat/roadmap_fixes.md
   Sections: "Global Context & Rules", "Shared Contracts", "File Ownership", "{TASK_ID}".
   Then read every source file your task owns.
2. Implement {TASK_ID} exactly. Edit only files {TASK_ID} owns and only inside your worktree (your
   cwd); never edit the main checkout. If another file seems to need a change, do not change it;
   list it under Follow-ups. Never modify samples/demo.pcap, tests/gen_demo_pcap.c, roadmap*.md.
   Add a regression test for every defect you fix.
3. Verify every Acceptance Criterion with real commands (zero-warning build: make && make debug &&
   make asan && make unit-test; then bash tests/run_tests.sh). Report exact results; never claim a
   check you did not run.
4. Commit on your worktree branch only (never main, never push): subject "{TASK_ID}: <summary>",
   body listing the audit IDs fixed, last line:
   Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
5. Final report sections: Branch & commit (git rev-parse --abbrev-ref HEAD; git log -1 --format=%H;
   pwd), Changes (per audit ID with file:line), Tests added, Verification (commands + pass/fail
   counts), Deviations from spec (with reasons), Follow-ups for other tasks.

Task-specific notes:
{NOTES}
```

### Task-specific notes

* **FIX-01:** `core.fileMode=false` → use `git update-index --chmod=+x tests/run_tests.sh`. Prove the fix from a fresh `git clone` of your worktree after committing; amend the commit if you change anything. If the stricter sanitizers expose defects in files you do not own, report them; do not fix them.
* **FIX-02:** Build synthetic pcaps inside the tests (`mkstemp` + `pcap_open_dead`/`pcap_dump_open`, or raw `fwrite` for truncated/corrupt files). Do not touch `src/stats.c`: until FIX-06, non-IP frames count as `other` and fragments as zero-flag TCP/UDP — this is intended.
* **FIX-03:** Memory check uses `spoofed_synflood_100k.pcap` and `sweep_16.pcap` from the audit fixtures dir with the **release** binary and `/usr/bin/time -v`. Do not edit `tests/test_anomaly.c`; report breakages there as Follow-ups.
* **FIX-04:** Work only with existing `stats_ctx_t` fields. The audit fixture `udp_flood_3s.pcap` is an all-flood capture with no baseline and is expected to stay unflagged; build your own burst-in-quiet-traffic tests.
* **FIX-05:** Inspect PNGs by reading the image files. Verify the UB fix with a local build using `-fsanitize=undefined,float-cast-overflow -fno-sanitize-recover=all`; do not edit the makefile (FIX-01 owns it).
* **FIX-06:** Start by merging/reading the Wave 1 reports' Follow-ups that fall into your files. Run the full suite with the stricter sanitizers from FIX-01.
* **FIX-07:** Follow the README verbatim from a fresh clone at the end; every documented command must work as written.

## Out of Scope / Owner Decisions

* **M10 — AI process artifacts.** `roadmap.md` (and this file) describe an AI-agent workflow and are tracked at the repo root. Whether to keep them (e.g. moved to `docs/` with a short "How this was built" note) or remove them before submission depends on the assignment's rules on AI assistance. No agent may delete them.
* IPv6 extension-header walking, IPv4 reassembly, pcapng multi-interface support, L7 inspection, per-victim SYN-flood attribution — future work, unchanged.
