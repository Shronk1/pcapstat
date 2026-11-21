# pcapstat — Architecture

## Overview

`pcapstat` is a Linux CLI tool that analyses TCP/UDP traffic from one or more
`.pcap` files and produces PNG charts plus a multi-page PDF report containing
statistics, traffic characteristics, and detected anomalies.

### Data Pipeline

```text
 .pcap file(s)
      │
      ▼
  ┌────────┐   parsed_packet_t   ┌────────────┐
  │ Parser │ ──────────────────▶ │ Stats      │
  └────────┘                     │ Engine     │
                                 └─────┬──────┘
                                       │ stats_ctx_t
                        ┌──────────────┼──────────────┐
                        ▼              ▼              ▼
                 ┌──────────┐   ┌──────────┐   ┌──────────┐
                 │ Anomaly  │   │ Charts   │   │ Report   │
                 │ Detector │   │ (PNG)    │   │ (PDF)    │
                 └──────────┘   └──────────┘   └──────────┘
```

`main.c` wires the stages: `cli_parse()` → `cli_validate_and_prepare()` →
`parser_process_file_ex()` per input with `stats_packet_cb()` →
`stats_finalize()` → `anomaly_detect()` → `charts_generate_all()` →
`report_generate()` → one-screen summary on stdout.

## Error-Code Convention

All public functions return `int` from `enum pcapstat_err` (defined in
`include/common.h`). `0` = success; negative values indicate specific
failures (`PCAPSTAT_ERR_ARGS`, `_IO`, `_PCAP`, `_NOMEM`, `_RENDER`).
Resources are released before returning via a `goto cleanup` pattern.
The process exits `0` on success and `1` (`EXIT_FAILURE`) on any error.

## Memory Ownership Rules

* **Caller allocates, callee fills:** Structs like `stats_ctx_t` and
  `anomaly_list_t` are initialized by dedicated `_init()` functions and freed
  by corresponding `_free()` functions.
* **Borrowed pointers:** Callback arguments (e.g., `const parsed_packet_t *`)
  are valid only for the duration of the callback invocation.
* **Top-N results** (`stats_top_*`) return borrowed pointers valid until
  `stats_free()`.

## CLI

* `-i` (repeatable) and positional arguments collect inputs; `-o` defaults to
  `./pcapstat_out`; `--portscan-threshold` must be an integer in
  `1 .. UINT32_MAX`.
* **Validation:** every input must be readable (`access(R_OK)`). Inputs that
  name the same file as an earlier one (same device and inode, so `../`
  paths, symlinks and hard links are caught) are removed with
  `pcapstat: warning: skipping duplicate input '<dup>' (same file as
  '<first>')`, because merging a file with itself doubles every counter.
* **Output directory:** created with `mkdir -p` semantics (mode `0755`). An
  existing non-directory fails with `pcapstat: output path '<p>' exists and
  is not a directory`.

## Parser

`parser_process_file_ex()` opens a `.pcap` via `pcap_open_offline()` and
decodes each packet into a stack-local `parsed_packet_t`, invoking a user
callback. `parser_process_file()` is the same call without the outcome record.

* **Supported DLTs:** `DLT_EN10MB` (Ethernet II, with 802.1Q `0x8100` and
  QinQ `0x88A8` VLAN tag peeling), `DLT_LINUX_SLL` (16 B), `DLT_LINUX_SLL2`
  (20 B), and `DLT_RAW` (version nibble detection). Any other link type is a
  hard error (`PCAPSTAT_ERR_PCAP`).
* **Alignment safety:** All L2/L3/L4 headers are read via `memcpy()` into
  stack-local `struct iphdr`, `struct ip6_hdr`, `struct tcphdr`, `struct udphdr`.
  No raw pointer casts — eliminates UBSan misaligned-address errors.
* **Bounds checking:** Every `memcpy` is preceded by `offset + needed <= caplen`.
  On failure the packet is marked `is_malformed = true`.
* **Callback for every packet:** The parser does not filter. Every frame is
  delivered to the callback with at most one classification flag set:
  * `is_malformed` — truncated by `caplen`, `ihl < 5`, `tot_len < ihl*4`,
    `doff < 5`, `udp_len < 8`, a VLAN tag cut short, or `DLT_RAW` with an
    unknown IP version.
  * `is_non_ip` — the link layer decoded fine but carries no IPv4/IPv6
    (ARP, LLDP, STP, ...); `ip_version == 0`, not malformed.
  * `is_fragment` — IPv4 non-first fragment (offset != 0). L3 fields and
    `proto` are valid; L4 is **not** decoded, so ports, TCP fields and
    `payload_len` are 0. First fragments (offset 0, MF set) are decoded
    normally.
  Well-formed IPv4/IPv6 packets with another L4 protocol (ICMP, GRE, ESP, ...)
  keep `proto` set and no flag.
* **TSO / BIG TCP:** an IPv4 `tot_len` of 0 or an IPv6 payload length of 0
  (written by segmentation offload when capturing on the sending host) means
  "length taken from the frame" (`wire_len`), not malformed.
* **Damaged files:** `pcap_next_ex()` returning `PCAP_ERROR` before the first
  packet (e.g. an impossible `caplen` in the first record) prints an error and
  returns `PCAPSTAT_ERR_PCAP`. After at least one packet (a capture killed
  mid-write), it prints `pcapstat: warning: '<file>': <pcap error> (stopped
  after N packets)`, sets `parser_file_info_t::truncated` and returns
  `PCAPSTAT_OK`, so the readable part is analyzed.
* **Callback return:** any non-zero value stops parsing and is returned
  unchanged.
* **Limitation:** IPv6 extension-header chains are not followed; TCP/UDP
  behind an extension header has `proto` of the first extension header and is
  counted as "other".

## Stats Engine

* **Streaming core.** No packet is retained; all state is aggregate counters,
  sparse one-second buckets and per-host/port/flow hash-table entries.
* **Category invariant.** Every packet is counted in exactly one of
  `tcp_packets`, `udp_packets`, `other_packets`, `non_ip_packets`,
  `malformed_packets`, so
  `tcp + udp + other + non_ip + malformed == total_packets`. Malformed wins
  over protocol, so a truncated TCP packet is not a TCP packet.
  `other_packets` means "well-formed IP, not TCP/UDP". Percentages use
  `total_packets` as denominator.
* **Non-IP frames** increment only `non_ip_packets` (plus totals, histogram
  and time bucket): no hosts, ports or flows.
* **IPv4 fragments** count under their IP protocol (tcp/udp/other) and in the
  informational `ip_fragments` counter (not part of the invariant). They
  update host tx/rx counters only and never reach the TCP flag counters,
  ports, flows, port-scan sets or retransmission analysis.
* **File counters.** `files_processed` and `truncated_files` are maintained by
  the caller (`main.c`) after each file; the engine never touches them.
* **TCP flags.** Counted for non-malformed, non-fragment TCP only. `syn` is
  *pure* SYN (SYN set, ACK clear); SYN+ACK is counted only in `syn_ack`, so
  `syn / syn_ack` is a usable SYN-flood signal. `ack` includes SYN+ACK.
  `null` (flags == 0), `xmas` (FIN+PSH+URG, SYN clear), `syn_fin`, `syn_rst`
  may overlap with the single-flag counters (e.g. `syn_rst` also adds to
  `rst`, but not to `syn` if ACK is set).
* **Packet-size histogram.** Half-open wire-length bins
  `[0,64) [64,128) [128,256) [256,512) [512,1024) [1024,1514) [1514,∞)`,
  matching the chart labels `<64 … 1024-1513, >=1514`.
* **Timestamps.** A timestamp is usable if finite and `|ts| < 9.0e18`, so
  `(int64_t)floor(ts)` is defined. `first_ts`/`last_ts` (min/max, so input
  order is irrelevant) are tracked over usable timestamps only, via
  `timestamped_packets`. Packets without a usable timestamp still count in
  all global counters but are in no time-series bucket, so
  `sum(timeline.packets) <= total_packets`.
* **Sparse time series.** One-second buckets live in `ts_buckets_ht`, keyed
  by `int64_t sec`, allocated lazily. No dense range array exists, so
  captures spanning days or years cost memory only per active second.
  Bucket `packets`/`bytes` include malformed and non-IP frames; protocol
  fields do not.
* **Downsampling.** `stats_finalize()` sorts buckets and, above 120, merges
  consecutive buckets into exactly 120 groups of equal bucket count (sizes
  differ by at most one). Groups are therefore *not* equal in time.
  `span_sec = last_sec - first_sec + 1` (gaps included, 1 for raw buckets)
  records the wall-clock time a bucket covers; **rates must be computed as
  `packets / span_sec`**, otherwise constant traffic renders as a sawtooth.
  Totals are preserved by merging.
* **Derived rates.** `duration_sec = last_ts - first_ts`,
  `avg_pps = total_packets / duration_sec`, and
  `avg_bps = 8 * total_bytes / duration_sec` in **bits** per second. All three
  are 0.0 when there are fewer than two distinct usable timestamps.
  `stats_finalize()` is idempotent and may be called again after more updates.
* **Hosts and ports.** `hosts_ht` stores per-IP transmit/receive counters,
  TCP SYN/RST counters, and the set of probed destination ports (pure TCP
  SYNs and UDP datagrams that are not replies to an earlier reverse flow;
  TCP and UDP share one set; port 0 ignored). The set keeps the first 16
  ports inline and promotes to a lazily `malloc`ed 8 KB bitmap (65,536 bits)
  on the 17th, so receive-only hosts allocate no port storage. Host objects
  are freed only through the module's host destructor. `ports_ht` aggregates
  packet/byte counts by `{proto, dst_port}`; service names are a static
  IANA lookup (`"Unknown"` otherwise).
* **Flows, retransmissions and reordering.** `flows_ht` stores directional
  `{ip_version, src_ip, dst_ip, src_port, dst_port, proto}` aggregates. For
  payload-bearing TCP segments each flow tracks `next_seq` (highest
  `seq + payload_len`) and one sequence hole, with wrap-safe `(int32_t)`
  differences:
  * `seq >= next_seq` → new data (a jump forward records the hole);
  * a segment inside the hole less than `STATS_OOO_WINDOW_SEC` (3 ms) after
    the segment that opened it → `out_of_order`;
  * anything else below `next_seq` → `retransmissions`;
  * a segment earlier in time than the flow's last advance (e.g. files
    merged out of chronological order) rebases instead of counting.
  `tcp_retransmissions` / `tcp_out_of_order` in `stats_ctx_t` are the sums
  over all flows. SYN is not tracked: if the first two data segments arrive
  swapped, the earlier one counts as a retransmission.
* **Hash table.** Separate chaining; keys are hashed with 64-bit FNV-1a, mixed
  with the murmur3 `fmix64` finalizer (the low bits of raw FNV-1a mix poorly
  and keys come from untrusted captures), then masked; the table doubles
  above a 0.7 load factor.
* **Ranking complexity.** Top-N export iterates its table, copies table
  pointers into a temporary `O(n)` array, sorts with `qsort()`, and returns
  borrowed pointers valid until `stats_free()`.
* **Errors.** Counters are updated before bucket/host/flow allocation, so
  after `PCAPSTAT_ERR_NOMEM` the context is partial and must be discarded.

## Anomaly Detection

`anomaly_detect()` evaluates aggregated statistics in `stats_ctx_t` against
run-time thresholds (`anomaly_thresholds_t` initialized to defaults from
`common.h` or overridden by CLI flags). Findings are appended to caller-owned
`anomaly_list_t` (dynamic array freed by `anomaly_list_free()`) and sorted
descending by severity (`CRITICAL` -> `WARNING` -> `INFO`) with deterministic
tie-breaking by category, subject, and description. No built-in rule emits
`INFO`.

### Heuristics Table

| Heuristic | Exact Condition / Formula | Default Threshold | Severity |
| :--- | :--- | :--- | :--- |
| **Port Scan** | Host `unique_dst_ports >= portscan_threshold` (pure SYNs and non-reply UDP) | `20` ports | `CRITICAL` |
| **SYN Flood** | Host `syn_sent >= syn_flood_min` and `syn_sent / syn_ack_recv > syn_ratio` (0 SYN-ACKs: ratio = SYN count). Skipped for hosts that meet the port-scan threshold. If no host met the criteria, the global `syn / syn_ack` (subject `Global`) | `>= 50` pkts, `> 3.0` ratio | `CRITICAL` |
| **TCP Retransmissions** | Flow `retrans / pkts > retrans_pct` (min 20 pkts); if no flow is flagged, Global `sum(retrans) / tcp_pkts > retrans_pct` (min 20 pkts) | `> 5.0%` | `WARNING` |
| **RST Spike** | Global `rst / tcp_pkts > rst_pct` (min 30 TCP pkts) | `> 10.0%` | `WARNING` |
| **Suspicious TCP Flags** | Any Null (`0`), Xmas (`FIN+PSH+URG`), `SYN+FIN`, or `SYN+RST` segment; one finding per pattern | `> 0` pkts | `CRITICAL` |
| **UDP Burst** | Second with `b` UDP pkts: `b >= udp_burst_min` and `b > udp_burst_mult * (U - b) / (n - 1)` (leave-one-out mean over the `n` active seconds, `U` = UDP total) | `>= 100` pkt/s, `> 3.0x` baseline | `WARNING` |
| **Malformed Packets** | `malformed_packets > 0` (truncated headers, illegal IHL/length) | `> 0` pkts | `WARNING` |
| **Capture Integrity** | `truncated_files > 0`; subject `T of F file(s)`, description `T input file(s) truncated or corrupt; statistics cover only the readable part` | `> 0` files | `WARNING` |

UDP burst details: consecutive flagged seconds are merged into one finding
whose subject is the UTC start time (`YYYY-MM-DD HH:MM:SS UTC`) and whose
description gives the duration, total and peak pkt/s, the peak second's
baseline and the thresholds. A capture with a single active second has no
baseline and is never flagged; a capture that is entirely a constant flood
has no quiet baseline either (every second's baseline equals the flood rate),
and a constant flood in otherwise idle traffic is flagged only while it
covers less than about `1 / udp_burst_mult` of the active seconds.

## Rendering & PDF

Traffic visualization and report generation rely on `libcairo`:

* **Shared Cairo Architecture:** Drawing routines in `charts.h` accept a borrowed `cairo_t *` and a bounding box `(x, y, w, h)`, isolating graphics state via `cairo_save()` and `cairo_restore()`. This enables direct vector embedding in PDF reports as well as standalone PNG export (`cairo_image_surface_create()`). Each routine checks `cairo_status()` and returns `PCAPSTAT_ERR_RENDER` if the context is in an error state; `charts_generate_all()` trims trailing slashes from the output directory.
* **Charts:**
  * *Traffic timeline:* TCP and UDP packets/s (`packets / span_sec`). Where a bucket does not start where the previous one ended, both lines drop to 0 across the gap. X labels are offsets whose unit follows the capture span (`+12s`, `+05:30`, `+3h05m`, `+2d04h`), computed on `int64_t`/`double` with clamping, so spans beyond `INT_MAX` seconds are safe.
  * *Top destination ports:* labels `"<port>/<proto> (<service>)"`, e.g. `53/udp (DNS)`, so TCP and UDP on the same port number stay distinct.
  * *Packet sizes:* the seven histogram bins with percentages of all packets.
  * *TCP flags:* SYN, SYN-ACK, ACK, FIN, RST, PSH, URG plus a dark-red "Suspicious" bar (null + xmas + SYN+FIN + SYN+RST).
  * Value-axis ticks are the maximum split into quarters, printed with `%g` below 1000 (`0 0.25 0.5 0.75 1`) and in compact metric form above (`2.5K`).
* **Multi-Page PDF Report:** `report_generate()` produces an A4 (`595 x 842 pt`) PDF via `cairo_pdf_surface_create()`:
  * Page 1: capture sources (`(none)` if empty), KPI cards and the protocol table (TCP, UDP, Other IP, Non-IP frames, Malformed, Total) with a TCP flag table. Duration is `12.34 s` below a minute, else `HH:MM:SS` or `Nd HH:MM:SS`; the rate card shows `X pps | Y bps/kbps/Mbps/Gbps` (bits per second, SI prefixes); the TCP card shows the global retransmission count with out-of-order, SYN and RST counts.
  * Page 2: Top 10 talkers, destination ports, and flows with alternating zebra striping.
  * Page 3: 2×2 vector chart grid.
  * Page 4+: detected anomalies with severity badges.
* **Text Wrapping & Dynamic Pagination:** An internal text-wrapping engine evaluates word widths via `cairo_text_extents()` to prevent margin overflow across file lists and descriptions. Anomaly findings paginate across multiple pages (`cairo_show_page()`) under running headers and footers with generation timestamps. The `Page X of Y` total is computed with the same row-layout function used for rendering, so it always matches the pages emitted.

## Testing

* **Unit tests** (`tests/test_*.c`, `make unit-test`) are built with
  `-fsanitize=address,undefined,float-cast-overflow -fno-sanitize-recover=all`,
  so any sanitizer report fails the test. Inputs are synthetic: captures
  written to temporary files (`pcap_open_dead()` + `pcap_dump_open()`, or raw
  writes for damaged files) and hand-built `stats_ctx_t` / anomaly lists.
* **Integration tests** (`tests/run_tests.sh`, `make test`) generate
  edge-case captures with `tests/gen_fixture_pcaps.c` into a temporary
  directory, run each through the release and ASan binaries, and check exit
  codes, stderr, the summary lines, golden numbers for `samples/demo.pcap`,
  and the PDF (page objects, `Page X of Y` footers and key text, extracted by
  inflating the PDF streams with `gzip`).
