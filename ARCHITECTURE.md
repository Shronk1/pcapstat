# pcapstat — Architecture

> Living document. Updated at milestone tasks (TASK-01, -04, -07, -08, -10).

## Overview

`pcapstat` is a Linux CLI tool that analyses TCP/UDP traffic from one or more
`.pcap` files and produces PNG charts plus a multi-page PDF report containing
statistics, traffic characteristics, and detected anomalies.

### Data Pipeline

```
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

## Error-Code Convention

All public functions return `int` from `enum pcapstat_err` (defined in
`include/common.h`). `0` = success; negative values indicate specific
failures (`PCAPSTAT_ERR_ARGS`, `_IO`, `_PCAP`, `_NOMEM`, `_RENDER`).
Resources are released before returning via a `goto cleanup` pattern.

## Memory Ownership Rules

* **Caller allocates, callee fills:** Structs like `stats_ctx_t` and
  `anomaly_list_t` are initialized by dedicated `_init()` functions and freed
  by corresponding `_free()` functions.
* **Borrowed pointers:** Callback arguments (e.g., `const parsed_packet_t *`)
  are valid only for the duration of the callback invocation.
* **Top-N results** (`stats_top_*`) return borrowed pointers valid until
  `stats_free()`.

## Parser

`parser_process_file()` opens a `.pcap` via `pcap_open_offline()` and decodes
each packet into a stack-local `parsed_packet_t`, invoking a user callback.

- **Supported DLTs:** `DLT_EN10MB` (Ethernet II, with 802.1Q `0x8100` and
  QinQ `0x88A8` VLAN tag peeling), `DLT_LINUX_SLL` (16 B), `DLT_LINUX_SLL2`
  (20 B), and `DLT_RAW` (version nibble detection).
- **Alignment safety:** All L2/L3/L4 headers are read via `memcpy()` into
  stack-local `struct iphdr`, `struct ip6_hdr`, `struct tcphdr`, `struct udphdr`.
  No raw pointer casts — eliminates UBSan misaligned-address errors.
- **Bounds checking:** Every `memcpy` is preceded by `offset + needed <= caplen`.
  On failure the packet is marked `is_malformed = true`.
- **Callback for every packet:** The parser does not filter. Every frame,
  including malformed and non-TCP/UDP ones, is delivered to the callback.
  Well-formed IPv4/IPv6 packets with another L4 protocol (ICMP, GRE, ESP, ...)
  keep `proto` set and `is_malformed == false`.
- **Malformed packets:** `is_malformed` is set for truncated captures,
  `ihl < 5`, `tot_len < ihl*4`, `doff < 5`, `udp_len < 8`, DLT_RAW with an
  unknown IP version, **and for any EtherType that is not IPv4/IPv6**
  (ARP, LLDP, STP, ...), see limitations below.
- **Known limitations (not fixed in TASK-06):**
  1. Non-IP frames are flagged `is_malformed` (despite the comment in
     `decode_ip()`), so downstream code cannot tell them from truncated
     packets (both have `ip_version == 0`). `malformed_packets` is therefore
     "malformed + non-IP". A dedicated flag/counter in the parser is the
     proper fix.
  2. IPv6 extension-header chains are not followed; TCP/UDP behind an
     extension header has `proto` of the first extension header and is
     counted as "other".
  3. IPv4 fragments with non-zero offset are still decoded as L4, so their
     ports/flags are unreliable.
- **Callback lifetime:** `const parsed_packet_t *pkt` is a borrowed pointer
  valid only during the callback invocation.

## Stats Engine

* TASK-06 provides a streaming, no-packet-retention stats core.
* **Category invariant.** Every packet is counted in exactly one of
  `tcp_packets`, `udp_packets`, `other_packets`, `malformed_packets`, so
  `tcp + udp + other + malformed == total_packets`. Malformed wins over
  protocol, so a truncated TCP packet is not a TCP packet. `other_packets`
  means "well-formed, not TCP/UDP" (see Parser). Percentages for reports
  must use `total_packets` as denominator.
* **TCP flags.** Counted for non-malformed TCP only. `syn` is *pure* SYN
  (SYN set, ACK clear); SYN+ACK is counted only in `syn_ack`, so
  `syn / syn_ack` is a usable SYN-flood signal. `ack` includes SYN+ACK.
  `null` (flags == 0), `xmas` (FIN+PSH+URG, SYN clear), `syn_fin`, `syn_rst`
  may overlap with the single-flag counters (e.g. `syn_rst` also adds to
  `rst`, but not to `syn` if ACK is set).
* **Timestamps.** A timestamp is usable if finite and `|ts| < 9.0e18`, so
  `(int64_t)floor(ts)` is defined. `first_ts`/`last_ts` (min/max, so input
  order is irrelevant) are tracked over usable timestamps only, via
  `timestamped_packets`. Packets without a usable timestamp still count in
  all global counters but are in no time-series bucket, so
  `sum(timeline.packets) <= total_packets`.
* **Sparse time series.** One-second buckets live in `ts_buckets_ht`, keyed
  by `int64_t sec`, allocated lazily. No dense range array exists, so
  captures spanning days or years cost memory only per active second.
  Bucket `packets`/`bytes` include malformed packets; protocol fields
  do not.
* **Downsampling.** `stats_finalize()` sorts buckets and, above 120, merges
  consecutive buckets into exactly 120 groups of equal bucket count (sizes
  differ by at most one). Groups are therefore *not* equal in time.
  `span_sec = last_sec - first_sec + 1` (gaps included, 1 for raw buckets)
  records the wall-clock time a bucket covers; **rates must be computed as
  `packets / span_sec`**, otherwise constant traffic renders as a sawtooth.
  `udp_packets_max` keeps the largest raw one-second UDP count in the group
  for burst detection. Totals are preserved by merging.
* **Edge cases.** `duration_sec`, `avg_pps`, `avg_bps` are 0.0 when there
  are fewer than two distinct usable timestamps. `stats_finalize()` is
  idempotent and may be called again after more updates.
* **Ownership and errors.** `files_processed` is incremented by the caller
  (main) after each successful file; the engine never touches it. Counters
  are updated before bucket allocation, so after `PCAPSTAT_ERR_NOMEM` the
  context is partial and must be discarded. Finalized timeline and the
  reserved host/port/flow tables are owned by `stats_ctx_t` until
  `stats_free()`; parsed packets remain callback-borrowed and are never
  copied.

* **Hosts and ports.** `hosts_ht` stores per-IP transmit/receive counters,
  TCP SYN/RST counters, and one 8 KB fixed `dst_ports_bitmap[8192]` for
  65,536 distinct destination ports. `ports_ht` aggregates packet/byte
  counts by `{proto, dst_port}`; service names are a static lookup.
* **Flows and retransmissions.** `flows_ht` stores directional
  `{ip_version, src_ip, dst_ip, src_port, dst_port, proto}` aggregates.
  Payload-bearing TCP packets use wrap-safe signed modular sequence
  arithmetic: `pkt->timestamp >= last_seq_ts` and
  `(int32_t)(tcp_seq - max_seq) <= 0` identifies a retransmission candidate.
* **Streaming memory model.** Host, port, and flow entries are sparse
  hash-table objects; no packet or capture-wide per-timestamp array is
  retained. Each host has a fixed 8 KB bitmap and no nested allocations.
* **Ranking complexity.** Top-N export iterates its table, copies table
  pointers into a temporary `O(n)` array, sorts with `qsort()`, and returns
  borrowed pointers. Results remain valid until `stats_free()`; table
  iteration and sorting are O(n) and O(n log n), respectively.

## Anomaly Detection

`anomaly_detect()` evaluates aggregated statistics in `stats_ctx_t` against
run-time thresholds (`anomaly_thresholds_t` initialized to defaults from
`common.h` or overridden by CLI flags). Findings are appended to caller-owned
`anomaly_list_t` (dynamic array freed by `anomaly_list_free()`) and sorted
descending by severity (`CRITICAL` -> `WARNING` -> `INFO`) with deterministic
tie-breaking by category, subject, and description.

### Heuristics Table

| Heuristic | Exact Condition / Formula | Default Threshold | Severity |
| :--- | :--- | :--- | :--- |
| **Port Scan** | Host `unique_dst_ports >= portscan_threshold` (via SYN/UDP) | `20` ports | `CRITICAL` |
| **SYN Flood** | Host or Global `SYN >= syn_flood_min` and `SYN / SYN_ACK > syn_ratio` | `>= 50` pkts, `> 3.0` ratio | `CRITICAL` |
| **TCP Retransmissions** | Flow `retrans / pkts > retrans_pct` (min 20 pkts) or Global `total_retrans / tcp_pkts > retrans_pct` (min 20 pkts) | `> 5.0%` | `WARNING` |
| **RST Spike** | Global `rst / tcp_pkts > rst_pct` (min 30 TCP pkts) | `> 10.0%` | `WARNING` |
| **Suspicious TCP Flags** | Any Null (`0`), Xmas (`FIN+PSH+URG`), `SYN+FIN`, or `SYN+RST` segment | `> 0` pkts | `CRITICAL` |
| **UDP Burst / Flood** | 1-second window `udp_pkts >= udp_burst_min` and `udp_pkts > udp_burst_mult * mean_udp` | `>= 100` pkt/s, `> 3.0x` mean | `WARNING` |
| **Malformed Packets** | `malformed_packets > 0` (truncated headers, illegal IHL/length) | `> 0` pkts | `WARNING` |

## Rendering & PDF

Traffic visualization and report generation rely on `libcairo`:
- **Shared Cairo Architecture:** Drawing routines in `charts.h` accept a borrowed `cairo_t *` and a bounding box `(x, y, w, h)`, isolating graphics state via `cairo_save()` and `cairo_restore()`. This enables direct vector embedding in PDF reports as well as standalone PNG export (`cairo_image_surface_create()`).
- **Multi-Page PDF Report:** `report_generate()` produces an A4 (`595 x 842 pt`) PDF via `cairo_pdf_surface_create()`. The document is organized into Page 1 (Executive Summary & KPI cards), Page 2 (Top 10 Talkers, Destination Ports, and Flows with alternating zebra striping), Page 3 ($2 \times 2$ vector chart grid), and Page 4+ (detected anomalies with severity badges).
- **Text Wrapping & Dynamic Pagination:** An internal text-wrapping engine evaluates word widths via `cairo_text_extents()` to prevent margin overflow across file lists and descriptions. Anomaly findings automatically paginate across multiple pages (`cairo_show_page()`) under running headers and footers with generation timestamps and pre-calculated `Page X of Y` indicators.