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
- **Malformed packets:** Delivered to the callback with `is_malformed` set so
  downstream modules can count them. Covers truncated captures, `ihl < 5`,
  `tot_len < ihl*4`, `doff < 5`, and `udp_len < 8`.
- **Callback lifetime:** `const parsed_packet_t *pkt` is a borrowed pointer
  valid only during the callback invocation.

## Stats Engine

*Placeholder — to be completed in TASK-06 / TASK-07.*

## Anomaly Detection

*Placeholder — to be completed in TASK-08.*

## Rendering & PDF

*Placeholder — to be completed in TASK-09 / TASK-10.*
