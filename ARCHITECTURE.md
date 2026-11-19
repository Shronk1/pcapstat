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

*Placeholder — to be completed in TASK-04.*

## Stats Engine

*Placeholder — to be completed in TASK-06 / TASK-07.*

## Anomaly Detection

*Placeholder — to be completed in TASK-08.*

## Rendering & PDF

*Placeholder — to be completed in TASK-09 / TASK-10.*
