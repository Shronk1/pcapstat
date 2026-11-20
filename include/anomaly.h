/**
 * @file anomaly.h
 * @brief Rule-based network anomaly detection engine.
 *
 * Evaluates traffic aggregated by the statistics engine (stats_ctx_t)
 * against configurable thresholds (anomaly_thresholds_t) and populates
 * an anomaly list sorted by severity (CRITICAL -> WARNING -> INFO).
 *
 * Memory ownership:
 * - anomaly_list_t is allocated/held on stack or heap by the caller.
 * - anomaly_list_init() initializes the dynamic array.
 * - anomaly_detect() appends detected anomalies into caller-owned anomaly_list_t.
 * - anomaly_list_free() releases the heap array owned by anomaly_list_t.
 * - Individual anomaly_t elements contain fixed-size char arrays, so no
 *   nested allocations exist inside elements.
 */

#ifndef PCAPSTAT_ANOMALY_H
#define PCAPSTAT_ANOMALY_H

#include "common.h"
#include "stats.h"

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Anomaly severity level.
 *
 * Ordered by ascending severity value so that numerical sorting
 * or comparison can order critical alerts first.
 */
typedef enum anomaly_severity {
    ANOMALY_INFO     = 0, /**< Informational event (e.g., malformed frame). */
    ANOMALY_WARNING  = 1, /**< Suspicious event (e.g., elevated retransmissions). */
    ANOMALY_CRITICAL = 2  /**< High-risk threat (e.g., port scan, SYN flood, flag scan). */
} anomaly_severity_t;

/**
 * @brief Representation of a single detected network anomaly.
 *
 * All text fields are fixed-capacity null-terminated strings; no separate
 * heap allocation is performed for descriptions or subjects.
 */
typedef struct {
    anomaly_severity_t severity;    /**< Severity level of the finding. */
    char category[64];              /**< Anomaly category (e.g., "Port Scan"). */
    char subject[128];              /**< Offending entity (IP, flow 5-tuple, or "Global"). */
    char description[256];          /**< Detailed explanation including metrics. */
} anomaly_t;

/**
 * @brief Dynamic array of detected anomalies.
 *
 * The caller allocates the container (typically on the stack) and initializes
 * it with anomaly_list_init(). Memory for items is allocated and grown
 * dynamically, and must be released with anomaly_list_free().
 */
typedef struct {
    anomaly_t *items;   /**< Heap-allocated array of anomalies. */
    size_t count;       /**< Number of valid anomalies in items. */
    size_t capacity;    /**< Total allocated capacity in items. */
} anomaly_list_t;

/**
 * @brief Initialize an anomaly list to empty state.
 *
 * Sets internal pointers to NULL and counters to zero.
 *
 * @param list Pointer to caller-allocated list.
 * @return PCAPSTAT_OK on success, or PCAPSTAT_ERR_ARGS if @p list is NULL.
 */
int anomaly_list_init(anomaly_list_t *list);

/**
 * @brief Append a copy of an anomaly to the dynamic list.
 *
 * Grows internal buffer exponentially as needed.
 *
 * @param list Initialized anomaly list.
 * @param item Anomaly to copy into the list.
 * @return PCAPSTAT_OK on success,
 *         PCAPSTAT_ERR_ARGS if arguments are NULL,
 *         PCAPSTAT_ERR_NOMEM if memory allocation fails.
 */
int anomaly_list_append(anomaly_list_t *list, const anomaly_t *item);

/**
 * @brief Free heap memory associated with an anomaly list.
 *
 * Releases @p list->items and resets counters to zero. Safe to call
 * on a zero-initialized or already freed list, or with NULL.
 *
 * @param list Pointer to list to free (may be NULL).
 */
void anomaly_list_free(anomaly_list_t *list);

/**
 * @brief Return a human-readable string for an anomaly severity.
 *
 * The returned string is static and must not be freed.
 *
 * @param severity Severity enum value.
 * @return String representation ("CRITICAL", "WARNING", "INFO", or "UNKNOWN").
 */
const char *anomaly_severity_str(anomaly_severity_t severity);

/**
 * @brief Run all deterministic anomaly detection heuristics.
 *
 * Evaluates the aggregated statistics in @p stats against @p thresholds.
 * Detected anomalies are appended to @p out and sorted in descending order
 * of severity (ANOMALY_CRITICAL -> ANOMALY_WARNING -> ANOMALY_INFO).
 * If multiple anomalies share the same severity, tie-breaking is deterministic
 * (by category, then subject).
 *
 * Rules evaluated:
 *  1. Port Scan: host targeted >= threshold unique destination ports (SYN/UDP).
 *  2. SYN Flood: host sent >= min SYN packets with SYN / SYN-ACK ratio > threshold.
 *  3. Elevated Retransmissions: retransmission rate > threshold % per flow (min 20 pkts)
 *     or globally across all flows.
 *  4. RST Spike: RST packets exceed > threshold % of TCP traffic (min 30 pkts).
 *  5. Suspicious TCP Flags: any Null Scan, Xmas Scan, SYN+FIN, or SYN+RST segment.
 *  6. UDP Burst / Flood: any 1-second window where UDP packet count exceeds
 *     multiplier * mean and absolute minimum (pkt/s).
 *  7. Malformed Packets: flagged if malformed_packets > 0.
 *
 * @param stats Validated, finalized or aggregated statistics context.
 * @param thresholds Configured detection thresholds. If NULL, default
 *                   thresholds from common.h are used.
 * @param[out] out Initialized anomaly list to receive findings.
 * @return PCAPSTAT_OK on success,
 *         PCAPSTAT_ERR_ARGS if @p stats or @p out is NULL,
 *         PCAPSTAT_ERR_NOMEM on memory allocation failure.
 */
int anomaly_detect(const stats_ctx_t *stats,
                   const anomaly_thresholds_t *thresholds,
                   anomaly_list_t *out);

#endif /* PCAPSTAT_ANOMALY_H */
