/**
 * @file stats.h
 * @brief Streaming statistics engine for parsed network packets.
 *
 * The engine retains only aggregate counters and sparse one-second buckets.
 * Parsed packets are borrowed callback data and are never stored.
 *
 * Counting invariants (every ingested packet is counted exactly once in
 * the global category counters):
 *   tcp_packets + udp_packets + other_packets + malformed_packets
 *       == total_packets
 * `other_packets` holds well-formed packets whose IP protocol is neither
 * TCP nor UDP (ICMP, GRE, ESP, IPv6 extension-header chains, ...).
 */

#ifndef PCAPSTAT_STATS_H
#define PCAPSTAT_STATS_H

#include "common.h"
#include "hashtable.h"
#include "parser.h"

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>

/** @brief Number of fixed packet-size histogram bins. */
#define STATS_PACKET_SIZE_BINS 7

/**
 * @brief Aggregate statistics for a span of consecutive seconds.
 *
 * Values are owned by the timeline array returned by stats_finalize().
 *
 * A raw bucket covers exactly one second (`span_sec == 1`). When the
 * timeline is downsampled, one bucket merges several raw buckets and
 * `span_sec` is the wall-clock time they cover, gaps included:
 * `last_merged_sec - first_merged_sec + 1`. Consumers must compute rates
 * as `packets / span_sec` (not per bucket) to get a correct chart.
 *
 * `packets` and `bytes` include malformed packets; the per-protocol
 * fields do not (see the invariants in the file header). Packets without
 * a usable timestamp are in no bucket.
 *
 * `udp_packets_max` is the largest raw one-second UDP packet count among
 * the merged buckets; it is retained for burst detection after
 * downsampling.
 */
typedef struct {
    int64_t  sec;             /**< First second covered (epoch). */
    uint64_t span_sec;        /**< Seconds covered, gaps included (>= 1). */
    uint64_t packets;
    uint64_t bytes;
    uint64_t tcp_packets;
    uint64_t tcp_bytes;
    uint64_t udp_packets;
    uint64_t udp_bytes;
    uint64_t other_packets;
    uint64_t udp_packets_max;
} ts_bucket_t;

/**
 * @brief Streaming traffic statistics context.
 *
 * Caller allocates this struct, stats_init() initializes it, and
 * stats_free() releases only its owned tables and timeline. The
 * host/port/flow hash-table pointers are reserved for future stats phases.
 *
 * `files_processed` is not touched by this module; the caller (main) must
 * increment it after each successfully processed file.
 *
 * Timestamps: a timestamp is "usable" if it is finite and its magnitude
 * is below 9.0e18 (so floor() fits in int64_t). Packets with unusable
 * timestamps are counted in all counters but are excluded from
 * first_ts/last_ts and from the time-series buckets.
 */
typedef struct {
    uint64_t files_processed;
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t tcp_packets;
    uint64_t tcp_bytes;
    uint64_t udp_packets;
    uint64_t udp_bytes;
    uint64_t other_packets;      /**< Well-formed, non-TCP/UDP packets. */
    uint64_t malformed_packets;  /**< Parser-flagged; counted in no other
                                      category (includes non-IP frames,
                                      which the parser flags as malformed). */

    double first_ts;             /**< Min usable timestamp (0 if none). */
    double last_ts;              /**< Max usable timestamp (0 if none). */
    double duration_sec;
    double avg_pps;
    double avg_bps;

    /** Packets with a usable timestamp (denominator for first/last_ts). */
    uint64_t timestamped_packets;

    uint64_t packet_size_histogram[STATS_PACKET_SIZE_BINS];

    /* TCP flag counters (non-malformed TCP packets only). */
    uint64_t syn;          /**< Pure SYN: SYN set and ACK clear. */
    uint64_t syn_ack;      /**< SYN and ACK both set. */
    uint64_t ack;          /**< ACK bit set (includes SYN+ACK). */
    uint64_t fin;
    uint64_t rst;
    uint64_t psh;
    uint64_t urg;
    uint64_t ece_cwr;      /**< ECE or CWR set. */
    uint64_t null_scan_pkts;   /**< flags == 0. */
    uint64_t xmas_scan_pkts;   /**< FIN+PSH+URG set, SYN clear. */
    uint64_t syn_fin_pkts;     /**< SYN and FIN both set. */
    uint64_t syn_rst_pkts;     /**< SYN and RST both set. */

    ht_t *ts_buckets_ht;
    ts_bucket_t *timeline;
    size_t timeline_count;

    /* Reserved for TASK-07; payload ownership remains with stats_free(). */
    ht_t *hosts_ht;
    ht_t *ports_ht;
    ht_t *flows_ht;
} stats_ctx_t;

/**
 * @brief Initialize a statistics context.
 *
 * Allocates the sparse time-series hash table. The caller owns @p ctx and
 * must later call stats_free().
 *
 * @param ctx Caller-owned context to initialize.
 * @return PCAPSTAT_OK on success, PCAPSTAT_ERR_ARGS if @p ctx is NULL, or
 *         PCAPSTAT_ERR_NOMEM on allocation failure. On failure, @p ctx is
 *         left without any owned allocations.
 */
int stats_init(stats_ctx_t *ctx);

/**
 * @brief Update all aggregate statistics with one parsed packet.
 *
 * @p pkt is borrowed and is not retained. One-second buckets are allocated
 * lazily as packets are ingested. Global counters are updated before the
 * bucket is allocated, so after PCAPSTAT_ERR_NOMEM the context is only
 * partially updated and should be discarded (the parser stops anyway).
 *
 * @param ctx Initialized, caller-owned context.
 * @param pkt Borrowed packet populated by the parser.
 * @return PCAPSTAT_OK on success, PCAPSTAT_ERR_ARGS for NULL arguments or
 *         an uninitialized context, PCAPSTAT_ERR_NOMEM if bucket
 *         allocation or hash-table growth fails.
 */
int stats_update(stats_ctx_t *ctx, const parsed_packet_t *pkt);

/**
 * @brief Packet callback adapter for parser_process_file().
 *
 * Calls stats_update() and forwards a stats error to stop parsing.
 *
 * @param pkt Borrowed packet for this callback invocation.
 * @param user_data Must point to an initialized stats_ctx_t.
 * @return PCAPSTAT_OK to continue, PCAPSTAT_ERR_ARGS for NULL arguments,
 *         or the error returned by stats_update().
 */
int stats_packet_cb(const parsed_packet_t *pkt, void *user_data);

/**
 * @brief Finalize derived metrics and export a sorted sparse timeline.
 *
 * Exported buckets are owned by @p ctx->timeline and released by
 * stats_free(). More than 120 sparse buckets are merged into exactly 120
 * groups of consecutive buckets; each output bucket carries `span_sec`
 * (see ts_bucket_t). May be called repeatedly (e.g. after further
 * updates); the previous timeline is released before rebuilding.
 *
 * Division by zero is guarded: duration_sec, avg_pps and avg_bps are 0.0
 * when fewer than two distinct usable timestamps were seen.
 *
 * @param ctx Initialized context to finalize.
 * @return PCAPSTAT_OK on success, PCAPSTAT_ERR_ARGS for NULL/uninitialized
 *         context, or PCAPSTAT_ERR_NOMEM on allocation failure (timeline
 *         is then empty).
 */
int stats_finalize(stats_ctx_t *ctx);

/**
 * @brief Release every allocation owned by a statistics context.
 *
 * Frees the sparse bucket table and exported timeline and resets @p ctx.
 *
 * @param ctx Context to release; may be NULL.
 */
void stats_free(stats_ctx_t *ctx);

#endif /* PCAPSTAT_STATS_H */