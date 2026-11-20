/**
 * @file stats.h
 * @brief Streaming statistics engine for parsed network packets.
 *
 * The engine retains only aggregate counters, sparse one-second buckets and
 * per-host / per-port / per-flow aggregates. Parsed packets are borrowed
 * callback data and are never stored.
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
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Number of fixed packet-size histogram bins.
 *
 * Bins are half-open ranges of wire length in bytes:
 * `[0,64) [64,128) [128,256) [256,512) [512,1024) [1024,1514) [1514,inf)`,
 * i.e. the chart labels `<64, 64-127, 128-255, 256-511, 512-1023,
 * 1024-1513, >=1514`.
 */
#define STATS_PACKET_SIZE_BINS 7

/**
 * @brief Reordering window for TCP out-of-order classification, seconds.
 *
 * A payload segment that fills the recorded sequence hole less than this
 * long after the segment that opened the hole is counted as out-of-order
 * instead of as a retransmission (see flow_stats_t).
 */
#define STATS_OOO_WINDOW_SEC 0.003

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

/** @brief Bytes in a promoted destination-port bitmap (65536 bits). */
#define STATS_DST_PORT_BITMAP_BYTES 8192

/** @brief Distinct probed ports a host stores inline before promotion. */
#define STATS_HOST_INLINE_PORTS 16

/**
 * @brief Aggregate traffic attributed to one IP host.
 *
 * The object is table-owned and is reachable only through @ref stats_ctx_t.
 * Created for every source and destination address of non-malformed IP
 * packets, so receive-only hosts get an entry too.
 *
 * Ownership: a host may own a heap bitmap (`dst_ports_bitmap`), so host
 * objects are created and freed only by the stats module (stats_free()).
 * Never free() a host_stats_t or copy one and free the copy.
 *
 * Probed-port set (compact): the first @ref STATS_HOST_INLINE_PORTS
 * distinct ports are kept unsorted in `dst_ports_inline`. The next new
 * port promotes the set to a lazily allocated
 * @ref STATS_DST_PORT_BITMAP_BYTES bitmap; the inline array is then
 * unused. Hosts that never probe (e.g. receive-only hosts) allocate no
 * port storage: `dst_ports_bitmap` stays NULL.
 */
typedef struct {
    uint8_t  ip_version; /**< IP version (4 or 6). */
    uint8_t  ip[16];     /**< IPv4 in bytes 0..3 or full IPv6 address. */
    uint64_t tx_packets; /**< Packets sent by this host. */
    uint64_t tx_bytes;   /**< Wire bytes sent. */
    uint64_t rx_packets; /**< Packets received. */
    uint64_t rx_bytes;   /**< Wire bytes received. */
    uint64_t syn_sent;     /**< Pure SYN (SYN set, ACK clear) sent. */
    uint64_t syn_ack_recv; /**< SYN+ACK received. */
    uint64_t rst_sent;     /**< Packets with RST sent. */
    uint64_t rst_recv;     /**< Packets with RST received. */

    /**
     * Distinct destination ports this host probed, for port-scan
     * detection. A port is recorded (in one set shared by TCP and UDP,
     * so TCP/80 and UDP/80 count once) when the host sends
     *  - a TCP pure SYN, or
     *  - a UDP datagram that is NOT a reply, i.e. no flow in the opposite
     *    direction (dst -> src, swapped ports) had been seen before.
     * Port 0 is ignored. The reply rule keeps servers (DNS, NTP, ...),
     * which answer many ephemeral client ports, from looking like
     * scanners. NULL/FIN/XMAS TCP scans are not tracked here.
     */
    uint32_t unique_dst_ports;

    /** Probed ports while `dst_ports_bitmap == NULL`: entries
     *  `[0, unique_dst_ports)` are valid, distinct and unsorted. */
    uint16_t dst_ports_inline[STATS_HOST_INLINE_PORTS];

    /** NULL until more than @ref STATS_HOST_INLINE_PORTS distinct ports
     *  were probed; then a host-owned @ref STATS_DST_PORT_BITMAP_BYTES
     *  bitmap holding every probed port (bit p set = port p probed: byte
     *  p / 8, bit p % 8). Freed by stats_free(). */
    uint8_t *dst_ports_bitmap;
} host_stats_t;

/**
 * @brief Aggregate traffic for one IP protocol and destination port.
 */
typedef struct {
    uint8_t  proto;     /**< IP protocol number (TCP or UDP). */
    uint16_t dst_port;  /**< Destination port in host byte order. */
    uint64_t packets;
    uint64_t bytes;
} port_stats_t;

/**
 * @brief Aggregate statistics for one directional IPv4/IPv6 5-tuple.
 *
 * TCP sequence tracking (payload-bearing segments only, i.e.
 * `payload_len > 0`; all comparisons are wrap-safe `(int32_t)` differences
 * modulo 2^32). Let `end = seq + payload_len`:
 *  - First segment, or a segment without a usable timestamp, or one whose
 *    timestamp is earlier than `last_seq_ts` (e.g. merged files given out
 *    of chronological order): **rebase** - `next_seq = end`, hole
 *    cleared, `last_seq_ts` = its timestamp if usable. Not counted.
 *  - `seq >= next_seq`: **new data**. If `seq > next_seq`, the gap
 *    `[next_seq, seq)` is recorded as the hole (an unexpired hole is
 *    extended to `seq` instead, so one interval covers all open gaps and
 *    keeps its opening time). `next_seq = end`, `last_seq_ts` = now.
 *  - Lying entirely inside the hole and arriving less than
 *    @ref STATS_OOO_WINDOW_SEC after the segment that opened it:
 *    **out_of_order**. The hole shrinks from the matching edge (cleared
 *    when empty; a fill strictly in the middle leaves it unchanged).
 *  - Anything else with `seq < next_seq`: **retransmission** (a
 *    duplicate, a late fill of the hole, or a segment overlapping data
 *    already seen). If it extends past `next_seq`, `next_seq = end` and
 *    `last_seq_ts` = now.
 *
 * Limitation: SYN/FIN are not tracked, so the first data segment seen is
 * the baseline; if the first two data segments arrive swapped, the
 * earlier one has no recorded hole and counts as a retransmission.
 */
typedef struct {
    uint8_t  ip_version; /**< IP version (4 or 6). */
    uint8_t  src_ip[16]; /**< Source IP address. */
    uint8_t  dst_ip[16]; /**< Destination IP address. */
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    double   first_ts;       /**< Valid only if has_timestamp. */
    double   last_ts;        /**< Valid only if has_timestamp. */
    uint64_t packets;
    uint64_t bytes;
    uint8_t  tcp_flags_seen; /**< OR of all TCP flag bytes seen. */
    bool     has_timestamp;  /**< A usable timestamp was seen. */
    bool     has_seq;        /**< A TCP data segment was seen. */
    bool     has_hole;       /**< hole_start/hole_end/hole_ts are valid. */
    uint32_t next_seq;       /**< Highest seq + payload_len seen (after the
                                  last rebase); valid if has_seq. */
    uint32_t hole_start;     /**< First missing sequence number. */
    uint32_t hole_end;       /**< One past the last missing number. */
    double   hole_ts;        /**< Arrival time of the segment that opened
                                  the hole. */
    double   last_seq_ts;    /**< Time next_seq last advanced or was
                                  rebased; valid if has_seq. */
    uint64_t retransmissions; /**< TCP retransmissions (see above). */
    uint64_t out_of_order;    /**< Reordered TCP segments (see above). */
} flow_stats_t;

/**
 * @brief Streaming traffic statistics context.
 *
 * Caller allocates this struct, stats_init() initializes it, and
 * stats_free() releases everything it owns: the time-series, host, port
 * and flow tables (with their payload objects, including promoted host
 * port bitmaps) and the timeline.
 *
 * `files_processed` is not touched by this module; the caller (main) must
 * increment it after each successfully processed file.
 *
 * Timestamps: a timestamp is "usable" if it is finite and its magnitude
 * is below 9.0e18 (so floor() fits in int64_t). Packets with unusable
 * timestamps are counted in all counters but are excluded from
 * first_ts/last_ts and from the time-series buckets.
 *
 * Hosts, ports and flows are filled only for non-malformed packets with
 * `ip_version != 0`; ports and flows only for TCP/UDP.
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
    double duration_sec;         /**< last_ts - first_ts, seconds. */
    double avg_pps;              /**< total_packets / duration_sec,
                                      packets per second. */
    double avg_bps;              /**< 8 * total_bytes / duration_sec:
                                      average wire bit rate in BITS per
                                      second (not bytes). */

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

    /* TCP sequence analysis, over ALL flows (see flow_stats_t). */
    uint64_t tcp_retransmissions; /**< Sum of flow_stats_t::retransmissions. */
    uint64_t tcp_out_of_order;    /**< Sum of flow_stats_t::out_of_order. */

    ht_t *ts_buckets_ht;
    ts_bucket_t *timeline;
    size_t timeline_count;

    ht_t *hosts_ht;   /**< key {ip_version, ip[16]} -> host_stats_t. */
    ht_t *ports_ht;   /**< key {proto, dst_port}    -> port_stats_t. */
    ht_t *flows_ht;   /**< directional 5-tuple      -> flow_stats_t. */
} stats_ctx_t;

/**
 * @brief Map a protocol and port to a common service name.
 *
 * The returned string is static and must not be freed or modified.
 * All current names are protocol-independent (well-known IANA ports).
 *
 * @param proto IP protocol number (currently unused; kept so names can
 *        become protocol-specific without an API change).
 * @param port Destination port in host byte order.
 * @return ASCII service name, or "Unknown".
 */
const char *stats_port_service_name(uint8_t proto, uint16_t port);

/**
 * @brief Export borrowed pointers to the highest-volume hosts.
 *
 * Ordered by total host bytes descending, then packets, then address
 * (deterministic). Returned pointers are borrowed from @p ctx and remain
 * valid until stats_free(). The caller owns @p out only.
 *
 * @param ctx Initialized statistics context.
 * @param out Caller-owned array of at least @p max_n pointers.
 * @param max_n Number of slots in @p out.
 * @return Number of pointers written (at most @p max_n). 0 means no data,
 *         invalid arguments, or an internal allocation failure.
 */
size_t stats_top_hosts(const stats_ctx_t *ctx,
                       const host_stats_t **out, size_t max_n);

/**
 * @brief Export borrowed pointers to the busiest destination ports.
 *
 * Ordered by packets descending, then bytes, then (proto, port). Pointers
 * are borrowed and valid until stats_free(). See stats_top_hosts() for
 * the return value.
 */
size_t stats_top_ports(const stats_ctx_t *ctx,
                       const port_stats_t **out, size_t max_n);

/**
 * @brief Export borrowed pointers to the busiest directional flows.
 *
 * Ordered by packets descending, then bytes, then 5-tuple. Pointers are
 * borrowed and valid until stats_free(). See stats_top_hosts() for the
 * return value.
 */
size_t stats_top_flows(const stats_ctx_t *ctx,
                       const flow_stats_t **out, size_t max_n);

/**
 * @brief Initialize a statistics context.
 *
 * Allocates the time-series, host, port and flow hash tables. The caller
 * owns @p ctx and must later call stats_free().
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
 * @p pkt is borrowed and is not retained. Buckets, hosts, ports and flows
 * are allocated lazily. Global counters are updated first, so after
 * PCAPSTAT_ERR_NOMEM the context is only partially updated (e.g. source
 * host counted, destination not) and should be discarded; the parser
 * stops anyway.
 *
 * @param ctx Initialized, caller-owned context.
 * @param pkt Borrowed packet populated by the parser.
 * @return PCAPSTAT_OK on success, PCAPSTAT_ERR_ARGS for NULL arguments or
 *         an uninitialized context, PCAPSTAT_ERR_NOMEM if an allocation
 *         (including a host port-bitmap promotion) or hash-table growth
 *         fails.
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
 * Derived rates: `avg_pps = total_packets / duration_sec` and
 * `avg_bps = 8 * total_bytes / duration_sec` (bits per second).
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
 * Frees all tables and their payload objects (host objects through the
 * module's host destructor, which also frees a promoted port bitmap) and
 * the exported timeline, then resets @p ctx. Pointers obtained from
 * stats_top_*() become invalid.
 *
 * @param ctx Context to release; may be NULL.
 */
void stats_free(stats_ctx_t *ctx);

#endif /* PCAPSTAT_STATS_H */
