#include "stats.h"

#include <math.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>

#define STATS_MAX_TIMELINE_POINTS 120

/* ECE/CWR are not defined by every libc's <netinet/tcp.h>. */
#define STATS_TCP_ECE 0x40
#define STATS_TCP_CWR 0x80

/* floor() of a usable timestamp must fit in int64_t (max ~9.22e18). */
#define STATS_TS_LIMIT 9.0e18

static bool ts_is_usable(double ts)
{
    return isfinite(ts) && fabs(ts) < STATS_TS_LIMIT;
}

static int histogram_bin(uint32_t size)
{
    if (size <= 64)
        return 0;
    if (size <= 128)
        return 1;
    if (size <= 256)
        return 2;
    if (size <= 512)
        return 3;
    if (size <= 1024)
        return 4;
    if (size <= 1500)
        return 5;
    return 6;
}

static void free_ts_bucket(void *value)
{
    free(value);
}

const char *stats_port_service_name(uint8_t proto, uint16_t port)
{
    switch (port) {
    case 20: return "FTP";
    case 21: return "FTP";
    case 22: return "SSH";
    case 25: return "SMTP";
    case 53: return "DNS";
    case 67: return "DHCP";
    case 68: return "DHCP";
    case 80: return "HTTP";
    case 110: return "POP3";
    case 123: return "NTP";
    case 137: return "NetBIOS";
    case 139: return "NetBIOS";
    case 143: return "IMAP";
    case 194: return "IRC";
    case 443: return "HTTPS";
    case 445: return "SMB";
    case 587: return "SMTP-Submission";
    case 853: return "DNS-TLS";
    case 993: return "IMAPS";
    case 995: return "POP3S";
    case 3306: return "MySQL";
    case 5432: return "PostgreSQL";
    case 8080: return "HTTP-Alt";
    case 8081: return "HTTP-Alt";
    case 9999:
        /* Demo/test traffic only; meaningful for UDP. */
        return proto == IPPROTO_UDP ? "UDP-Data" : "Unknown";
    default: return "Unknown";
    }
}

/* ---- Top-N comparators ------------------------------------------------ */

/* Descending order for counters (larger value sorts first). */
static int cmp_desc_u64(uint64_t a, uint64_t b)
{
    if (a < b)
        return 1;
    if (a > b)
        return -1;
    return 0;
}

/* Ascending order for tie-breaks on keys. */
static int cmp_asc_u64(uint64_t a, uint64_t b)
{
    if (a < b)
        return -1;
    if (a > b)
        return 1;
    return 0;
}

static int compare_host_volume(const void *left, const void *right)
{
    const host_stats_t *a = *(const host_stats_t *const *)left;
    const host_stats_t *b = *(const host_stats_t *const *)right;
    int c;

    c = cmp_desc_u64(a->tx_bytes + a->rx_bytes,
                     b->tx_bytes + b->rx_bytes);
    if (c != 0)
        return c;
    c = cmp_desc_u64(a->tx_packets + a->rx_packets,
                     b->tx_packets + b->rx_packets);
    if (c != 0)
        return c;

    /* Deterministic tie-break by address. */
    c = cmp_asc_u64(a->ip_version, b->ip_version);
    if (c != 0)
        return c;
    return memcmp(a->ip, b->ip, sizeof(a->ip));
}

static int compare_port_volume(const void *left, const void *right)
{
    const port_stats_t *a = *(const port_stats_t *const *)left;
    const port_stats_t *b = *(const port_stats_t *const *)right;
    int c;

    c = cmp_desc_u64(a->packets, b->packets);
    if (c != 0)
        return c;
    c = cmp_desc_u64(a->bytes, b->bytes);
    if (c != 0)
        return c;

    /* Deterministic tie-break by key. */
    c = cmp_asc_u64(a->proto, b->proto);
    if (c != 0)
        return c;
    return cmp_asc_u64(a->dst_port, b->dst_port);
}

static int compare_flow_volume(const void *left, const void *right)
{
    const flow_stats_t *a = *(const flow_stats_t *const *)left;
    const flow_stats_t *b = *(const flow_stats_t *const *)right;
    int c;

    c = cmp_desc_u64(a->packets, b->packets);
    if (c != 0)
        return c;
    c = cmp_desc_u64(a->bytes, b->bytes);
    if (c != 0)
        return c;

    /* Deterministic tie-break by 5-tuple. */
    c = cmp_asc_u64(a->ip_version, b->ip_version);
    if (c != 0)
        return c;
    c = memcmp(a->src_ip, b->src_ip, sizeof(a->src_ip));
    if (c != 0)
        return c;
    c = memcmp(a->dst_ip, b->dst_ip, sizeof(a->dst_ip));
    if (c != 0)
        return c;
    c = cmp_asc_u64(a->src_port, b->src_port);
    if (c != 0)
        return c;
    c = cmp_asc_u64(a->dst_port, b->dst_port);
    if (c != 0)
        return c;
    return cmp_asc_u64(a->proto, b->proto);
}

size_t stats_top_hosts(const stats_ctx_t *ctx,
                       const host_stats_t **out, size_t max_n)
{
    if (ctx == NULL || ctx->hosts_ht == NULL || (out == NULL && max_n != 0))
        return 0;
    if (max_n == 0)
        return 0;

    size_t count = ht_count(ctx->hosts_ht);
    if (count == 0)
        return 0;
    const host_stats_t **values =
        (const host_stats_t **)malloc(count * sizeof(*values));
    if (values == NULL)
        return 0;

    ht_iter_t it = ht_iter_begin(ctx->hosts_ht);
    const void *key;
    size_t key_len;
    void *value;
    size_t index = 0;
    while (ht_iter_next(&it, &key, &key_len, &value)) {
        (void)key;
        (void)key_len;
        if (value != NULL)
            values[index++] = (const host_stats_t *)value;
    }
    count = index;
    qsort(values, count, sizeof(*values), compare_host_volume);
    if (count > max_n)
        count = max_n;
    memcpy(out, values, count * sizeof(*out));
    free(values);
    return count;
}

size_t stats_top_ports(const stats_ctx_t *ctx,
                       const port_stats_t **out, size_t max_n)
{
    if (ctx == NULL || ctx->ports_ht == NULL || (out == NULL && max_n != 0))
        return 0;
    if (max_n == 0)
        return 0;

    size_t count = ht_count(ctx->ports_ht);
    if (count == 0)
        return 0;
    const port_stats_t **values =
        (const port_stats_t **)malloc(count * sizeof(*values));
    if (values == NULL)
        return 0;

    ht_iter_t it = ht_iter_begin(ctx->ports_ht);
    const void *key;
    size_t key_len;
    void *value;
    size_t index = 0;
    while (ht_iter_next(&it, &key, &key_len, &value)) {
        (void)key;
        (void)key_len;
        if (value != NULL)
            values[index++] = (const port_stats_t *)value;
    }
    count = index;
    qsort(values, count, sizeof(*values), compare_port_volume);
    if (count > max_n)
        count = max_n;
    memcpy(out, values, count * sizeof(*out));
    free(values);
    return count;
}

size_t stats_top_flows(const stats_ctx_t *ctx,
                       const flow_stats_t **out, size_t max_n)
{
    if (ctx == NULL || ctx->flows_ht == NULL || (out == NULL && max_n != 0))
        return 0;
    if (max_n == 0)
        return 0;

    size_t count = ht_count(ctx->flows_ht);
    if (count == 0)
        return 0;
    const flow_stats_t **values =
        (const flow_stats_t **)malloc(count * sizeof(*values));
    if (values == NULL)
        return 0;

    ht_iter_t it = ht_iter_begin(ctx->flows_ht);
    const void *key;
    size_t key_len;
    void *value;
    size_t index = 0;
    while (ht_iter_next(&it, &key, &key_len, &value)) {
        (void)key;
        (void)key_len;
        if (value != NULL)
            values[index++] = (const flow_stats_t *)value;
    }
    count = index;
    qsort(values, count, sizeof(*values), compare_flow_volume);
    if (count > max_n)
        count = max_n;
    memcpy(out, values, count * sizeof(*out));
    free(values);
    return count;
}

/* ---- Lifecycle -------------------------------------------------------- */

int stats_init(stats_ctx_t *ctx)
{
    if (ctx == NULL)
        return PCAPSTAT_ERR_ARGS;

    memset(ctx, 0, sizeof(*ctx));
    ctx->ts_buckets_ht = ht_create(16);
    ctx->hosts_ht = ht_create(16);
    ctx->ports_ht = ht_create(16);
    ctx->flows_ht = ht_create(16);
    if (ctx->ts_buckets_ht == NULL || ctx->hosts_ht == NULL ||
        ctx->ports_ht == NULL || ctx->flows_ht == NULL) {
        ht_destroy(ctx->ts_buckets_ht, free_ts_bucket);
        ht_destroy(ctx->hosts_ht, free);
        ht_destroy(ctx->ports_ht, free);
        ht_destroy(ctx->flows_ht, free);
        memset(ctx, 0, sizeof(*ctx));
        return PCAPSTAT_ERR_NOMEM;
    }
    return PCAPSTAT_OK;
}

static void update_tcp_flags(stats_ctx_t *ctx, uint8_t flags)
{
    const uint8_t syn = (uint8_t)TH_SYN;
    const uint8_t ack = (uint8_t)TH_ACK;
    const uint8_t fin = (uint8_t)TH_FIN;
    const uint8_t rst = (uint8_t)TH_RST;
    const uint8_t psh = (uint8_t)TH_PUSH;
    const uint8_t urg = (uint8_t)TH_URG;

    /* Pure SYN only; SYN+ACK is counted in syn_ack so that the
     * syn / syn_ack ratio is meaningful for SYN-flood detection. */
    if ((flags & syn) != 0 && (flags & ack) == 0)
        ctx->syn++;
    if ((flags & (syn | ack)) == (syn | ack))
        ctx->syn_ack++;
    if ((flags & ack) != 0)
        ctx->ack++;
    if ((flags & fin) != 0)
        ctx->fin++;
    if ((flags & rst) != 0)
        ctx->rst++;
    if ((flags & psh) != 0)
        ctx->psh++;
    if ((flags & urg) != 0)
        ctx->urg++;
    if ((flags & (STATS_TCP_ECE | STATS_TCP_CWR)) != 0)
        ctx->ece_cwr++;
    if (flags == 0)
        ctx->null_scan_pkts++;
    if ((flags & fin) != 0 && (flags & psh) != 0 &&
        (flags & urg) != 0 && (flags & syn) == 0)
        ctx->xmas_scan_pkts++;
    if ((flags & (syn | fin)) == (syn | fin))
        ctx->syn_fin_pkts++;
    if ((flags & (syn | rst)) == (syn | rst))
        ctx->syn_rst_pkts++;
}

/* ---- Hash keys (memset before filling: padding is hashed) ------------- */

typedef struct {
    uint8_t ip_version;
    uint8_t ip[16];
} host_key_t;

typedef struct {
    uint8_t proto;
    uint16_t dst_port;
} port_key_t;

typedef struct {
    uint8_t ip_version;
    uint8_t src_ip[16];
    uint8_t dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
} flow_key_t;

/* Record @p port in the host's bitmap; ports are counted once. */
static void mark_dst_port(host_stats_t *host, uint16_t port)
{
    if (port == 0)
        return;

    uint32_t byte_index = (uint32_t)port / 8;
    uint8_t bit = (uint8_t)(1U << (port % 8));
    if ((host->dst_ports_bitmap[byte_index] & bit) == 0) {
        host->dst_ports_bitmap[byte_index] |= bit;
        host->unique_dst_ports++;
    }
}

/*
 * A UDP datagram is a reply if the opposite-direction flow (dst -> src,
 * ports swapped) was already seen. UDP has no handshake, so this is the
 * only way to tell a probe from a server answering a client's ephemeral
 * port. Must run before update_flow() creates this packet's own flow.
 */
static bool udp_is_reply(stats_ctx_t *ctx, const parsed_packet_t *pkt)
{
    flow_key_t rev;

    memset(&rev, 0, sizeof(rev));
    rev.ip_version = pkt->ip_version;
    memcpy(rev.src_ip, pkt->dst_ip, 16);
    memcpy(rev.dst_ip, pkt->src_ip, 16);
    rev.src_port = pkt->dst_port;
    rev.dst_port = pkt->src_port;
    rev.proto = IPPROTO_UDP;
    return ht_get(ctx->flows_ht, &rev, sizeof(rev)) != NULL;
}

static int update_host(stats_ctx_t *ctx, const parsed_packet_t *pkt)
{
    host_key_t src_key;
    host_key_t dst_key;
    host_stats_t *src;
    host_stats_t *dst;

    if (pkt->ip_version == 0)
        return PCAPSTAT_OK;

    memset(&src_key, 0, sizeof(src_key));
    memset(&dst_key, 0, sizeof(dst_key));
    src_key.ip_version = pkt->ip_version;
    dst_key.ip_version = pkt->ip_version;
    memcpy(src_key.ip, pkt->src_ip, 16);
    memcpy(dst_key.ip, pkt->dst_ip, 16);

    src = (host_stats_t *)ht_get(ctx->hosts_ht, &src_key, sizeof(src_key));
    if (src == NULL) {
        src = (host_stats_t *)calloc(1, sizeof(*src));
        if (src == NULL)
            return PCAPSTAT_ERR_NOMEM;
        src->ip_version = pkt->ip_version;
        memcpy(src->ip, pkt->src_ip, 16);
        if (ht_put(ctx->hosts_ht, &src_key, sizeof(src_key), src) !=
            PCAPSTAT_OK) {
            free(src);
            return PCAPSTAT_ERR_NOMEM;
        }
    }
    src->tx_packets++;
    src->tx_bytes += pkt->wire_len;

    dst = (host_stats_t *)ht_get(ctx->hosts_ht, &dst_key, sizeof(dst_key));
    if (dst == NULL) {
        dst = (host_stats_t *)calloc(1, sizeof(*dst));
        if (dst == NULL)
            return PCAPSTAT_ERR_NOMEM;
        dst->ip_version = pkt->ip_version;
        memcpy(dst->ip, pkt->dst_ip, 16);
        if (ht_put(ctx->hosts_ht, &dst_key, sizeof(dst_key), dst) !=
            PCAPSTAT_OK) {
            free(dst);
            return PCAPSTAT_ERR_NOMEM;
        }
    }
    dst->rx_packets++;
    dst->rx_bytes += pkt->wire_len;

    if (pkt->proto == IPPROTO_TCP) {
        const uint8_t syn = (uint8_t)TH_SYN;
        const uint8_t ack = (uint8_t)TH_ACK;
        const uint8_t rst = (uint8_t)TH_RST;

        if ((pkt->tcp_flags & syn) != 0 && (pkt->tcp_flags & ack) == 0) {
            src->syn_sent++;
            mark_dst_port(src, pkt->dst_port);
        }
        if ((pkt->tcp_flags & (syn | ack)) == (syn | ack))
            dst->syn_ack_recv++;
        if ((pkt->tcp_flags & rst) != 0) {
            src->rst_sent++;
            dst->rst_recv++;
        }
    } else if (pkt->proto == IPPROTO_UDP) {
        if (!udp_is_reply(ctx, pkt))
            mark_dst_port(src, pkt->dst_port);
    }
    return PCAPSTAT_OK;
}

static int update_port(stats_ctx_t *ctx, const parsed_packet_t *pkt)
{
    port_key_t key;
    port_stats_t *port;

    if (pkt->proto != IPPROTO_TCP && pkt->proto != IPPROTO_UDP)
        return PCAPSTAT_OK;

    memset(&key, 0, sizeof(key));
    key.proto = pkt->proto;
    key.dst_port = pkt->dst_port;
    port = (port_stats_t *)ht_get(ctx->ports_ht, &key, sizeof(key));
    if (port == NULL) {
        port = (port_stats_t *)calloc(1, sizeof(*port));
        if (port == NULL)
            return PCAPSTAT_ERR_NOMEM;
        port->proto = pkt->proto;
        port->dst_port = pkt->dst_port;
        if (ht_put(ctx->ports_ht, &key, sizeof(key), port) != PCAPSTAT_OK) {
            free(port);
            return PCAPSTAT_ERR_NOMEM;
        }
    }
    port->packets++;
    port->bytes += pkt->wire_len;
    return PCAPSTAT_OK;
}

static int update_flow(stats_ctx_t *ctx, const parsed_packet_t *pkt)
{
    flow_key_t key;
    flow_stats_t *flow;

    if (pkt->proto != IPPROTO_TCP && pkt->proto != IPPROTO_UDP)
        return PCAPSTAT_OK;

    memset(&key, 0, sizeof(key));
    key.ip_version = pkt->ip_version;
    memcpy(key.src_ip, pkt->src_ip, 16);
    memcpy(key.dst_ip, pkt->dst_ip, 16);
    key.src_port = pkt->src_port;
    key.dst_port = pkt->dst_port;
    key.proto = pkt->proto;

    flow = (flow_stats_t *)ht_get(ctx->flows_ht, &key, sizeof(key));
    if (flow == NULL) {
        flow = (flow_stats_t *)calloc(1, sizeof(*flow));
        if (flow == NULL)
            return PCAPSTAT_ERR_NOMEM;
        flow->ip_version = pkt->ip_version;
        memcpy(flow->src_ip, pkt->src_ip, 16);
        memcpy(flow->dst_ip, pkt->dst_ip, 16);
        flow->src_port = pkt->src_port;
        flow->dst_port = pkt->dst_port;
        flow->proto = pkt->proto;
        if (ht_put(ctx->flows_ht, &key, sizeof(key), flow) != PCAPSTAT_OK) {
            free(flow);
            return PCAPSTAT_ERR_NOMEM;
        }
        if (ts_is_usable(pkt->timestamp)) {
            flow->first_ts = pkt->timestamp;
            flow->last_ts = pkt->timestamp;
            flow->has_timestamp = true;
        }
    } else if (ts_is_usable(pkt->timestamp)) {
        if (!flow->has_timestamp) {
            flow->first_ts = pkt->timestamp;
            flow->last_ts = pkt->timestamp;
            flow->has_timestamp = true;
        } else {
            if (pkt->timestamp < flow->first_ts)
                flow->first_ts = pkt->timestamp;
            if (pkt->timestamp > flow->last_ts)
                flow->last_ts = pkt->timestamp;
        }
    }

    flow->packets++;
    flow->bytes += pkt->wire_len;
    if (pkt->proto == IPPROTO_TCP) {
        flow->tcp_flags_seen |= pkt->tcp_flags;
        if (pkt->payload_len > 0) {
            /* Wrap-safe modular comparison: seq <= max_seq. */
            if (flow->has_seq &&
                ts_is_usable(pkt->timestamp) &&
                pkt->timestamp >= flow->last_seq_ts &&
                (int32_t)(pkt->tcp_seq - flow->max_seq) <= 0) {
                flow->retransmissions++;
            } else {
                flow->max_seq = pkt->tcp_seq;
                flow->last_seq_ts =
                    ts_is_usable(pkt->timestamp) ? pkt->timestamp : 0.0;
            }
            flow->has_seq = true;
        }
    }
    return PCAPSTAT_OK;
}

int stats_update(stats_ctx_t *ctx, const parsed_packet_t *pkt)
{
    if (ctx == NULL || pkt == NULL)
        return PCAPSTAT_ERR_ARGS;
    if (ctx->ts_buckets_ht == NULL || ctx->hosts_ht == NULL ||
        ctx->ports_ht == NULL || ctx->flows_ht == NULL)
        return PCAPSTAT_ERR_ARGS;

    const bool ts_ok = ts_is_usable(pkt->timestamp);

    ctx->total_packets++;
    ctx->total_bytes += pkt->wire_len;
    ctx->packet_size_histogram[histogram_bin(pkt->wire_len)]++;

    /* Track min/max only over packets with a usable timestamp; using
     * total_packets here would break when the first packet has none. */
    if (ts_ok) {
        if (ctx->timestamped_packets == 0 ||
            pkt->timestamp < ctx->first_ts)
            ctx->first_ts = pkt->timestamp;
        if (ctx->timestamped_packets == 0 ||
            pkt->timestamp > ctx->last_ts)
            ctx->last_ts = pkt->timestamp;
        ctx->timestamped_packets++;
    }

    /* Exactly one category per packet:
     * malformed | tcp | udp | other (see invariants in stats.h). */
    if (pkt->is_malformed) {
        ctx->malformed_packets++;
    } else if (pkt->proto == IPPROTO_TCP) {
        ctx->tcp_packets++;
        ctx->tcp_bytes += pkt->wire_len;
        update_tcp_flags(ctx, pkt->tcp_flags);
    } else if (pkt->proto == IPPROTO_UDP) {
        ctx->udp_packets++;
        ctx->udp_bytes += pkt->wire_len;
    } else {
        ctx->other_packets++;
    }

    /* Hosts/ports/flows need a decoded L3 header. The parser always sets
     * ip_version for non-malformed packets; the check keeps hand-built
     * packets (tests) from collapsing into one all-zero flow. */
    if (!pkt->is_malformed && pkt->ip_version != 0) {
        int rc = update_host(ctx, pkt);
        if (rc != PCAPSTAT_OK)
            return rc;
        rc = update_port(ctx, pkt);
        if (rc != PCAPSTAT_OK)
            return rc;
        rc = update_flow(ctx, pkt);
        if (rc != PCAPSTAT_OK)
            return rc;
    }

    if (!ts_ok)
        return PCAPSTAT_OK;

    int64_t sec = (int64_t)floor(pkt->timestamp);
    ts_bucket_t *bucket =
        (ts_bucket_t *)ht_get(ctx->ts_buckets_ht, &sec, sizeof(sec));
    if (bucket == NULL) {
        bucket = (ts_bucket_t *)calloc(1, sizeof(*bucket));
        if (bucket == NULL)
            return PCAPSTAT_ERR_NOMEM;
        bucket->sec = sec;
        bucket->span_sec = 1;
        if (ht_put(ctx->ts_buckets_ht, &sec, sizeof(sec), bucket) !=
            PCAPSTAT_OK) {
            free(bucket);
            return PCAPSTAT_ERR_NOMEM;
        }
    }

    bucket->packets++;
    bucket->bytes += pkt->wire_len;
    if (pkt->is_malformed) {
        /* Counted in packets/bytes only, like the global counters. */
    } else if (pkt->proto == IPPROTO_TCP) {
        bucket->tcp_packets++;
        bucket->tcp_bytes += pkt->wire_len;
    } else if (pkt->proto == IPPROTO_UDP) {
        bucket->udp_packets++;
        bucket->udp_bytes += pkt->wire_len;
        if (bucket->udp_packets > bucket->udp_packets_max)
            bucket->udp_packets_max = bucket->udp_packets;
    } else {
        bucket->other_packets++;
    }

    return PCAPSTAT_OK;
}

int stats_packet_cb(const parsed_packet_t *pkt, void *user_data)
{
    if (pkt == NULL || user_data == NULL)
        return PCAPSTAT_ERR_ARGS;
    return stats_update((stats_ctx_t *)user_data, pkt);
}

static int compare_ts_bucket(const void *left, const void *right)
{
    const ts_bucket_t *a = (const ts_bucket_t *)left;
    const ts_bucket_t *b = (const ts_bucket_t *)right;
    if (a->sec < b->sec)
        return -1;
    if (a->sec > b->sec)
        return 1;
    return 0;
}

int stats_finalize(stats_ctx_t *ctx)
{
    if (ctx == NULL)
        return PCAPSTAT_ERR_ARGS;
    if (ctx->ts_buckets_ht == NULL)
        return PCAPSTAT_ERR_ARGS;

    free(ctx->timeline);
    ctx->timeline = NULL;
    ctx->timeline_count = 0;

    ctx->duration_sec = 0.0;
    ctx->avg_pps = 0.0;
    ctx->avg_bps = 0.0;

    size_t raw_count = ht_count(ctx->ts_buckets_ht);
    ts_bucket_t *raw = NULL;
    if (raw_count > 0) {
        raw = (ts_bucket_t *)malloc(raw_count * sizeof(*raw));
        if (raw == NULL)
            return PCAPSTAT_ERR_NOMEM;

        ht_iter_t it = ht_iter_begin(ctx->ts_buckets_ht);
        const void *key;
        size_t key_len;
        void *value;
        size_t index = 0;
        while (ht_iter_next(&it, &key, &key_len, &value)) {
            (void)key;
            (void)key_len;
            if (value != NULL)
                raw[index++] = *(const ts_bucket_t *)value;
        }
        raw_count = index;
        qsort(raw, raw_count, sizeof(*raw), compare_ts_bucket);
    }

    size_t out_count = raw_count;
    if (out_count > STATS_MAX_TIMELINE_POINTS)
        out_count = STATS_MAX_TIMELINE_POINTS;

    if (out_count > 0) {
        ctx->timeline =
            (ts_bucket_t *)calloc(out_count, sizeof(*ctx->timeline));
        if (ctx->timeline == NULL) {
            free(raw);
            return PCAPSTAT_ERR_NOMEM;
        }

        if (raw_count <= STATS_MAX_TIMELINE_POINTS) {
            memcpy(ctx->timeline, raw,
                   raw_count * sizeof(*ctx->timeline));
        } else {
            /* Merge consecutive buckets into out_count groups of
             * (nearly) equal bucket count. Group sizes differ by at
             * most one, so consumers must use span_sec, not the bucket
             * count, to turn sums into rates. */
            for (size_t i = 0; i < out_count; ++i) {
                size_t start = i * raw_count / out_count;
                size_t end = (i + 1) * raw_count / out_count;
                if (end <= start)
                    end = start + 1;
                if (end > raw_count)
                    end = raw_count;

                ts_bucket_t *out = &ctx->timeline[i];
                out->sec = raw[start].sec;
                /* Unsigned subtraction: the true difference may exceed
                 * INT64_MAX for extreme (but usable) timestamps. */
                out->span_sec = (uint64_t)raw[end - 1].sec -
                                (uint64_t)raw[start].sec + 1;
                for (size_t j = start; j < end; ++j) {
                    out->packets += raw[j].packets;
                    out->bytes += raw[j].bytes;
                    out->tcp_packets += raw[j].tcp_packets;
                    out->tcp_bytes += raw[j].tcp_bytes;
                    out->udp_packets += raw[j].udp_packets;
                    out->udp_bytes += raw[j].udp_bytes;
                    out->other_packets += raw[j].other_packets;
                    if (raw[j].udp_packets_max > out->udp_packets_max)
                        out->udp_packets_max = raw[j].udp_packets_max;
                }
            }
        }
        ctx->timeline_count = out_count;
    }

    free(raw);

    if (ctx->timestamped_packets > 0 && isfinite(ctx->first_ts) &&
        isfinite(ctx->last_ts) && ctx->last_ts >= ctx->first_ts) {
        ctx->duration_sec = ctx->last_ts - ctx->first_ts;
        if (ctx->duration_sec > 0.0) {
            ctx->avg_pps =
                (double)ctx->total_packets / ctx->duration_sec;
            ctx->avg_bps =
                (double)ctx->total_bytes / ctx->duration_sec;
        }
    }

    return PCAPSTAT_OK;
}

void stats_free(stats_ctx_t *ctx)
{
    if (ctx == NULL)
        return;

    ht_destroy(ctx->ts_buckets_ht, free_ts_bucket);
    ht_destroy(ctx->hosts_ht, free);
    ht_destroy(ctx->ports_ht, free);
    ht_destroy(ctx->flows_ht, free);
    free(ctx->timeline);
    memset(ctx, 0, sizeof(*ctx));
}
