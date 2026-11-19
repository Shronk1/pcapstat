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

int stats_init(stats_ctx_t *ctx)
{
    if (ctx == NULL)
        return PCAPSTAT_ERR_ARGS;

    memset(ctx, 0, sizeof(*ctx));
    ctx->ts_buckets_ht = ht_create(16);
    if (ctx->ts_buckets_ht == NULL)
        return PCAPSTAT_ERR_NOMEM;
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

int stats_update(stats_ctx_t *ctx, const parsed_packet_t *pkt)
{
    if (ctx == NULL || pkt == NULL)
        return PCAPSTAT_ERR_ARGS;
    if (ctx->ts_buckets_ht == NULL)
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