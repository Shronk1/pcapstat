#include "stats.h"

#include <math.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Unlike assert(), never compiled out by -DNDEBUG (side effects safe). */
#define CHECK(c)                                                          \
    do {                                                                  \
        if (!(c)) {                                                       \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__,        \
                    __LINE__, #c);                                        \
            abort();                                                      \
        }                                                                 \
    } while (0)

#define TCP_ECE 0x40
#define TCP_CWR 0x80

static parsed_packet_t make_packet(double timestamp, uint32_t wire_len,
                                   uint8_t proto)
{
    parsed_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.timestamp = timestamp;
    pkt.wire_len = wire_len;
    pkt.cap_len = wire_len;
    pkt.proto = proto;
    return pkt;
}

static void feed(stats_ctx_t *ctx, double ts, uint32_t len, uint8_t proto,
                 uint8_t flags)
{
    parsed_packet_t p = make_packet(ts, len, proto);
    p.tcp_flags = flags;
    CHECK(stats_update(ctx, &p) == PCAPSTAT_OK);
}

static void test_basic_stats(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    feed(&ctx, 100.9, 60, IPPROTO_TCP, TH_SYN);
    feed(&ctx, 101.2, 1500, IPPROTO_UDP, 0);
    feed(&ctx, 99.8, 2000, IPPROTO_TCP, TH_SYN | TH_RST);

    CHECK(stats_finalize(&ctx) == PCAPSTAT_OK);
    CHECK(ctx.total_packets == 3);
    CHECK(ctx.total_bytes == 3560);
    CHECK(ctx.tcp_packets == 2);
    CHECK(ctx.tcp_bytes == 2060);
    CHECK(ctx.udp_packets == 1);
    CHECK(ctx.syn == 2);
    CHECK(ctx.syn_rst_pkts == 1);
    CHECK(ctx.packet_size_histogram[0] == 1);
    CHECK(ctx.packet_size_histogram[5] == 1);
    CHECK(ctx.packet_size_histogram[6] == 1);
    CHECK(ctx.first_ts == 99.8);
    CHECK(ctx.last_ts == 101.2);
    CHECK(ctx.duration_sec > 0.0);
    CHECK(ctx.timeline_count == 3);
    CHECK(ctx.timeline[0].sec == 99);
    CHECK(ctx.timeline[1].sec == 100);
    CHECK(ctx.timeline[2].sec == 101);

    stats_free(&ctx);
    CHECK(ctx.ts_buckets_ht == NULL);
    CHECK(ctx.timeline == NULL);
}

static void test_downsampling_and_zero_duration(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);
    for (int i = 0; i < 250; ++i)
        feed(&ctx, (double)i, 70, IPPROTO_UDP, 0);
    CHECK(stats_finalize(&ctx) == PCAPSTAT_OK);
    CHECK(ctx.timeline_count == 120);
    CHECK(ctx.duration_sec == 249.0);
    CHECK(ctx.avg_pps > 0.0);
    CHECK(ctx.udp_packets == 250);
    stats_free(&ctx);

    CHECK(stats_init(&ctx) == PCAPSTAT_OK);
    feed(&ctx, 42.25, 64, IPPROTO_TCP, TH_SYN);
    CHECK(stats_finalize(&ctx) == PCAPSTAT_OK);
    CHECK(ctx.duration_sec == 0.0);
    CHECK(ctx.avg_pps == 0.0);
    CHECK(ctx.avg_bps == 0.0);
    stats_free(&ctx);
}

static void test_null_args(void)
{
    stats_ctx_t ctx;
    parsed_packet_t p = make_packet(1.0, 64, IPPROTO_UDP);

    CHECK(stats_init(NULL) == PCAPSTAT_ERR_ARGS);
    CHECK(stats_finalize(NULL) == PCAPSTAT_ERR_ARGS);
    CHECK(stats_update(NULL, &p) == PCAPSTAT_ERR_ARGS);
    stats_free(NULL); /* must not crash */

    CHECK(stats_init(&ctx) == PCAPSTAT_OK);
    CHECK(stats_update(&ctx, NULL) == PCAPSTAT_ERR_ARGS);
    CHECK(stats_packet_cb(NULL, &ctx) == PCAPSTAT_ERR_ARGS);
    CHECK(stats_packet_cb(&p, NULL) == PCAPSTAT_ERR_ARGS);
    CHECK(stats_packet_cb(&p, &ctx) == PCAPSTAT_OK);
    CHECK(ctx.total_packets == 1);
    stats_free(&ctx);
}

static void test_histogram_boundaries(void)
{
    static const struct { uint32_t size; int bin; } cases[] = {
        {0, 0},    {64, 0},   {65, 1},   {128, 1},  {129, 2},
        {256, 2},  {257, 3},  {512, 3},  {513, 4},  {1024, 4},
        {1025, 5}, {1500, 5}, {1501, 6}, {65535, 6},
    };
    uint64_t expect[STATS_PACKET_SIZE_BINS] = {0};
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        feed(&ctx, 1.0, cases[i].size, IPPROTO_UDP, 0);
        expect[cases[i].bin]++;
    }
    for (int b = 0; b < STATS_PACKET_SIZE_BINS; ++b)
        CHECK(ctx.packet_size_histogram[b] == expect[b]);
    stats_free(&ctx);
}

static void test_tcp_flag_counters(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    feed(&ctx, 1.0, 60, IPPROTO_TCP, TH_ACK);
    feed(&ctx, 1.0, 60, IPPROTO_TCP, TH_SYN | TH_ACK);
    feed(&ctx, 1.0, 60, IPPROTO_TCP, TH_FIN | TH_ACK);
    feed(&ctx, 1.0, 60, IPPROTO_TCP, TH_RST);
    feed(&ctx, 1.0, 60, IPPROTO_TCP, TH_PUSH | TH_ACK);
    feed(&ctx, 1.0, 60, IPPROTO_TCP, TH_URG);
    feed(&ctx, 1.0, 60, IPPROTO_TCP, TCP_ECE);
    feed(&ctx, 1.0, 60, IPPROTO_TCP, TCP_CWR);
    feed(&ctx, 1.0, 60, IPPROTO_TCP, 0);                           /* null */
    feed(&ctx, 1.0, 60, IPPROTO_TCP, TH_FIN | TH_PUSH | TH_URG);   /* xmas */
    feed(&ctx, 1.0, 60, IPPROTO_TCP,
         TH_SYN | TH_FIN | TH_PUSH | TH_URG);        /* syn+fin, NOT xmas */
    feed(&ctx, 1.0, 60, IPPROTO_TCP, TH_SYN | TH_RST);
    feed(&ctx, 1.0, 60, IPPROTO_TCP,
         TH_SYN | TH_ACK | TH_FIN);

    CHECK(ctx.tcp_packets == 13);
    CHECK(ctx.syn == 2);       /* revise if syn is redefined as SYN&&!ACK */
    CHECK(ctx.syn_ack == 2);
    CHECK(ctx.ack == 5);
    CHECK(ctx.fin == 4);
    CHECK(ctx.rst == 2);
    CHECK(ctx.psh == 3);
    CHECK(ctx.urg == 3);
    CHECK(ctx.ece_cwr == 2);
    CHECK(ctx.null_scan_pkts == 1);
    CHECK(ctx.xmas_scan_pkts == 1);
    CHECK(ctx.syn_fin_pkts == 2);
    CHECK(ctx.syn_rst_pkts == 1);
    stats_free(&ctx);
}

static void test_malformed_and_other(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    parsed_packet_t bad = make_packet(5.5, 100, IPPROTO_TCP);
    bad.is_malformed = true;
    bad.tcp_flags = TH_SYN;
    CHECK(stats_update(&ctx, &bad) == PCAPSTAT_OK);
    feed(&ctx, 5.6, 80, IPPROTO_ICMP, 0);

    CHECK(ctx.total_packets == 2);
    CHECK(ctx.malformed_packets == 1);
    CHECK(ctx.tcp_packets == 0);
    CHECK(ctx.syn == 0);
    CHECK(ctx.other_packets == 1);
    CHECK(ctx.packet_size_histogram[1] == 2); /* 100 and 80 -> bin 1 */

    CHECK(stats_finalize(&ctx) == PCAPSTAT_OK);
    CHECK(ctx.timeline_count == 1);
    CHECK(ctx.timeline[0].packets == 2);
    CHECK(ctx.timeline[0].tcp_packets == 0);
    CHECK(ctx.timeline[0].other_packets == 1);
    stats_free(&ctx);
}

static void test_timeline_contents_and_order(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    feed(&ctx, 10.1, 100, IPPROTO_UDP, 0);
    feed(&ctx, 10.9, 200, IPPROTO_UDP, 0);
    feed(&ctx, 10.5, 50, IPPROTO_UDP, 0);
    feed(&ctx, 9.2, 40, IPPROTO_TCP, TH_ACK); /* out of order */

    CHECK(stats_finalize(&ctx) == PCAPSTAT_OK);
    CHECK(ctx.first_ts == 9.2);
    CHECK(ctx.last_ts == 10.9);
    CHECK(fabs(ctx.duration_sec - 1.7) < 1e-9);
    CHECK(fabs(ctx.avg_pps - 4.0 / 1.7) < 1e-6);
    CHECK(ctx.timeline_count == 2);

    CHECK(ctx.timeline[0].sec == 9);
    CHECK(ctx.timeline[0].span_sec == 1);
    CHECK(ctx.timeline[0].packets == 1);
    CHECK(ctx.timeline[0].tcp_packets == 1);
    CHECK(ctx.timeline[0].tcp_bytes == 40);

    CHECK(ctx.timeline[1].sec == 10);
    CHECK(ctx.timeline[1].span_sec == 1);
    CHECK(ctx.timeline[1].packets == 3);
    CHECK(ctx.timeline[1].bytes == 350);
    CHECK(ctx.timeline[1].udp_packets == 3);
    CHECK(ctx.timeline[1].udp_bytes == 350);
    CHECK(ctx.timeline[1].udp_packets_max == 3);
    stats_free(&ctx);
}

static void test_sparse_far_apart(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);
    feed(&ctx, 0.0, 64, IPPROTO_UDP, 0);
    feed(&ctx, 2.0e9, 64, IPPROTO_UDP, 0); /* ~63 years, no dense array */
    CHECK(stats_finalize(&ctx) == PCAPSTAT_OK);
    CHECK(ctx.timeline_count == 2);
    CHECK(ctx.duration_sec == 2.0e9);
    stats_free(&ctx);
}

static void test_non_finite_timestamps(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    feed(&ctx, NAN, 64, IPPROTO_UDP, 0);      /* first packet w/o usable ts */
    feed(&ctx, INFINITY, 64, IPPROTO_UDP, 0);
    feed(&ctx, 1e30, 64, IPPROTO_UDP, 0);     /* would overflow int64 */
    feed(&ctx, 100.5, 64, IPPROTO_UDP, 0);
    feed(&ctx, 101.5, 64, IPPROTO_UDP, 0);

    CHECK(stats_finalize(&ctx) == PCAPSTAT_OK);
    CHECK(ctx.total_packets == 5);
    CHECK(ctx.first_ts == 100.5);   /* fails on code with bug B1 */
    CHECK(ctx.last_ts == 101.5);
    CHECK(ctx.duration_sec == 1.0);
    CHECK(ctx.timeline_count == 2); /* only usable timestamps bucketed */
    stats_free(&ctx);
}

static void test_downsampling_preserves_totals_and_burst(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    uint64_t total_bytes = 0, total_pkts = 0;
    for (int i = 0; i < 1000; ++i) {      /* seconds 0..999, no gaps */
        feed(&ctx, (double)i, 70, IPPROTO_UDP, 0);
        total_bytes += 70; total_pkts++;
    }
    for (int k = 0; k < 39; ++k) { /* burst: 40 UDP packets in second 500 */
        feed(&ctx, 500.3, 70, IPPROTO_UDP, 0);
        total_bytes += 70; total_pkts++;
    }
    CHECK(stats_finalize(&ctx) == PCAPSTAT_OK);

    CHECK(ctx.timeline_count >= 60 && ctx.timeline_count <= 120);

    uint64_t sum_pkts = 0, sum_bytes = 0, sum_udp = 0, peak = 0;
    uint64_t sum_span = 0;
    for (size_t i = 0; i < ctx.timeline_count; ++i) {
        if (i > 0)
            CHECK(ctx.timeline[i].sec > ctx.timeline[i - 1].sec);
        CHECK(ctx.timeline[i].span_sec >= 1);
        sum_pkts += ctx.timeline[i].packets;
        sum_bytes += ctx.timeline[i].bytes;
        sum_udp += ctx.timeline[i].udp_packets;
        sum_span += ctx.timeline[i].span_sec;
        if (ctx.timeline[i].udp_packets_max > peak)
            peak = ctx.timeline[i].udp_packets_max;
    }
    CHECK(sum_pkts == total_pkts);
    CHECK(sum_bytes == total_bytes);
    CHECK(sum_udp == total_pkts);
    CHECK(sum_span == 1000);        /* groups tile the 0..999 range exactly */
    CHECK(peak == 40);              /* burst survives downsampling */
    stats_free(&ctx);
}

static void test_finalize_empty_and_repeat(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);
    CHECK(stats_finalize(&ctx) == PCAPSTAT_OK);
    CHECK(ctx.timeline == NULL && ctx.timeline_count == 0);
    CHECK(ctx.duration_sec == 0.0 && ctx.avg_pps == 0.0);

    feed(&ctx, 1.0, 64, IPPROTO_UDP, 0);
    feed(&ctx, 3.0, 64, IPPROTO_UDP, 0);
    CHECK(stats_finalize(&ctx) == PCAPSTAT_OK);
    CHECK(stats_finalize(&ctx) == PCAPSTAT_OK); /* no leak, same result */
    CHECK(ctx.timeline_count == 2);
    CHECK(ctx.duration_sec == 2.0);

    feed(&ctx, 4.0, 64, IPPROTO_UDP, 0);        /* update after finalize */
    CHECK(stats_finalize(&ctx) == PCAPSTAT_OK);
    CHECK(ctx.timeline_count == 3);
    stats_free(&ctx);
}


static void test_span_with_gaps(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);
    for (int i = 0; i < 250; ++i)
        feed(&ctx, (double)(i * 10), 70, IPPROTO_UDP, 0); /* 1 pkt / 10 s */
    CHECK(stats_finalize(&ctx) == PCAPSTAT_OK);
    CHECK(ctx.timeline_count == 120);
    for (size_t i = 0; i < ctx.timeline_count; ++i) {
        CHECK(ctx.timeline[i].span_sec >= 11);   /* 2 buckets: 10 s apart + 1 */
        CHECK(ctx.timeline[i].packets >= 2);
    }
    stats_free(&ctx);
}


static void test_category_invariant(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);
    feed(&ctx, 1.0, 60, IPPROTO_TCP, TH_ACK);
    feed(&ctx, 1.0, 60, IPPROTO_UDP, 0);
    feed(&ctx, 1.0, 60, IPPROTO_ICMP, 0);
    parsed_packet_t bad = make_packet(NAN, 60, IPPROTO_TCP);
    bad.is_malformed = true;
    CHECK(stats_update(&ctx, &bad) == PCAPSTAT_OK);
    CHECK(ctx.tcp_packets + ctx.udp_packets + ctx.other_packets +
          ctx.malformed_packets == ctx.total_packets);
    stats_free(&ctx);
}

#define RUN(t)                          \
    do {                                \
        printf("  %s...\n", #t);        \
        t();                            \
        printf("    PASS\n");           \
    } while (0)

int main(void)
{
    RUN(test_basic_stats);
    RUN(test_downsampling_and_zero_duration);
    RUN(test_null_args);
    RUN(test_histogram_boundaries);
    RUN(test_tcp_flag_counters);
    RUN(test_malformed_and_other);
    RUN(test_timeline_contents_and_order);
    RUN(test_sparse_far_apart);
    RUN(test_non_finite_timestamps);
    RUN(test_downsampling_preserves_totals_and_burst);
    RUN(test_finalize_empty_and_repeat);
    RUN(test_span_with_gaps);
    RUN(test_category_invariant);
    return 0;
}