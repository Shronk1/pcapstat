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

/* ---- Helpers ---------------------------------------------------------- */

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

/* Packet without L3 info (ip_version == 0): global counters only. */
static void feed(stats_ctx_t *ctx, double ts, uint32_t len, uint8_t proto,
                 uint8_t flags)
{
    parsed_packet_t p = make_packet(ts, len, proto);
    p.tcp_flags = flags;
    CHECK(stats_update(ctx, &p) == PCAPSTAT_OK);
}

/* IPv4 packet 10.0.0.<src> -> 10.0.0.<dst>. */
static parsed_packet_t net_pkt(double ts, uint8_t proto, uint8_t src,
                               uint8_t dst, uint16_t sp, uint16_t dp,
                               uint8_t flags, uint32_t len)
{
    parsed_packet_t p = make_packet(ts, len, proto);
    p.ip_version = 4;
    p.src_ip[0] = 10;
    p.src_ip[3] = src;
    p.dst_ip[0] = 10;
    p.dst_ip[3] = dst;
    p.src_port = sp;
    p.dst_port = dp;
    p.tcp_flags = flags;
    return p;
}

static void send_pkt(stats_ctx_t *c, parsed_packet_t p)
{
    CHECK(stats_update(c, &p) == PCAPSTAT_OK);
}

static const host_stats_t *find_host(const stats_ctx_t *ctx, uint8_t last)
{
    ht_iter_t it = ht_iter_begin(ctx->hosts_ht);
    const void *key;
    size_t key_len;
    void *value;
    while (ht_iter_next(&it, &key, &key_len, &value)) {
        const host_stats_t *h = (const host_stats_t *)value;
        if (h->ip_version == 4 && h->ip[0] == 10 && h->ip[3] == last)
            return h;
    }
    return NULL;
}

static parsed_packet_t tcp_data(double ts, uint32_t seq)
{
    parsed_packet_t p = make_packet(ts, 100, IPPROTO_TCP);
    p.ip_version = 4;
    p.src_ip[0] = 192;
    p.src_ip[2] = 2;
    p.src_ip[3] = 1;
    p.dst_ip[0] = 198;
    p.dst_ip[1] = 51;
    p.dst_ip[2] = 100;
    p.dst_ip[3] = 2;
    p.src_port = 40000;
    p.dst_port = 443;
    p.tcp_flags = TH_ACK;
    p.payload_len = 10;
    p.tcp_seq = seq;
    return p;
}

static const flow_stats_t *only_flow(const stats_ctx_t *ctx)
{
    ht_iter_t it = ht_iter_begin(ctx->flows_ht);
    const void *key;
    size_t key_len;
    void *value;
    CHECK(ht_iter_next(&it, &key, &key_len, &value));
    return (const flow_stats_t *)value;
}

/* ---- TASK-06: global metrics, histogram, flags, time series ----------- */

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

/* FIX-03 (M1): half-open bins matching the chart labels
 * "<64, 64-127, 128-255, 256-511, 512-1023, 1024-1513, >=1514".
 * The old "<=64 ... <=1500" bins put 64 in "<64" and 1500..1513 nowhere
 * near their label. */
static void test_histogram_boundaries(void)
{
    static const struct {
        uint32_t size;
        int bin;
    } cases[] = {
        {0, 0},     {63, 0},    {64, 1},    {127, 1},  {128, 2},
        {255, 2},   {256, 3},   {511, 3},   {512, 4},  {1023, 4},
        {1024, 5},  {1500, 5},  {1513, 5},  {1514, 6}, {1518, 6},
        {65535, 6},
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
    feed(&ctx, 1.0, 60, IPPROTO_TCP, 0);                         /* null */
    feed(&ctx, 1.0, 60, IPPROTO_TCP, TH_FIN | TH_PUSH | TH_URG); /* xmas */
    feed(&ctx, 1.0, 60, IPPROTO_TCP,
         TH_SYN | TH_FIN | TH_PUSH | TH_URG);     /* syn+fin, NOT xmas */
    feed(&ctx, 1.0, 60, IPPROTO_TCP, TH_SYN | TH_RST);
    feed(&ctx, 1.0, 60, IPPROTO_TCP,
         TH_SYN | TH_ACK | TH_FIN);  /* syn_ack + syn_fin, NOT pure syn */

    CHECK(ctx.tcp_packets == 13);
    CHECK(ctx.syn == 2);
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
    /* FIX-06: non-IP frames are their own category. */
    parsed_packet_t arp = make_packet(1.0, 60, 0);
    arp.is_non_ip = true;
    CHECK(stats_update(&ctx, &arp) == PCAPSTAT_OK);
    /* A fragment is counted by proto; ip_fragments is informational. */
    parsed_packet_t frag = net_pkt(1.0, IPPROTO_UDP, 1, 2, 0, 0, 0, 60);
    frag.is_fragment = true;
    CHECK(stats_update(&ctx, &frag) == PCAPSTAT_OK);
    CHECK(ctx.total_packets == 6);
    CHECK(ctx.non_ip_packets == 1);
    CHECK(ctx.malformed_packets == 1);
    CHECK(ctx.ip_fragments == 1);
    CHECK(ctx.udp_packets == 2);
    CHECK(ctx.tcp_packets + ctx.udp_packets + ctx.other_packets +
              ctx.non_ip_packets + ctx.malformed_packets ==
          ctx.total_packets);
    stats_free(&ctx);
}

/* H2 (stats side): a non-IP frame (ARP, LLDP, ...) is counted only in
 * non_ip_packets and the bucket totals: not malformed, not "other IP", no
 * hosts/ports/flows, even if a hand-built packet carries stray L3 data. */
static void test_non_ip_frames_classified(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);
    for (int i = 0; i < 4; ++i) {
        parsed_packet_t p = net_pkt(5.0 + 0.1 * i, 0, 1, 2, 0, 0, 0, 60);
        p.ip_version = (i == 0) ? 4 : 0; /* stray L3 info must be ignored */
        p.is_non_ip = true;
        send_pkt(&ctx, p);
    }
    CHECK(ctx.total_packets == 4);
    CHECK(ctx.total_bytes == 240);
    CHECK(ctx.non_ip_packets == 4);
    CHECK(ctx.malformed_packets == 0);
    CHECK(ctx.other_packets == 0);
    CHECK(ctx.tcp_packets == 0 && ctx.udp_packets == 0);
    CHECK(ht_count(ctx.hosts_ht) == 0);
    CHECK(ht_count(ctx.ports_ht) == 0);
    CHECK(ht_count(ctx.flows_ht) == 0);

    CHECK(stats_finalize(&ctx) == PCAPSTAT_OK);
    CHECK(ctx.timeline_count == 1);
    CHECK(ctx.timeline[0].packets == 4);
    CHECK(ctx.timeline[0].bytes == 240);
    CHECK(ctx.timeline[0].other_packets == 0);
    CHECK(ctx.timeline[0].tcp_packets == 0);
    CHECK(ctx.timeline[0].udp_packets == 0);
    stats_free(&ctx);
}

/* H3 (stats side): IPv4 non-first fragments count as TCP/UDP by proto and
 * in ip_fragments, update host tx/rx, but never reach TCP flag counters,
 * ports, flows, the port-scan set or retransmission tracking. Ports and
 * flags are deliberately set to garbage here to prove they are ignored
 * (the parser zeroes them; zero flags used to be a fake "Null Scan"). */
static void test_fragments_skip_l4(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    for (int i = 0; i < 30; ++i) {
        parsed_packet_t p = net_pkt(1.0 + 0.01 * i, IPPROTO_UDP, 1, 2,
                                    (uint16_t)(1000 + i), (uint16_t)(2000 + i),
                                    0, 1000);
        p.is_fragment = true;
        send_pkt(&ctx, p);
    }
    const uint8_t tcp_flag_patterns[] = {
        0, TH_FIN | TH_PUSH | TH_URG, TH_SYN | TH_FIN, TH_SYN | TH_RST, TH_SYN
    };
    for (size_t i = 0; i < sizeof(tcp_flag_patterns); ++i) {
        parsed_packet_t p = net_pkt(2.0 + 0.01 * (double)i, IPPROTO_TCP, 3, 4,
                                    (uint16_t)(3000 + i), (uint16_t)(80 + i),
                                    tcp_flag_patterns[i], 500);
        p.is_fragment = true;
        p.tcp_seq = 1000;
        p.payload_len = 100;
        send_pkt(&ctx, p);
        send_pkt(&ctx, p); /* would be a "retransmission" if tracked */
    }

    CHECK(ctx.total_packets == 40);
    CHECK(ctx.ip_fragments == 40);
    CHECK(ctx.udp_packets == 30 && ctx.udp_bytes == 30000);
    CHECK(ctx.tcp_packets == 10 && ctx.tcp_bytes == 5000);
    CHECK(ctx.other_packets == 0 && ctx.non_ip_packets == 0);
    CHECK(ctx.syn == 0 && ctx.syn_ack == 0 && ctx.ack == 0);
    CHECK(ctx.fin == 0 && ctx.rst == 0 && ctx.psh == 0 && ctx.urg == 0);
    CHECK(ctx.null_scan_pkts == 0 && ctx.xmas_scan_pkts == 0);
    CHECK(ctx.syn_fin_pkts == 0 && ctx.syn_rst_pkts == 0);
    CHECK(ctx.tcp_retransmissions == 0 && ctx.tcp_out_of_order == 0);
    CHECK(ht_count(ctx.ports_ht) == 0);
    CHECK(ht_count(ctx.flows_ht) == 0);
    CHECK(ht_count(ctx.hosts_ht) == 4);

    const host_stats_t *h1 = find_host(&ctx, 1);
    const host_stats_t *h2 = find_host(&ctx, 2);
    const host_stats_t *h3 = find_host(&ctx, 3);
    CHECK(h1 != NULL && h2 != NULL && h3 != NULL);
    CHECK(h1->tx_packets == 30 && h1->tx_bytes == 30000);
    CHECK(h2->rx_packets == 30 && h2->rx_bytes == 30000);
    CHECK(h1->unique_dst_ports == 0 && h1->dst_ports_bitmap == NULL);
    CHECK(h3->tx_packets == 10);
    CHECK(h3->syn_sent == 0 && h3->rst_sent == 0);
    CHECK(h3->unique_dst_ports == 0);

    /* Buckets count fragments by proto, like the global counters. */
    CHECK(stats_finalize(&ctx) == PCAPSTAT_OK);
    CHECK(ctx.timeline_count == 2);
    CHECK(ctx.timeline[0].udp_packets == 30);
    CHECK(ctx.timeline[1].tcp_packets == 10);
    stats_free(&ctx);
}

/* A first fragment (offset 0, MF set) is decoded normally by the parser
 * and has is_fragment == false: its L4 header is real and still counted. */
static void test_first_fragment_still_counted(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);
    send_pkt(&ctx, net_pkt(1.0, IPPROTO_TCP, 1, 2, 40000, 80, TH_SYN, 60));
    CHECK(ctx.syn == 1 && ctx.ip_fragments == 0);
    CHECK(ht_count(ctx.flows_ht) == 1 && ht_count(ctx.ports_ht) == 1);
    CHECK(find_host(&ctx, 1)->unique_dst_ports == 1);
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

    feed(&ctx, NAN, 64, IPPROTO_UDP, 0);  /* first packet w/o usable ts */
    feed(&ctx, INFINITY, 64, IPPROTO_UDP, 0);
    feed(&ctx, 1e30, 64, IPPROTO_UDP, 0); /* would overflow int64 */
    feed(&ctx, 100.5, 64, IPPROTO_UDP, 0);
    feed(&ctx, 101.5, 64, IPPROTO_UDP, 0);

    CHECK(stats_finalize(&ctx) == PCAPSTAT_OK);
    CHECK(ctx.total_packets == 5);
    CHECK(ctx.first_ts == 100.5);
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
    for (int i = 0; i < 1000; ++i) { /* seconds 0..999, no gaps */
        feed(&ctx, (double)i, 70, IPPROTO_UDP, 0);
        total_bytes += 70;
        total_pkts++;
    }
    for (int k = 0; k < 39; ++k) { /* burst: 40 UDP packets in second 500 */
        feed(&ctx, 500.3, 70, IPPROTO_UDP, 0);
        total_bytes += 70;
        total_pkts++;
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
    CHECK(sum_span == 1000); /* groups tile the 0..999 range exactly */
    CHECK(peak == 40);       /* burst survives downsampling */
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
        CHECK(ctx.timeline[i].span_sec >= 11); /* 2 buckets: 10 s apart + 1 */
        CHECK(ctx.timeline[i].packets >= 2);
    }
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

    feed(&ctx, 4.0, 64, IPPROTO_UDP, 0); /* update after finalize */
    CHECK(stats_finalize(&ctx) == PCAPSTAT_OK);
    CHECK(ctx.timeline_count == 3);
    stats_free(&ctx);
}

/* ---- TASK-07: hosts, ports, flows, retransmissions, Top-N ------------- */

static void test_host_counters_and_port_bitmap(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    send_pkt(&ctx, net_pkt(1.0, IPPROTO_TCP, 1, 2, 40000, 1000, TH_SYN, 60));
    send_pkt(&ctx, net_pkt(1.1, IPPROTO_TCP, 1, 2, 40000, 1000, TH_SYN, 60)); /* dup port */
    send_pkt(&ctx, net_pkt(1.2, IPPROTO_TCP, 1, 2, 40000, 1001, TH_SYN, 60));
    send_pkt(&ctx, net_pkt(1.3, IPPROTO_TCP, 1, 2, 40000, 65535, TH_SYN, 60)); /* last bitmap bit */
    send_pkt(&ctx, net_pkt(1.4, IPPROTO_TCP, 1, 2, 40000, 0, TH_SYN, 60));     /* port 0 ignored */
    send_pkt(&ctx, net_pkt(1.5, IPPROTO_TCP, 1, 2, 40000, 2000, TH_SYN | TH_ACK, 60)); /* not pure SYN */
    send_pkt(&ctx, net_pkt(1.6, IPPROTO_TCP, 1, 2, 40000, 3000, TH_ACK, 60));
    send_pkt(&ctx, net_pkt(1.7, IPPROTO_UDP, 1, 2, 40000, 4000, 0, 60));      /* UDP probe */
    send_pkt(&ctx, net_pkt(1.8, IPPROTO_TCP, 2, 1, 1000, 50000, TH_RST, 60));

    const host_stats_t *a = find_host(&ctx, 1);
    const host_stats_t *b = find_host(&ctx, 2);
    CHECK(a != NULL && b != NULL);
    CHECK(ht_count(ctx.hosts_ht) == 2);

    CHECK(a->tx_packets == 8 && a->tx_bytes == 480);
    CHECK(a->rx_packets == 1 && a->rx_bytes == 60);
    CHECK(a->syn_sent == 5);         /* pure SYN, incl. dup and port 0 */
    CHECK(a->unique_dst_ports == 4); /* TCP 1000, 1001, 65535 + UDP 4000 */
    CHECK(a->rst_recv == 1 && a->rst_sent == 0);
    CHECK(b->rx_packets == 8 && b->tx_packets == 1);
    CHECK(b->syn_ack_recv == 1);
    CHECK(b->rst_sent == 1);
    CHECK(b->unique_dst_ports == 0); /* a RST to port 50000 is not a probe */

    CHECK(ht_count(ctx.ports_ht) == 8);  /* guards against key padding bug */
    CHECK(ht_count(ctx.flows_ht) == 8);  /* directional: RST is its own flow */
    stats_free(&ctx);
}

static void test_udp_scan_tracking(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    /* Host 1 sweeps UDP ports 1000..1009 of host 2 from one source port. */
    for (uint16_t p = 1000; p < 1010; ++p)
        send_pkt(&ctx, net_pkt(1.0 + p / 1000.0, IPPROTO_UDP, 1, 2, 5000,
                               p, 0, 60));
    send_pkt(&ctx, net_pkt(2.0, IPPROTO_UDP, 1, 2, 5000, 1000, 0, 60)); /* dup */
    send_pkt(&ctx, net_pkt(2.1, IPPROTO_UDP, 1, 2, 5000, 0, 0, 60));    /* port 0 */
    /* Host 2 answers on one port: reply to a known flow, not a probe. */
    send_pkt(&ctx, net_pkt(2.2, IPPROTO_UDP, 2, 1, 1000, 5000, 0, 60));

    const host_stats_t *scanner = find_host(&ctx, 1);
    const host_stats_t *target = find_host(&ctx, 2);
    CHECK(scanner != NULL && target != NULL);
    CHECK(scanner->unique_dst_ports == 10);
    CHECK(scanner->syn_sent == 0);
    CHECK(target->unique_dst_ports == 0);
    stats_free(&ctx);
}

static void test_udp_server_replies_are_not_scans(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    /* A DNS server (host 3) answers 20 clients on distinct ephemeral
     * ports; every answer follows the client's query. */
    for (uint8_t c = 10; c < 30; ++c) {
        uint16_t eph = (uint16_t)(50000 + c);
        send_pkt(&ctx, net_pkt(1.0, IPPROTO_UDP, c, 3, eph, 53, 0, 80));
        send_pkt(&ctx, net_pkt(1.1, IPPROTO_UDP, 3, c, 53, eph, 0, 120));
    }

    const host_stats_t *server = find_host(&ctx, 3);
    const host_stats_t *client = find_host(&ctx, 10);
    CHECK(server != NULL && client != NULL);
    CHECK(server->unique_dst_ports == 0);
    CHECK(client->unique_dst_ports == 1); /* its query to port 53 */
    CHECK(ht_count(ctx.flows_ht) == 40);  /* both directions are flows */
    stats_free(&ctx);
}

static void test_scan_ports_shared_between_tcp_and_udp(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    send_pkt(&ctx, net_pkt(1.0, IPPROTO_TCP, 5, 6, 40000, 80, TH_SYN, 60));
    send_pkt(&ctx, net_pkt(1.1, IPPROTO_UDP, 5, 6, 40001, 80, 0, 60));
    CHECK(find_host(&ctx, 5)->unique_dst_ports == 1); /* port 80 once */
    send_pkt(&ctx, net_pkt(1.2, IPPROTO_UDP, 5, 6, 40001, 81, 0, 60));
    CHECK(find_host(&ctx, 5)->unique_dst_ports == 2);

    /* Non-TCP/UDP traffic never touches the bitmap. */
    send_pkt(&ctx, net_pkt(1.3, IPPROTO_ICMP, 5, 6, 0, 0, 0, 60));
    CHECK(find_host(&ctx, 5)->unique_dst_ports == 2);
    CHECK(ht_count(ctx.ports_ht) == 3); /* tcp/80, udp/80, udp/81 */
    stats_free(&ctx);
}

static void test_retransmission_seq_wraparound(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    parsed_packet_t p = tcp_data(1.0, 0xFFFFFFF0u);
    CHECK(stats_update(&ctx, &p) == PCAPSTAT_OK);
    p = tcp_data(2.0, 0x10u); /* wrapped forward: new data */
    CHECK(stats_update(&ctx, &p) == PCAPSTAT_OK);
    CHECK(only_flow(&ctx)->retransmissions == 0);
    p = tcp_data(3.0, 0x10u); /* same seq: retransmission */
    CHECK(stats_update(&ctx, &p) == PCAPSTAT_OK);
    CHECK(only_flow(&ctx)->retransmissions == 1);
    p = tcp_data(4.0, 0xFFFFFFF0u); /* behind across the wrap */
    CHECK(stats_update(&ctx, &p) == PCAPSTAT_OK);
    CHECK(only_flow(&ctx)->retransmissions == 2);

    p = tcp_data(5.0, 0x10u); /* payload 0 is ignored entirely */
    p.payload_len = 0;
    CHECK(stats_update(&ctx, &p) == PCAPSTAT_OK);
    CHECK(only_flow(&ctx)->retransmissions == 2);
    stats_free(&ctx);
}

static void test_unsorted_48h_and_retransmission(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    /* tcp_data() segments carry 10 payload bytes. */
    struct {
        double ts;
        uint32_t seq;
    } in[] = {
        {1.0, 100},      /* first: next_seq=110, last_seq_ts=1.0      */
        {172800.0, 100}, /* same seq, later ts           -> retrans 1 */
        {90000.0, 99},   /* older seq, later than 1.0    -> retrans 2 */
        {172800.0, 200}, /* ahead: hole [110,200), next_seq=210       */
        {100.0, 150},    /* ts < last_seq_ts: NOT counted, rebase     */
    };
    for (size_t i = 0; i < sizeof(in) / sizeof(in[0]); ++i) {
        parsed_packet_t p = tcp_data(in[i].ts, in[i].seq);
        CHECK(stats_update(&ctx, &p) == PCAPSTAT_OK);
    }

    const flow_stats_t *f = only_flow(&ctx);
    CHECK(f->packets == 5);
    CHECK(f->retransmissions == 2);
    CHECK(f->out_of_order == 0);
    CHECK(f->first_ts == 1.0 && f->last_ts == 172800.0);
    CHECK(f->next_seq == 160);      /* documented: base follows the rebase */
    CHECK(f->last_seq_ts == 100.0);
    CHECK(!f->has_hole);            /* a rebase forgets the hole */
    CHECK(ctx.tcp_retransmissions == 2);

    CHECK(stats_finalize(&ctx) == PCAPSTAT_OK);
    CHECK(ctx.timeline_count == 4); /* secs 1, 100, 90000, 172800 only */
    CHECK(ctx.duration_sec == 172799.0);
    CHECK(ctx.avg_pps > 0.0 && ctx.avg_bps > 0.0);
    stats_free(&ctx);
}

static void test_top_n_bytes_vs_packets_and_ties(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    send_pkt(&ctx, net_pkt(1.0, IPPROTO_UDP, 1, 2, 5000, 53, 0, 1500));
    for (int i = 0; i < 3; ++i)
        send_pkt(&ctx, net_pkt(2.0, IPPROTO_UDP, 3, 4, 5000, 80, 0, 100));

    const host_stats_t *top[8];
    CHECK(stats_top_hosts(&ctx, top, 8) == 4); /* max_n > count */
    CHECK(top[0]->ip[3] == 1);                 /* 1500 B beats 3 pkts */
    CHECK(top[1]->ip[3] == 2);                 /* tie on bytes+packets: by IP */
    CHECK(top[2]->ip[3] == 3 && top[3]->ip[3] == 4);
    CHECK(stats_top_hosts(&ctx, top, 2) == 2);
    CHECK(stats_top_hosts(&ctx, NULL, 0) == 0);
    CHECK(stats_top_hosts(NULL, top, 2) == 0);

    const port_stats_t *ports[4];
    CHECK(stats_top_ports(&ctx, ports, 4) == 2);
    CHECK(ports[0]->dst_port == 80 && ports[0]->packets == 3);
    CHECK(ports[1]->dst_port == 53);

    const flow_stats_t *flows[4];
    CHECK(stats_top_flows(&ctx, flows, 4) == 2);
    CHECK(flows[0]->packets == 3 && flows[1]->packets == 1);
    stats_free(&ctx);
}

static void test_service_names(void)
{
    CHECK(strcmp(stats_port_service_name(IPPROTO_TCP, 22), "SSH") == 0);
    CHECK(strcmp(stats_port_service_name(IPPROTO_UDP, 53), "DNS") == 0);
    CHECK(strcmp(stats_port_service_name(IPPROTO_UDP, 123), "NTP") == 0);
    CHECK(strcmp(stats_port_service_name(IPPROTO_TCP, 443), "HTTPS") == 0);
    CHECK(strcmp(stats_port_service_name(IPPROTO_TCP, 3306), "MySQL") == 0);
    CHECK(strcmp(stats_port_service_name(IPPROTO_TCP, 8080), "HTTP-Alt") == 0);
    /* FIX-03: no made-up demo-only "UDP-Data" service on 9999. */
    CHECK(strcmp(stats_port_service_name(IPPROTO_UDP, 9999), "Unknown") == 0);
    CHECK(strcmp(stats_port_service_name(IPPROTO_TCP, 9999), "Unknown") == 0);
    CHECK(strcmp(stats_port_service_name(IPPROTO_TCP, 0), "Unknown") == 0);
    CHECK(strcmp(stats_port_service_name(IPPROTO_TCP, 1), "Unknown") == 0);
}

/* Needs samples/demo.pcap (run from the project root); skipped if absent
 * so a missing file is reported instead of failing with a bare ERR_IO. */
static void test_demo_hosts_ports_flows(void)
{
    FILE *f = fopen("samples/demo.pcap", "rb");
    if (f == NULL) {
        printf("    SKIP (samples/demo.pcap not found; run from project root)\n");
        return;
    }
    fclose(f);

    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);
    CHECK(parser_process_file("samples/demo.pcap", stats_packet_cb, &ctx) ==
          PCAPSTAT_OK);
    CHECK(ctx.tcp_packets + ctx.udp_packets + ctx.other_packets +
              ctx.malformed_packets == ctx.total_packets);

    const host_stats_t *scan = find_host(&ctx, 100); /* 10.0.0.100 */
    CHECK(scan != NULL);
    CHECK(scan->unique_dst_ports == 25);
    CHECK(scan->dst_ports_bitmap != NULL); /* 25 > inline capacity */

    uint64_t retransmissions = 0;
    uint64_t out_of_order = 0;
    uint64_t max_pkts = 0;
    ht_iter_t it = ht_iter_begin(ctx.flows_ht);
    const void *key;
    size_t key_len;
    void *value;
    while (ht_iter_next(&it, &key, &key_len, &value)) {
        const flow_stats_t *flow = (const flow_stats_t *)value;
        retransmissions += flow->retransmissions;
        out_of_order += flow->out_of_order;
        if (flow->packets > max_pkts)
            max_pkts = flow->packets;
    }
    /* The same 100-byte segment (seq 301, already delivered) sent three
     * times 10 ms apart: exactly 3 retransmissions, no reordering. */
    CHECK(retransmissions == 3);
    CHECK(out_of_order == 0);
    CHECK(ctx.tcp_retransmissions == retransmissions);
    CHECK(ctx.tcp_out_of_order == out_of_order);

    /* Only hosts that probed > 16 ports own a bitmap (just the scanner). */
    size_t with_bitmap = 0;
    it = ht_iter_begin(ctx.hosts_ht);
    while (ht_iter_next(&it, &key, &key_len, &value)) {
        const host_stats_t *h = (const host_stats_t *)value;
        if (h->dst_ports_bitmap != NULL)
            with_bitmap++;
        else
            CHECK(h->unique_dst_ports <= STATS_HOST_INLINE_PORTS);
    }
    CHECK(with_bitmap == 1);

    const host_stats_t *top_hosts[3];
    const port_stats_t *top_ports[5];
    const flow_stats_t *top_flows[5];
    size_t nh = ht_count(ctx.hosts_ht) < 3 ? ht_count(ctx.hosts_ht) : 3;
    size_t np = ht_count(ctx.ports_ht) < 5 ? ht_count(ctx.ports_ht) : 5;
    size_t nf = ht_count(ctx.flows_ht) < 5 ? ht_count(ctx.flows_ht) : 5;
    CHECK(stats_top_hosts(&ctx, top_hosts, 3) == nh);
    CHECK(stats_top_ports(&ctx, top_ports, 5) == np);
    CHECK(stats_top_flows(&ctx, top_flows, 5) == nf);
    if (nh >= 2)
        CHECK(top_hosts[0]->tx_bytes + top_hosts[0]->rx_bytes >=
              top_hosts[1]->tx_bytes + top_hosts[1]->rx_bytes);
    if (np >= 2)
        CHECK(top_ports[0]->packets >= top_ports[1]->packets);
    CHECK(top_flows[0]->packets == max_pkts); /* brute-force reference */

    stats_free(&ctx);
}

/* ---- FIX-03: units, compact port set, retransmission vs reordering ---- */

/* One payload segment of the tcp_data() flow (192.0.2.1:sport -> :443). */
static void seg(stats_ctx_t *ctx, double ts, uint16_t sport, uint32_t seq,
                uint32_t len)
{
    parsed_packet_t p = tcp_data(ts, seq);
    p.src_port = sport;
    p.payload_len = len;
    CHECK(stats_update(ctx, &p) == PCAPSTAT_OK);
}

static const flow_stats_t *flow_by_sport(const stats_ctx_t *ctx,
                                         uint16_t sport)
{
    ht_iter_t it = ht_iter_begin(ctx->flows_ht);
    const void *key;
    size_t key_len;
    void *value;
    while (ht_iter_next(&it, &key, &key_len, &value)) {
        const flow_stats_t *f = (const flow_stats_t *)value;
        if (f->proto == IPPROTO_TCP && f->src_port == sport)
            return f;
    }
    return NULL;
}

/* Global counters must equal the sums over every flow. */
static void check_global_seq_counters(const stats_ctx_t *ctx)
{
    uint64_t retrans = 0, ooo = 0;
    ht_iter_t it = ht_iter_begin(ctx->flows_ht);
    const void *key;
    size_t key_len;
    void *value;
    while (ht_iter_next(&it, &key, &key_len, &value)) {
        const flow_stats_t *f = (const flow_stats_t *)value;
        retrans += f->retransmissions;
        ooo += f->out_of_order;
    }
    CHECK(ctx->tcp_retransmissions == retrans);
    CHECK(ctx->tcp_out_of_order == ooo);
}

static size_t bitmap_popcount(const uint8_t *bitmap)
{
    size_t n = 0;
    for (size_t i = 0; i < STATS_DST_PORT_BITMAP_BYTES; ++i)
        for (uint8_t b = bitmap[i]; b != 0; b &= (uint8_t)(b - 1))
            n++;
    return n;
}

static bool bitmap_has(const uint8_t *bitmap, uint16_t port)
{
    return (bitmap[port / 8] & (1U << (port % 8))) != 0;
}

/* H4: avg_bps was bytes/s while the report prints it as kbps/Mbps. */
static void test_avg_bps_is_bits_per_second(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);
    feed(&ctx, 1.0, 1000, IPPROTO_UDP, 0);
    feed(&ctx, 3.0, 500, IPPROTO_UDP, 0);
    CHECK(stats_finalize(&ctx) == PCAPSTAT_OK);
    CHECK(ctx.duration_sec == 2.0);
    CHECK(ctx.avg_pps == 1.0);
    CHECK(ctx.avg_bps == 8.0 * 1500.0 / 2.0); /* 6000 bit/s, not 750 */
    CHECK(ctx.avg_bps == 8.0 * (double)ctx.total_bytes / ctx.duration_sec);
    stats_free(&ctx);
}

/* C3: every host used to embed an 8 KB bitmap (856 MB RSS for 100k
 * spoofed sources). Receive-only hosts must not own any port storage. */
static void test_receive_only_host_has_no_port_storage(void)
{
    CHECK(sizeof(host_stats_t) <= 256); /* was > 8192 */

    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    /* Host 1 SYN-scans 100 ports of host 2; host 2 answers SYN+ACK/RST. */
    for (uint16_t p = 1000; p < 1100; ++p) {
        send_pkt(&ctx, net_pkt(1.0, IPPROTO_TCP, 1, 2, 40000, p, TH_SYN, 60));
        send_pkt(&ctx, net_pkt(1.0, IPPROTO_TCP, 2, 1, p, 40000,
                               (p % 2) ? (TH_SYN | TH_ACK) : TH_RST, 60));
    }
    /* Host 5 sends UDP to 50 ports of host 4 (never answered). */
    for (uint16_t p = 2000; p < 2050; ++p)
        send_pkt(&ctx, net_pkt(2.0, IPPROTO_UDP, 5, 4, 5000, p, 0, 60));
    /* Host 3 probes exactly the inline capacity. */
    for (uint16_t p = 1; p <= STATS_HOST_INLINE_PORTS; ++p)
        send_pkt(&ctx, net_pkt(3.0, IPPROTO_TCP, 3, 6, 40000, p, TH_SYN, 60));

    const host_stats_t *h1 = find_host(&ctx, 1);
    const host_stats_t *h2 = find_host(&ctx, 2);
    const host_stats_t *h3 = find_host(&ctx, 3);
    const host_stats_t *h4 = find_host(&ctx, 4);
    const host_stats_t *h5 = find_host(&ctx, 5);
    const host_stats_t *h6 = find_host(&ctx, 6);
    CHECK(h1 && h2 && h3 && h4 && h5 && h6);

    /* Receivers: no probed ports, no bitmap. */
    CHECK(h2->unique_dst_ports == 0 && h2->dst_ports_bitmap == NULL);
    CHECK(h4->unique_dst_ports == 0 && h4->dst_ports_bitmap == NULL);
    CHECK(h6->unique_dst_ports == 0 && h6->dst_ports_bitmap == NULL);
    CHECK(h2->rx_packets == 100 && h4->rx_packets == 50);

    /* At capacity: still inline. Beyond it: promoted. */
    CHECK(h3->unique_dst_ports == STATS_HOST_INLINE_PORTS);
    CHECK(h3->dst_ports_bitmap == NULL);
    CHECK(h1->unique_dst_ports == 100 && h1->dst_ports_bitmap != NULL);
    CHECK(h5->unique_dst_ports == 50 && h5->dst_ports_bitmap != NULL);

    stats_free(&ctx); /* LSan: promoted bitmaps are released */
}

/* C3: promotion inline -> bitmap keeps unique_dst_ports exact (port 0
 * ignored, TCP and UDP share one set, inline ports carried over). */
static void test_port_set_promotion_exact(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    for (uint16_t p = 1; p <= 16; ++p)
        send_pkt(&ctx, net_pkt(1.0, IPPROTO_TCP, 1, 2, 40000, p, TH_SYN, 60));
    for (uint16_t p = 16; p >= 1; --p) /* duplicates, reverse order */
        send_pkt(&ctx, net_pkt(1.1, IPPROTO_TCP, 1, 2, 40001, p, TH_SYN, 60));
    send_pkt(&ctx, net_pkt(1.2, IPPROTO_TCP, 1, 2, 40000, 0, TH_SYN, 60));
    send_pkt(&ctx, net_pkt(1.3, IPPROTO_UDP, 1, 2, 5000, 5, 0, 60)); /* shared */
    send_pkt(&ctx, net_pkt(1.4, IPPROTO_UDP, 1, 2, 5000, 0, 0, 60));

    const host_stats_t *h = find_host(&ctx, 1);
    CHECK(h != NULL);
    CHECK(h->unique_dst_ports == 16);
    CHECK(h->dst_ports_bitmap == NULL);

    send_pkt(&ctx, net_pkt(2.0, IPPROTO_TCP, 1, 2, 40000, 17, TH_SYN, 60));
    CHECK(h->unique_dst_ports == 17);
    CHECK(h->dst_ports_bitmap != NULL);
    CHECK(bitmap_popcount(h->dst_ports_bitmap) == 17);

    /* Every pre-promotion port is a duplicate now. */
    for (uint16_t p = 1; p <= 17; ++p)
        send_pkt(&ctx, net_pkt(2.1, IPPROTO_TCP, 1, 2, 40002, p, TH_SYN, 60));
    send_pkt(&ctx, net_pkt(2.2, IPPROTO_UDP, 1, 2, 5000, 3, 0, 60));
    send_pkt(&ctx, net_pkt(2.3, IPPROTO_TCP, 1, 2, 40000, 0, TH_SYN, 60));
    CHECK(h->unique_dst_ports == 17);

    for (uint16_t p = 18; p <= 40; ++p)
        send_pkt(&ctx, net_pkt(3.0, IPPROTO_TCP, 1, 2, 40000, p, TH_SYN, 60));
    for (uint16_t p = 30; p <= 60; ++p) /* 30..40 overlap TCP */
        send_pkt(&ctx, net_pkt(3.1, IPPROTO_UDP, 1, 2, 5001, p, 0, 60));
    send_pkt(&ctx, net_pkt(3.2, IPPROTO_TCP, 1, 2, 40000, 65535, TH_SYN, 60));
    send_pkt(&ctx, net_pkt(3.3, IPPROTO_TCP, 1, 2, 40000, 65535, TH_SYN, 60));

    CHECK(h->unique_dst_ports == 61);
    CHECK(bitmap_popcount(h->dst_ports_bitmap) == 61);
    for (uint16_t p = 1; p <= 60; ++p)
        CHECK(bitmap_has(h->dst_ports_bitmap, p));
    CHECK(bitmap_has(h->dst_ports_bitmap, 65535));
    CHECK(!bitmap_has(h->dst_ports_bitmap, 0));
    CHECK(!bitmap_has(h->dst_ports_bitmap, 61));
    CHECK(find_host(&ctx, 2)->dst_ports_bitmap == NULL);
    stats_free(&ctx);
}

/* Every possible port once (and port 0): 65535 distinct, exactly. */
static void test_port_set_full_sweep(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);
    for (uint32_t p = 0; p <= 65535; ++p)
        send_pkt(&ctx, net_pkt(1.0, IPPROTO_TCP, 1, 2, 40000, (uint16_t)p,
                               TH_SYN, 60));
    const host_stats_t *h = find_host(&ctx, 1);
    CHECK(h != NULL && h->dst_ports_bitmap != NULL);
    CHECK(h->unique_dst_ports == 65535);
    CHECK(bitmap_popcount(h->dst_ports_bitmap) == 65535);
    stats_free(&ctx);
}

/* H6: 30 segments with 10 adjacent swaps 0.1 ms apart used to report 10
 * retransmissions (33 %). Reordering is not retransmission. */
static void test_sub_ms_swaps_are_out_of_order(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    size_t order[30];
    for (size_t i = 0; i < 30; ++i)
        order[i] = i;
    for (size_t j = 0; j < 10; ++j) { /* swap (1,2) (4,5) ... (28,29) */
        size_t a = 3 * j + 1;
        order[a] = a + 1;
        order[a + 1] = a;
    }
    for (size_t k = 0; k < 30; ++k)
        seg(&ctx, 10.0 + 0.0001 * (double)k, 40000,
            1000u + 100u * (uint32_t)order[k], 100);

    const flow_stats_t *f = only_flow(&ctx);
    CHECK(f->packets == 30);
    CHECK(f->retransmissions == 0); /* old code: 10 */
    CHECK(f->out_of_order == 10);
    CHECK(!f->has_hole);
    CHECK(f->next_seq == 1000u + 100u * 30u);
    CHECK(ctx.tcp_retransmissions == 0 && ctx.tcp_out_of_order == 10);
    stats_free(&ctx);
}

/* H6: exact duplicates are retransmissions, also within the window. */
static void test_exact_duplicate_is_retransmission(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    seg(&ctx, 1.0000, 40000, 1000, 100);
    seg(&ctx, 1.0010, 40000, 1100, 100);
    seg(&ctx, 1.0012, 40000, 1100, 100); /* dup 0.2 ms later: no hole */
    CHECK(only_flow(&ctx)->retransmissions == 1);
    seg(&ctx, 1.0110, 40000, 1000, 100); /* dup 10 ms later */
    CHECK(only_flow(&ctx)->retransmissions == 2);

    /* Duplicate of the segment that opened a hole is not a hole fill. */
    seg(&ctx, 2.0000, 40000, 1300, 100);  /* hole [1200, 1300) */
    seg(&ctx, 2.0001, 40000, 1300, 100);  /* dup                -> retrans */
    seg(&ctx, 2.0002, 40000, 1200, 100);  /* fill               -> ooo     */
    const flow_stats_t *f = only_flow(&ctx);
    CHECK(f->retransmissions == 3);
    CHECK(f->out_of_order == 1);
    CHECK(ctx.tcp_retransmissions == 3 && ctx.tcp_out_of_order == 1);
    stats_free(&ctx);
}

/* H6: a hole filled after the window is a real (loss) retransmission. */
static void test_late_hole_fill_is_retransmission(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    seg(&ctx, 2.0000, 40000, 1000, 100);
    seg(&ctx, 2.0000, 40000, 1200, 100); /* hole [1100, 1200) at t=2.0 */
    seg(&ctx, 2.0025, 40000, 1100, 50);  /* 2.5 ms: ooo, hole [1150,1200) */
    CHECK(only_flow(&ctx)->out_of_order == 1);
    seg(&ctx, 2.0035, 40000, 1150, 50);  /* 3.5 ms: window over -> retrans */
    const flow_stats_t *f = only_flow(&ctx);
    CHECK(f->out_of_order == 1);
    CHECK(f->retransmissions == 1);
    CHECK(!f->has_hole);

    /* Classic loss: RTO retransmission 200 ms later. */
    seg(&ctx, 3.0000, 40000, 1400, 100); /* hole [1300, 1400) */
    seg(&ctx, 3.2000, 40000, 1300, 100);
    CHECK(f->retransmissions == 2 && f->out_of_order == 1);
    check_global_seq_counters(&ctx);
    stats_free(&ctx);
}

/* H6: multi-segment holes filled in any order within the window. */
static void test_multi_segment_hole_fills(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    /* Reverse fill: A E D C B -> hole [100,400) shrinks from both ends. */
    seg(&ctx, 1.0000, 40000, 0, 100);
    seg(&ctx, 1.0001, 40000, 400, 100);
    seg(&ctx, 1.0002, 40000, 300, 100); /* end edge   -> [100,300) */
    seg(&ctx, 1.0003, 40000, 100, 100); /* start edge -> [200,300) */
    seg(&ctx, 1.0004, 40000, 200, 100); /* closes the hole */
    const flow_stats_t *f = only_flow(&ctx);
    CHECK(f->out_of_order == 3 && f->retransmissions == 0);
    CHECK(!f->has_hole);

    /* Middle fill first: F J H G I. */
    seg(&ctx, 2.0000, 40000, 500, 100);
    seg(&ctx, 2.0001, 40000, 900, 100); /* hole [600,900) */
    seg(&ctx, 2.0002, 40000, 700, 100); /* middle: hole unchanged */
    seg(&ctx, 2.0003, 40000, 600, 100);
    seg(&ctx, 2.0004, 40000, 800, 100);
    CHECK(f->out_of_order == 6 && f->retransmissions == 0);
    seg(&ctx, 2.0500, 40000, 700, 100); /* dup after window */
    CHECK(f->retransmissions == 1);

    /* Second gap while a hole is open: one interval covers both. */
    seg(&ctx, 3.0000, 40000, 1000, 100);
    seg(&ctx, 3.0001, 40000, 1200, 100); /* hole [1100,1200) */
    seg(&ctx, 3.0002, 40000, 1400, 100); /* extended to [1100,1400) */
    seg(&ctx, 3.0003, 40000, 1100, 100);
    seg(&ctx, 3.0004, 40000, 1300, 100);
    CHECK(f->out_of_order == 8 && f->retransmissions == 1);
    CHECK(f->next_seq == 1500);
    check_global_seq_counters(&ctx);
    stats_free(&ctx);
}

/* H6: reordering across the 2^32 sequence wrap. */
static void test_out_of_order_across_seq_wrap(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    seg(&ctx, 1.0000, 40000, 0xFFFFFF00u, 0x80); /* -> next 0xFFFFFF80 */
    seg(&ctx, 1.0001, 40000, 0x00000000u, 0x80); /* hole [..FF80, 0) */
    seg(&ctx, 1.0002, 40000, 0xFFFFFF80u, 0x80); /* ends exactly at 0 */
    const flow_stats_t *f = only_flow(&ctx);
    CHECK(f->out_of_order == 1 && f->retransmissions == 0);
    CHECK(!f->has_hole && f->next_seq == 0x80u);
    seg(&ctx, 1.0100, 40000, 0xFFFFFF00u, 0x80); /* behind across wrap */
    CHECK(f->retransmissions == 1);
    seg(&ctx, 1.0200, 40000, 0x00000080u, 0x80); /* in order */
    CHECK(f->retransmissions == 1 && f->out_of_order == 1);
    CHECK(f->next_seq == 0x100u);
    stats_free(&ctx);
}

/* A repacketized retransmission (old + new bytes) counts once and moves
 * next_seq forward, so the following segment is new data. */
static void test_partial_overlap_is_retransmission(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    seg(&ctx, 1.000, 40000, 1000, 100);
    seg(&ctx, 1.001, 40000, 1100, 100);
    seg(&ctx, 1.200, 40000, 1150, 100); /* 1150..1250 overlaps 1150..1200 */
    const flow_stats_t *f = only_flow(&ctx);
    CHECK(f->retransmissions == 1);
    CHECK(f->next_seq == 1250);
    seg(&ctx, 1.201, 40000, 1250, 100);
    CHECK(f->retransmissions == 1 && f->out_of_order == 0);
    stats_free(&ctx);
}

/* H5: global counters cover every flow (the report summed only the
 * top-128 flows) and equal the per-flow sums. */
static void test_global_tcp_counters_cover_all_flows(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    /* 200 flows, each: 1 retransmission + 1 out-of-order segment. */
    for (uint16_t s = 0; s < 200; ++s) {
        uint16_t sport = (uint16_t)(30000 + s);
        double t = 1.0 + s;
        seg(&ctx, t, sport, 0, 100);
        seg(&ctx, t + 0.0001, sport, 200, 100); /* hole [100,200) */
        seg(&ctx, t + 0.0002, sport, 100, 100); /* ooo */
        seg(&ctx, t + 0.5000, sport, 0, 100);   /* retrans */
    }
    /* UDP and zero-payload TCP never count. */
    send_pkt(&ctx, net_pkt(500.0, IPPROTO_UDP, 1, 2, 5000, 53, 0, 60));
    parsed_packet_t p = tcp_data(501.0, 0);
    p.src_port = 30000;
    p.payload_len = 0;
    send_pkt(&ctx, p);

    CHECK(ht_count(ctx.flows_ht) == 201);
    CHECK(ctx.tcp_retransmissions == 200);
    CHECK(ctx.tcp_out_of_order == 200);
    check_global_seq_counters(&ctx);
    const flow_stats_t *f = flow_by_sport(&ctx, 30199);
    CHECK(f != NULL && f->retransmissions == 1 && f->out_of_order == 1);

    const flow_stats_t *top[128];
    uint64_t top_sum = 0;
    size_t n = stats_top_flows(&ctx, top, 128);
    for (size_t i = 0; i < n; ++i)
        top_sum += top[i]->retransmissions;
    CHECK(top_sum < ctx.tcp_retransmissions); /* why the global exists */
    stats_free(&ctx);
}

#define RUN(t)                   \
    do {                         \
        printf("  %s...\n", #t); \
        t();                     \
        printf("    PASS\n");    \
    } while (0)

int main(void)
{
    RUN(test_basic_stats);
    RUN(test_downsampling_and_zero_duration);
    RUN(test_null_args);
    RUN(test_histogram_boundaries);
    RUN(test_tcp_flag_counters);
    RUN(test_malformed_and_other);
    RUN(test_category_invariant);
    RUN(test_non_ip_frames_classified);
    RUN(test_fragments_skip_l4);
    RUN(test_first_fragment_still_counted);
    RUN(test_timeline_contents_and_order);
    RUN(test_sparse_far_apart);
    RUN(test_non_finite_timestamps);
    RUN(test_downsampling_preserves_totals_and_burst);
    RUN(test_span_with_gaps);
    RUN(test_finalize_empty_and_repeat);

    RUN(test_host_counters_and_port_bitmap);
    RUN(test_udp_scan_tracking);
    RUN(test_udp_server_replies_are_not_scans);
    RUN(test_scan_ports_shared_between_tcp_and_udp);
    RUN(test_retransmission_seq_wraparound);
    RUN(test_unsorted_48h_and_retransmission);
    RUN(test_top_n_bytes_vs_packets_and_ties);
    RUN(test_service_names);
    RUN(test_demo_hosts_ports_flows);

    RUN(test_avg_bps_is_bits_per_second);
    RUN(test_receive_only_host_has_no_port_storage);
    RUN(test_port_set_promotion_exact);
    RUN(test_port_set_full_sweep);
    RUN(test_sub_ms_swaps_are_out_of_order);
    RUN(test_exact_duplicate_is_retransmission);
    RUN(test_late_hole_fill_is_retransmission);
    RUN(test_multi_segment_hole_fills);
    RUN(test_out_of_order_across_seq_wrap);
    RUN(test_partial_overlap_is_retransmission);
    RUN(test_global_tcp_counters_cover_all_flows);
    return 0;
}