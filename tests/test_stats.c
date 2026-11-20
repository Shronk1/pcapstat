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

static void test_histogram_boundaries(void)
{
    static const struct {
        uint32_t size;
        int bin;
    } cases[] = {
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
    CHECK(ctx.tcp_packets + ctx.udp_packets + ctx.other_packets +
              ctx.malformed_packets == ctx.total_packets);
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

    struct {
        double ts;
        uint32_t seq;
    } in[] = {
        {1.0, 100},      /* new: max=100, last_seq_ts=1.0            */
        {172800.0, 100}, /* same seq, later ts          -> retrans 1 */
        {90000.0, 99},   /* older seq, later than 1.0   -> retrans 2 */
        {172800.0, 200}, /* ahead: max=200, last_seq_ts=172800       */
        {100.0, 150},    /* ts < last_seq_ts: NOT retrans, rebase    */
    };
    for (size_t i = 0; i < sizeof(in) / sizeof(in[0]); ++i) {
        parsed_packet_t p = tcp_data(in[i].ts, in[i].seq);
        CHECK(stats_update(&ctx, &p) == PCAPSTAT_OK);
    }

    const flow_stats_t *f = only_flow(&ctx);
    CHECK(f->packets == 5);
    CHECK(f->retransmissions == 2);
    CHECK(f->first_ts == 1.0 && f->last_ts == 172800.0);
    CHECK(f->max_seq == 150); /* documented: base follows the rebase */

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
    CHECK(strcmp(stats_port_service_name(IPPROTO_UDP, 9999), "UDP-Data") == 0);
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

    uint64_t retransmissions = 0;
    uint64_t max_pkts = 0;
    ht_iter_t it = ht_iter_begin(ctx.flows_ht);
    const void *key;
    size_t key_len;
    void *value;
    while (ht_iter_next(&it, &key, &key_len, &value)) {
        const flow_stats_t *flow = (const flow_stats_t *)value;
        retransmissions += flow->retransmissions;
        if (flow->packets > max_pkts)
            max_pkts = flow->packets;
    }
    CHECK(retransmissions > 0);

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
    return 0;
}