/**
 * @file test_anomaly.c
 * @brief Unit and integration tests for network anomaly detection (TASK-08).
 */

#include "anomaly.h"
#include "parser.h"
#include "stats.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(c)                                                               \
    do {                                                                       \
        if (!(c)) {                                                            \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__,   \
                    #c);                                                       \
            abort();                                                           \
        }                                                                      \
    } while (0)

#define RUN(t)                                                                 \
    do {                                                                       \
        printf("  %s...\n", #t);                                               \
        t();                                                                   \
        printf("    PASS\n");                                                  \
    } while (0)

/* ---- Packet creation helpers ---- */

static parsed_packet_t make_raw_pkt(double ts, uint32_t len, uint8_t proto)
{
    parsed_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.timestamp = ts;
    pkt.wire_len = len;
    pkt.cap_len = len;
    pkt.proto = proto;
    return pkt;
}

static parsed_packet_t make_ipv4_pkt(double ts, uint8_t proto, uint8_t src,
                                     uint8_t dst, uint16_t sp, uint16_t dp,
                                     uint8_t flags, uint32_t len)
{
    parsed_packet_t p = make_raw_pkt(ts, len, proto);
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

static void send_pkt(stats_ctx_t *ctx, parsed_packet_t p)
{
    CHECK(stats_update(ctx, &p) == PCAPSTAT_OK);
}

/* Helper to find an anomaly by category and subject */
static const anomaly_t *find_anomaly(const anomaly_list_t *list,
                                     const char *category, const char *subject)
{
    for (size_t i = 0; i < list->count; ++i) {
        if (strcmp(list->items[i].category, category) == 0) {
            if (subject == NULL || strcmp(list->items[i].subject, subject) == 0)
                return &list->items[i];
        }
    }
    return NULL;
}

/* Number of anomalies in @p category */
static size_t count_category(const anomaly_list_t *list, const char *category)
{
    size_t n = 0;
    for (size_t i = 0; i < list->count; ++i)
        if (strcmp(list->items[i].category, category) == 0)
            n++;
    return n;
}

/* ---- Tests ---- */

static void test_anomaly_list_lifecycle(void)
{
    CHECK(anomaly_list_init(NULL) == PCAPSTAT_ERR_ARGS);
    anomaly_list_free(NULL);

    anomaly_list_t list;
    CHECK(anomaly_list_init(&list) == PCAPSTAT_OK);
    CHECK(list.count == 0 && list.capacity == 0 && list.items == NULL);

    anomaly_t a;
    memset(&a, 0, sizeof(a));
    a.severity = ANOMALY_WARNING;
    snprintf(a.category, sizeof(a.category), "TestCat");
    snprintf(a.subject, sizeof(a.subject), "TestSubj");
    snprintf(a.description, sizeof(a.description), "TestDesc");

    CHECK(anomaly_list_append(NULL, &a) == PCAPSTAT_ERR_ARGS);
    CHECK(anomaly_list_append(&list, NULL) == PCAPSTAT_ERR_ARGS);

    /* Append multiple to trigger dynamic resizing */
    for (int i = 0; i < 20; ++i) {
        CHECK(anomaly_list_append(&list, &a) == PCAPSTAT_OK);
        CHECK(list.count == (size_t)(i + 1));
        CHECK(list.capacity >= list.count);
    }

    CHECK(strcmp(anomaly_severity_str(ANOMALY_CRITICAL), "CRITICAL") == 0);
    CHECK(strcmp(anomaly_severity_str(ANOMALY_WARNING), "WARNING") == 0);
    CHECK(strcmp(anomaly_severity_str(ANOMALY_INFO), "INFO") == 0);
    CHECK(strcmp(anomaly_severity_str((anomaly_severity_t)99), "UNKNOWN") == 0);

    anomaly_list_free(&list);
    CHECK(list.count == 0 && list.capacity == 0 && list.items == NULL);
}

static void test_null_and_empty_args(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);
    anomaly_list_t list;
    CHECK(anomaly_list_init(&list) == PCAPSTAT_OK);

    CHECK(anomaly_detect(NULL, NULL, &list) == PCAPSTAT_ERR_ARGS);
    CHECK(anomaly_detect(&ctx, NULL, NULL) == PCAPSTAT_ERR_ARGS);

    /* Empty stats: zero anomalies */
    CHECK(anomaly_detect(&ctx, NULL, &list) == PCAPSTAT_OK);
    CHECK(list.count == 0);

    anomaly_list_free(&list);
    stats_free(&ctx);
}

static void test_clean_traffic(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    /* 1. Normal TCP handshake: client (10.0.0.1:50000) -> server (10.0.0.2:443) */
    send_pkt(&ctx, make_ipv4_pkt(1.000, IPPROTO_TCP, 1, 2, 50000, 443, TH_SYN, 60));
    send_pkt(&ctx, make_ipv4_pkt(1.001, IPPROTO_TCP, 2, 1, 443, 50000, TH_SYN | TH_ACK, 60));
    send_pkt(&ctx, make_ipv4_pkt(1.002, IPPROTO_TCP, 1, 2, 50000, 443, TH_ACK, 54));

    /* 2. Normal TCP data transfer with progressive seq numbers (no retransmissions) */
    for (uint32_t i = 0; i < 5; ++i) {
        parsed_packet_t p = make_ipv4_pkt(1.010 + 0.005 * i, IPPROTO_TCP, 1, 2,
                                          50000, 443, TH_ACK | TH_PUSH, 150);
        p.payload_len = 100;
        p.tcp_seq = 1000 + i * 100;
        send_pkt(&ctx, p);
    }

    /* 3. Normal TCP teardown (FIN) */
    send_pkt(&ctx, make_ipv4_pkt(1.050, IPPROTO_TCP, 1, 2, 50000, 443, TH_FIN | TH_ACK, 54));
    send_pkt(&ctx, make_ipv4_pkt(1.051, IPPROTO_TCP, 2, 1, 443, 50000, TH_FIN | TH_ACK, 54));

    /* 4. Normal UDP request/reply (DNS :53, NTP :123) */
    send_pkt(&ctx, make_ipv4_pkt(1.100, IPPROTO_UDP, 1, 2, 53000, 53, 0, 70));
    send_pkt(&ctx, make_ipv4_pkt(1.105, IPPROTO_UDP, 2, 1, 53, 53000, 0, 120));
    send_pkt(&ctx, make_ipv4_pkt(2.000, IPPROTO_UDP, 1, 2, 53001, 123, 0, 76));
    send_pkt(&ctx, make_ipv4_pkt(2.010, IPPROTO_UDP, 2, 1, 123, 53001, 0, 76));

    CHECK(stats_finalize(&ctx) == PCAPSTAT_OK);

    anomaly_list_t list;
    CHECK(anomaly_list_init(&list) == PCAPSTAT_OK);
    CHECK(anomaly_detect(&ctx, NULL, &list) == PCAPSTAT_OK);

    /* Must have zero warnings and zero criticals */
    for (size_t i = 0; i < list.count; ++i) {
        CHECK(list.items[i].severity != ANOMALY_CRITICAL);
        CHECK(list.items[i].severity != ANOMALY_WARNING);
    }
    CHECK(list.count == 0);

    anomaly_list_free(&list);
    stats_free(&ctx);
}

static void test_demo_pcap_anomalies(void)
{
    FILE *f = fopen("samples/demo.pcap", "rb");
    if (f == NULL) {
        printf("    SKIP (samples/demo.pcap not found; run from repo root)\n");
        return;
    }
    fclose(f);

    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);
    CHECK(parser_process_file("samples/demo.pcap", stats_packet_cb, &ctx) ==
          PCAPSTAT_OK);
    CHECK(stats_finalize(&ctx) == PCAPSTAT_OK);

    anomaly_list_t list;
    CHECK(anomaly_list_init(&list) == PCAPSTAT_OK);
    CHECK(anomaly_detect(&ctx, NULL, &list) == PCAPSTAT_OK);

    /* Exactly the 6 findings checked below (no SYN Flood, no extra bursts). */
    CHECK(list.count == 6);

    /* Verify sorting: CRITICAL -> WARNING -> INFO */
    for (size_t i = 1; i < list.count; ++i) {
        CHECK(list.items[i - 1].severity >= list.items[i].severity);
    }

    /* 1. Port Scan: host 10.0.0.100 scanned 25 unique destination ports */
    const anomaly_t *ps = find_anomaly(&list, "Port Scan", "10.0.0.100");
    CHECK(ps != NULL);
    CHECK(ps->severity == ANOMALY_CRITICAL);
    CHECK(strstr(ps->description, "25") != NULL);

    /* 2. Xmas Scan: FIN+PSH+URG packet */
    const anomaly_t *xmas = find_anomaly(&list, "Suspicious TCP Flags", "Xmas Scan");
    CHECK(xmas != NULL);
    CHECK(xmas->severity == ANOMALY_CRITICAL);

    /* 3. Null Scan: flags == 0 */
    const anomaly_t *null_scan = find_anomaly(&list, "Suspicious TCP Flags", "Null Scan");
    CHECK(null_scan != NULL);
    CHECK(null_scan->severity == ANOMALY_CRITICAL);

    /* 4. TCP Retransmissions: global rate (3 retrans / 55 TCP pkts = 5.45% > 5%) */
    const anomaly_t *ret = find_anomaly(&list, "TCP Retransmissions", "Global");
    CHECK(ret != NULL);
    CHECK(ret->severity == ANOMALY_WARNING);

    /* 5. UDP Burst: 120 pkts in single second window (sec 1704067202).
     * FIX-04: the subject is the UTC start time instead of the raw epoch
     * ("Second 1704067202"); one second -> "lasted 1 s". */
    const anomaly_t *burst = find_anomaly(&list, "UDP Burst",
                                          "2024-01-01 00:00:02 UTC");
    CHECK(burst != NULL);
    CHECK(burst->severity == ANOMALY_WARNING);
    CHECK(strstr(burst->description, "120") != NULL);
    CHECK(strstr(burst->description, "lasted 1 s") != NULL);

    /* 6. Malformed Packets: 2 malformed frames in demo.pcap */
    const anomaly_t *mal = find_anomaly(&list, "Malformed Packets", "Global");
    CHECK(mal != NULL);
    CHECK(mal->severity == ANOMALY_WARNING);
    CHECK(strstr(mal->description, "2") != NULL);

    anomaly_list_free(&list);
    stats_free(&ctx);
}

static void test_port_scan_threshold_override(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    /* Host 10.0.0.5 probes 15 distinct ports */
    for (uint16_t port = 1000; port < 1015; ++port) {
        send_pkt(&ctx, make_ipv4_pkt(1.0, IPPROTO_TCP, 5, 2, 40000, port, TH_SYN, 60));
    }

    anomaly_list_t list;
    CHECK(anomaly_list_init(&list) == PCAPSTAT_OK);

    /* Default threshold is 20: 15 ports should NOT trigger */
    CHECK(anomaly_detect(&ctx, NULL, &list) == PCAPSTAT_OK);
    CHECK(find_anomaly(&list, "Port Scan", "10.0.0.5") == NULL);
    anomaly_list_free(&list);

    /* Custom threshold 10: 15 ports SHOULD trigger */
    anomaly_thresholds_t custom = ANOMALY_THRESHOLDS_DEFAULT;
    custom.portscan_threshold = 10;
    CHECK(anomaly_list_init(&list) == PCAPSTAT_OK);
    CHECK(anomaly_detect(&ctx, &custom, &list) == PCAPSTAT_OK);
    const anomaly_t *ps = find_anomaly(&list, "Port Scan", "10.0.0.5");
    CHECK(ps != NULL);
    CHECK(ps->severity == ANOMALY_CRITICAL);

    anomaly_list_free(&list);
    stats_free(&ctx);
}

static void test_syn_flood_heuristics(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    /* Case A: Host 10.0.0.10 sends 60 SYNs and receives 0 SYN-ACKs (ratio > 3.0) */
    for (int i = 0; i < 60; ++i) {
        send_pkt(&ctx, make_ipv4_pkt(1.0 + 0.01 * i, IPPROTO_TCP, 10, 20,
                                     (uint16_t)(30000 + i), 80, TH_SYN, 60));
    }

    /* Case B: Host 10.0.0.11 sends 60 SYNs and receives 50 SYN-ACKs (ratio 1.2 <= 3.0) */
    for (int i = 0; i < 60; ++i) {
        send_pkt(&ctx, make_ipv4_pkt(1.0 + 0.01 * i, IPPROTO_TCP, 11, 20,
                                     (uint16_t)(40000 + i), 80, TH_SYN, 60));
        if (i < 50) {
            send_pkt(&ctx, make_ipv4_pkt(1.0 + 0.01 * i + 0.001, IPPROTO_TCP, 20,
                                         11, 80, (uint16_t)(40000 + i),
                                         TH_SYN | TH_ACK, 60));
        }
    }

    anomaly_list_t list;
    CHECK(anomaly_list_init(&list) == PCAPSTAT_OK);
    CHECK(anomaly_detect(&ctx, NULL, &list) == PCAPSTAT_OK);

    /* 10.0.0.10 must be flagged */
    const anomaly_t *sf10 = find_anomaly(&list, "SYN Flood", "10.0.0.10");
    CHECK(sf10 != NULL);
    CHECK(sf10->severity == ANOMALY_CRITICAL);

    /* 10.0.0.11 must NOT be flagged */
    const anomaly_t *sf11 = find_anomaly(&list, "SYN Flood", "10.0.0.11");
    CHECK(sf11 == NULL);

    anomaly_list_free(&list);
    stats_free(&ctx);
}

static void test_tcp_retransmissions_per_flow(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    /* Flow 1: 30 packets with 5 retransmissions (5/30 = 16.67% > 5%) */
    for (int i = 0; i < 25; ++i) {
        parsed_packet_t p = make_ipv4_pkt(1.0 + 0.01 * i, IPPROTO_TCP, 1, 2,
                                          50000, 443, TH_ACK, 100);
        p.payload_len = 50;
        p.tcp_seq = 1000 + i * 50;
        send_pkt(&ctx, p);
    }
    for (int i = 0; i < 5; ++i) {
        parsed_packet_t p = make_ipv4_pkt(2.0 + 0.01 * i, IPPROTO_TCP, 1, 2,
                                          50000, 443, TH_ACK, 100);
        p.payload_len = 50;
        p.tcp_seq = 1500; /* repeat seq in the past -> retransmission */
        send_pkt(&ctx, p);
    }

    anomaly_list_t list;
    CHECK(anomaly_list_init(&list) == PCAPSTAT_OK);
    CHECK(anomaly_detect(&ctx, NULL, &list) == PCAPSTAT_OK);

    const anomaly_t *f_ret = find_anomaly(&list, "TCP Retransmissions",
                                          "10.0.0.1:50000 -> 10.0.0.2:443 (TCP)");
    CHECK(f_ret != NULL);
    CHECK(f_ret->severity == ANOMALY_WARNING);

    anomaly_list_free(&list);
    stats_free(&ctx);
}

static void test_rst_spike_detection(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    /* 50 normal TCP packets */
    for (int i = 0; i < 50; ++i) {
        send_pkt(&ctx, make_ipv4_pkt(1.0 + 0.01 * i, IPPROTO_TCP, 1, 2,
                                     50000, 80, TH_ACK, 60));
    }
    /* 10 RST packets: total 60 pkts (>= 30), RST rate = 10/60 = 16.67% > 10% */
    for (int i = 0; i < 10; ++i) {
        send_pkt(&ctx, make_ipv4_pkt(2.0 + 0.01 * i, IPPROTO_TCP, 2, 1,
                                     80, 50000, TH_RST, 60));
    }

    anomaly_list_t list;
    CHECK(anomaly_list_init(&list) == PCAPSTAT_OK);
    CHECK(anomaly_detect(&ctx, NULL, &list) == PCAPSTAT_OK);

    const anomaly_t *rst = find_anomaly(&list, "RST Spike", "Global");
    CHECK(rst != NULL);
    CHECK(rst->severity == ANOMALY_WARNING);

    anomaly_list_free(&list);
    stats_free(&ctx);
}

static void test_suspicious_tcp_flag_variants(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    /* Conflicting SYN+FIN */
    send_pkt(&ctx, make_ipv4_pkt(1.0, IPPROTO_TCP, 1, 2, 50000, 80,
                                 TH_SYN | TH_FIN, 60));

    /* Conflicting SYN+RST */
    send_pkt(&ctx, make_ipv4_pkt(1.1, IPPROTO_TCP, 1, 2, 50001, 80,
                                 TH_SYN | TH_RST, 60));

    anomaly_list_t list;
    CHECK(anomaly_list_init(&list) == PCAPSTAT_OK);
    CHECK(anomaly_detect(&ctx, NULL, &list) == PCAPSTAT_OK);

    const anomaly_t *syn_fin = find_anomaly(&list, "Suspicious TCP Flags", "SYN+FIN");
    CHECK(syn_fin != NULL);
    CHECK(syn_fin->severity == ANOMALY_CRITICAL);

    const anomaly_t *syn_rst = find_anomaly(&list, "Suspicious TCP Flags", "SYN+RST");
    CHECK(syn_rst != NULL);
    CHECK(syn_rst->severity == ANOMALY_CRITICAL);

    anomaly_list_free(&list);
    stats_free(&ctx);
}

static void test_udp_burst_boundary(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    /* 4 one-second windows */
    /* Sec 100: 5 pkts */
    for (int i = 0; i < 5; ++i)
        send_pkt(&ctx, make_ipv4_pkt(100.1 + 0.1 * i, IPPROTO_UDP, 1, 2, 5000, 9999, 0, 50));
    /* Sec 101: 5 pkts */
    for (int i = 0; i < 5; ++i)
        send_pkt(&ctx, make_ipv4_pkt(101.1 + 0.1 * i, IPPROTO_UDP, 1, 2, 5000, 9999, 0, 50));
    /* Sec 102: 5 pkts */
    for (int i = 0; i < 5; ++i)
        send_pkt(&ctx, make_ipv4_pkt(102.1 + 0.1 * i, IPPROTO_UDP, 1, 2, 5000, 9999, 0, 50));
    /* Sec 103: 100 pkts (leave-one-out baseline = 15 / 3 = 5, 3x = 15;
     * pkts = 100 >= 100 absolute minimum) */
    for (int i = 0; i < 100; ++i)
        send_pkt(&ctx, make_ipv4_pkt(103.0 + 0.008 * i, IPPROTO_UDP, 1, 2, 5000, 9999, 0, 50));

    CHECK(stats_finalize(&ctx) == PCAPSTAT_OK);

    anomaly_list_t list;
    CHECK(anomaly_list_init(&list) == PCAPSTAT_OK);
    CHECK(anomaly_detect(&ctx, NULL, &list) == PCAPSTAT_OK);

    /* Epoch second 103 = 1970-01-01 00:01:43 UTC */
    const anomaly_t *burst = find_anomaly(&list, "UDP Burst",
                                          "1970-01-01 00:01:43 UTC");
    CHECK(burst != NULL);
    CHECK(burst->severity == ANOMALY_WARNING);
    CHECK(count_category(&list, "UDP Burst") == 1);

    anomaly_list_free(&list);

    /* Absolute minimum: raising it to 101 suppresses the 100-pkt second. */
    anomaly_thresholds_t custom = ANOMALY_THRESHOLDS_DEFAULT;
    custom.udp_burst_min = 101;
    CHECK(anomaly_list_init(&list) == PCAPSTAT_OK);
    CHECK(anomaly_detect(&ctx, &custom, &list) == PCAPSTAT_OK);
    CHECK(count_category(&list, "UDP Burst") == 0);
    anomaly_list_free(&list);

    stats_free(&ctx);
}

/* Multiplier boundary: the check is strict (b > mult * baseline). */
static void test_udp_burst_multiplier_boundary(void)
{
    for (int extra = 0; extra <= 1; ++extra) {
        stats_ctx_t ctx;
        CHECK(stats_init(&ctx) == PCAPSTAT_OK);

        /* 3 seconds x 50 pkts: baseline for the 4th second = 150 / 3 = 50 */
        for (int s = 0; s < 3; ++s)
            for (int i = 0; i < 50; ++i)
                send_pkt(&ctx, make_ipv4_pkt(200.0 + s + 0.01 * i, IPPROTO_UDP,
                                             1, 2, 5000, 9999, 0, 50));
        /* 4th second: 150 pkts (== 3 x 50, not flagged) or 151 (flagged) */
        for (int i = 0; i < 150 + extra; ++i)
            send_pkt(&ctx, make_ipv4_pkt(203.0 + 0.005 * i, IPPROTO_UDP, 1, 2,
                                         5000, 9999, 0, 50));

        anomaly_list_t list;
        CHECK(anomaly_list_init(&list) == PCAPSTAT_OK);
        CHECK(anomaly_detect(&ctx, NULL, &list) == PCAPSTAT_OK);
        CHECK(count_category(&list, "UDP Burst") == (size_t)extra);
        if (extra) {
            const anomaly_t *b = find_anomaly(&list, "UDP Burst",
                                              "1970-01-01 00:03:23 UTC");
            CHECK(b != NULL);
            CHECK(strstr(b->description, "peak 151 pkt/s") != NULL);
            CHECK(strstr(b->description, "baseline 50.0 pkt/s") != NULL);
        }
        anomaly_list_free(&list);
        stats_free(&ctx);
    }
}

/* H7 regression: a short burst in quiet traffic. With the old global mean
 * (1010 / 3 = 336.7, 3x = 1010) the 1000-pkt second was never flagged. */
static void test_udp_short_burst_detected(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    /* Sec 1000: 1000 UDP pkts; secs 1001, 1002: 5 UDP pkts each */
    for (int i = 0; i < 1000; ++i)
        send_pkt(&ctx, make_ipv4_pkt(1000.0 + 0.0009 * i, IPPROTO_UDP, 1, 2,
                                     5000, 7777, 0, 60));
    for (int s = 1; s <= 2; ++s)
        for (int i = 0; i < 5; ++i)
            send_pkt(&ctx, make_ipv4_pkt(1000.0 + s + 0.1 * i, IPPROTO_UDP, 1,
                                         2, 5000, 7777, 0, 60));

    anomaly_list_t list;
    CHECK(anomaly_list_init(&list) == PCAPSTAT_OK);
    CHECK(anomaly_detect(&ctx, NULL, &list) == PCAPSTAT_OK);

    CHECK(list.count == 1);
    CHECK(count_category(&list, "UDP Burst") == 1);
    /* Epoch second 1000 = 1970-01-01 00:16:40 UTC */
    const anomaly_t *b = find_anomaly(&list, "UDP Burst",
                                      "1970-01-01 00:16:40 UTC");
    CHECK(b != NULL);
    CHECK(b->severity == ANOMALY_WARNING);
    CHECK(strstr(b->description, "lasted 1 s") != NULL);
    CHECK(strstr(b->description, "peak 1000 pkt/s") != NULL);
    /* Leave-one-out baseline: (1010 - 1000) / 2 = 5.0 */
    CHECK(strstr(b->description, "baseline 5.0 pkt/s") != NULL);

    anomaly_list_free(&list);
    stats_free(&ctx);
}

/* Fill [first_sec, first_sec + nsec) with @p per_sec UDP pkts each. */
static void send_udp_seconds(stats_ctx_t *ctx, int64_t first_sec, int nsec,
                             int per_sec)
{
    for (int s = 0; s < nsec; ++s)
        for (int i = 0; i < per_sec; ++i)
            send_pkt(ctx, make_ipv4_pkt((double)(first_sec + s) +
                                            (double)i / (double)(per_sec + 1),
                                        IPPROTO_UDP, 1, 2, 5000, 7777, 0, 60));
}

/* M5 regression: 5 consecutive burst seconds -> exactly one finding. */
static void test_udp_burst_consecutive_merged(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    /* 2024-01-01 00:00:00 UTC = 1704067200. Quiet 10 s, burst 5 s
     * (peak in the 3rd second), quiet 10 s. */
    const int64_t t0 = 1704067200;
    send_udp_seconds(&ctx, t0, 10, 5);
    send_udp_seconds(&ctx, t0 + 10, 2, 1000);
    send_udp_seconds(&ctx, t0 + 12, 1, 1500);
    send_udp_seconds(&ctx, t0 + 13, 2, 1000);
    send_udp_seconds(&ctx, t0 + 15, 10, 5);

    anomaly_list_t list;
    CHECK(anomaly_list_init(&list) == PCAPSTAT_OK);
    CHECK(anomaly_detect(&ctx, NULL, &list) == PCAPSTAT_OK);

    CHECK(list.count == 1);
    const anomaly_t *b = find_anomaly(&list, "UDP Burst",
                                      "2024-01-01 00:00:10 UTC");
    CHECK(b != NULL);
    CHECK(b->severity == ANOMALY_WARNING);
    CHECK(strstr(b->description, "lasted 5 s") != NULL);
    CHECK(strstr(b->description, "5500 UDP pkts") != NULL);
    CHECK(strstr(b->description, "peak 1500 pkt/s") != NULL);
    /* Peak second's baseline: (100 + 4000) / 24 = 170.8 */
    CHECK(strstr(b->description, "baseline 170.8 pkt/s") != NULL);
    CHECK(strstr(b->description, "> 3.0x baseline and >= 100 pkt/s") != NULL);
    CHECK(strlen(b->description) < sizeof(b->description) - 1);

    anomaly_list_free(&list);
    stats_free(&ctx);
}

/* Separate (non-adjacent) bursts stay separate findings, in time order. */
static void test_udp_burst_separate_runs(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    /* Inserted out of order on purpose; the hash table is unordered. */
    send_udp_seconds(&ctx, 1730, 3, 1000); /* burst B: 1730..1732 */
    send_udp_seconds(&ctx, 0, 20, 5);      /* quiet: 0..19 */
    send_udp_seconds(&ctx, 1700, 1, 900);  /* burst A: 1700 */
    send_udp_seconds(&ctx, 1702, 1, 900);  /* burst C: 1702 (gap at 1701) */
    send_udp_seconds(&ctx, 2000, 20, 5);   /* quiet: 2000..2019 */

    anomaly_list_t list;
    CHECK(anomaly_list_init(&list) == PCAPSTAT_OK);
    CHECK(anomaly_detect(&ctx, NULL, &list) == PCAPSTAT_OK);

    CHECK(list.count == 3);
    /* Sorted by subject, which is chronological for this format. */
    CHECK(strcmp(list.items[0].subject, "1970-01-01 00:28:20 UTC") == 0);
    CHECK(strstr(list.items[0].description, "lasted 1 s") != NULL);
    CHECK(strcmp(list.items[1].subject, "1970-01-01 00:28:22 UTC") == 0);
    CHECK(strstr(list.items[1].description, "lasted 1 s") != NULL);
    CHECK(strcmp(list.items[2].subject, "1970-01-01 00:28:50 UTC") == 0);
    CHECK(strstr(list.items[2].description, "lasted 3 s") != NULL);

    anomaly_list_free(&list);
    stats_free(&ctx);
}

/* A capture that is entirely a constant flood has no quiet baseline and is
 * not flagged (documented limitation, matches udp_flood_3s.pcap). A single
 * active second has baseline 0, so only the absolute minimum applies. */
static void test_udp_flood_without_baseline(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);
    send_udp_seconds(&ctx, 500, 3, 2000);

    anomaly_list_t list;
    CHECK(anomaly_list_init(&list) == PCAPSTAT_OK);
    CHECK(anomaly_detect(&ctx, NULL, &list) == PCAPSTAT_OK);
    CHECK(count_category(&list, "UDP Burst") == 0);
    anomaly_list_free(&list);
    stats_free(&ctx);

    /* Owner decision (FIX-06): a capture with a single active second has
     * no baseline, so even 100 000 UDP pkt/s produce no UDP Burst finding
     * (FIX-04 flagged it against a 0.0 baseline). */
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);
    send_udp_seconds(&ctx, 500, 1, 100);
    CHECK(anomaly_list_init(&list) == PCAPSTAT_OK);
    CHECK(anomaly_detect(&ctx, NULL, &list) == PCAPSTAT_OK);
    CHECK(count_category(&list, "UDP Burst") == 0);
    anomaly_list_free(&list);
    stats_free(&ctx);

    CHECK(stats_init(&ctx) == PCAPSTAT_OK);
    send_udp_seconds(&ctx, 500, 1, 100000);
    CHECK(anomaly_list_init(&list) == PCAPSTAT_OK);
    CHECK(anomaly_detect(&ctx, NULL, &list) == PCAPSTAT_OK);
    CHECK(count_category(&list, "UDP Burst") == 0);
    anomaly_list_free(&list);
    stats_free(&ctx);

    /* Two active seconds already give a baseline: a 100-pkt second next
     * to a 1-pkt second is flagged (leave-one-out baseline 1.0). */
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);
    send_udp_seconds(&ctx, 500, 1, 100);
    send_udp_seconds(&ctx, 501, 1, 1);
    CHECK(anomaly_list_init(&list) == PCAPSTAT_OK);
    CHECK(anomaly_detect(&ctx, NULL, &list) == PCAPSTAT_OK);
    CHECK(count_category(&list, "UDP Burst") == 1);
    CHECK(find_anomaly(&list, "UDP Burst", "1970-01-01 00:08:20 UTC") != NULL);
    CHECK(strstr(list.items[0].description, "baseline 1.0 pkt/s") != NULL);
    anomaly_list_free(&list);
    stats_free(&ctx);
}

/* FIX-06: rule 8 "Capture Integrity" fires only when main recorded a
 * truncated input file. */
static void test_capture_integrity(void)
{
    stats_ctx_t ctx;
    anomaly_list_t list;

    CHECK(stats_init(&ctx) == PCAPSTAT_OK);
    send_pkt(&ctx, make_ipv4_pkt(1.0, IPPROTO_UDP, 1, 2, 5000, 53, 0, 60));
    ctx.files_processed = 3;
    CHECK(anomaly_list_init(&list) == PCAPSTAT_OK);
    CHECK(anomaly_detect(&ctx, NULL, &list) == PCAPSTAT_OK);
    CHECK(count_category(&list, "Capture Integrity") == 0);
    CHECK(list.count == 0);
    anomaly_list_free(&list);

    ctx.truncated_files = 2;
    CHECK(anomaly_list_init(&list) == PCAPSTAT_OK);
    CHECK(anomaly_detect(&ctx, NULL, &list) == PCAPSTAT_OK);
    CHECK(list.count == 1);
    const anomaly_t *ci = find_anomaly(&list, "Capture Integrity",
                                       "2 of 3 file(s)");
    CHECK(ci != NULL);
    CHECK(ci->severity == ANOMALY_WARNING);
    CHECK(strcmp(ci->description,
                 "2 input file(s) truncated or corrupt; statistics cover"
                 " only the readable part") == 0);
    anomaly_list_free(&list);

    /* Hand-built context without files_processed: plain count. */
    ctx.files_processed = 0;
    ctx.truncated_files = 1;
    CHECK(anomaly_list_init(&list) == PCAPSTAT_OK);
    CHECK(anomaly_detect(&ctx, NULL, &list) == PCAPSTAT_OK);
    CHECK(find_anomaly(&list, "Capture Integrity", "1 file(s)") != NULL);
    anomaly_list_free(&list);
    stats_free(&ctx);
}

/* Burst subjects for pre-1970 seconds and for years gmtime_r cannot
 * represent (fallback to the raw epoch second). */
static void test_udp_burst_subject_edge_times(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    send_udp_seconds(&ctx, -100, 10, 5);  /* quiet: -100..-91 */
    send_udp_seconds(&ctx, -1, 1, 500);   /* burst at -1 = 23:59:59 */
    /* Burst at 8e18 s (year ~2.5e11 overflows struct tm's int year). */
    for (int i = 0; i < 500; ++i)
        send_pkt(&ctx, make_ipv4_pkt(8.0e18, IPPROTO_UDP, 1, 2, 5000, 7777,
                                     0, 60));

    anomaly_list_t list;
    CHECK(anomaly_list_init(&list) == PCAPSTAT_OK);
    CHECK(anomaly_detect(&ctx, NULL, &list) == PCAPSTAT_OK);

    CHECK(count_category(&list, "UDP Burst") == 2);
    CHECK(find_anomaly(&list, "UDP Burst", "1969-12-31 23:59:59 UTC") != NULL);
    CHECK(find_anomaly(&list, "UDP Burst", "Epoch 8000000000000000000 s") !=
          NULL);

    anomaly_list_free(&list);
    stats_free(&ctx);
}

/* M4 regression: a port scanner that sends >= 50 unanswered SYNs is
 * reported only as a Port Scan (it used to get a CRITICAL SYN Flood too). */
static void test_port_scanner_not_syn_flood(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    /* 10.0.0.100 sends 60 SYNs to 30 distinct ports, 0 SYN-ACKs back */
    for (int i = 0; i < 60; ++i)
        send_pkt(&ctx, make_ipv4_pkt(1.0 + 0.01 * i, IPPROTO_TCP, 100, 2,
                                     (uint16_t)(40000 + i),
                                     (uint16_t)(1 + i % 30), TH_SYN, 60));

    anomaly_list_t list;
    CHECK(anomaly_list_init(&list) == PCAPSTAT_OK);
    CHECK(anomaly_detect(&ctx, NULL, &list) == PCAPSTAT_OK);

    CHECK(list.count == 1);
    const anomaly_t *ps = find_anomaly(&list, "Port Scan", "10.0.0.100");
    CHECK(ps != NULL);
    CHECK(ps->severity == ANOMALY_CRITICAL);
    CHECK(strstr(ps->description, "30 unique") != NULL);
    /* Neither a host-level nor the global SYN Flood finding */
    CHECK(find_anomaly(&list, "SYN Flood", NULL) == NULL);

    anomaly_list_free(&list);
    stats_free(&ctx);
}

/* A host flooding a single port is still a SYN Flood (not a Port Scan),
 * also when a scanner is present in the same capture. */
static void test_syn_flood_single_port_with_scanner(void)
{
    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);

    /* 10.0.0.10 floods 10.0.0.20:80 with 60 SYNs, 0 SYN-ACKs */
    for (int i = 0; i < 60; ++i)
        send_pkt(&ctx, make_ipv4_pkt(1.0 + 0.01 * i, IPPROTO_TCP, 10, 20,
                                     (uint16_t)(30000 + i), 80, TH_SYN, 60));

    anomaly_list_t list;
    CHECK(anomaly_list_init(&list) == PCAPSTAT_OK);
    CHECK(anomaly_detect(&ctx, NULL, &list) == PCAPSTAT_OK);
    CHECK(list.count == 1);
    CHECK(find_anomaly(&list, "SYN Flood", "10.0.0.10") != NULL);
    CHECK(find_anomaly(&list, "Port Scan", NULL) == NULL);
    anomaly_list_free(&list);

    /* Add a scanner: 10.0.0.100 -> 10.0.0.2, 55 SYNs to 55 ports */
    for (int i = 0; i < 55; ++i)
        send_pkt(&ctx, make_ipv4_pkt(2.0 + 0.01 * i, IPPROTO_TCP, 100, 2,
                                     45000, (uint16_t)(1000 + i), TH_SYN, 60));

    CHECK(anomaly_list_init(&list) == PCAPSTAT_OK);
    CHECK(anomaly_detect(&ctx, NULL, &list) == PCAPSTAT_OK);
    CHECK(list.count == 2);
    CHECK(find_anomaly(&list, "Port Scan", "10.0.0.100") != NULL);
    CHECK(find_anomaly(&list, "SYN Flood", "10.0.0.10") != NULL);
    CHECK(count_category(&list, "SYN Flood") == 1);
    anomaly_list_free(&list);

    stats_free(&ctx);
}

/* M4 on real data: loading the demo twice doubles the scanner's SYNs to 50,
 * which used to add a CRITICAL "SYN Flood" for 10.0.0.100. */
static void test_demo_pcap_twice_no_syn_flood(void)
{
    FILE *f = fopen("samples/demo.pcap", "rb");
    if (f == NULL) {
        printf("    SKIP (samples/demo.pcap not found; run from repo root)\n");
        return;
    }
    fclose(f);

    stats_ctx_t ctx;
    CHECK(stats_init(&ctx) == PCAPSTAT_OK);
    for (int i = 0; i < 2; ++i)
        CHECK(parser_process_file("samples/demo.pcap", stats_packet_cb, &ctx) ==
              PCAPSTAT_OK);

    anomaly_list_t list;
    CHECK(anomaly_list_init(&list) == PCAPSTAT_OK);
    CHECK(anomaly_detect(&ctx, NULL, &list) == PCAPSTAT_OK);

    CHECK(find_anomaly(&list, "Port Scan", "10.0.0.100") != NULL);
    CHECK(find_anomaly(&list, "SYN Flood", NULL) == NULL);
    CHECK(count_category(&list, "UDP Burst") == 1);

    anomaly_list_free(&list);
    stats_free(&ctx);
}

int main(void)
{
    printf("=== test_anomaly ===\n");
    RUN(test_anomaly_list_lifecycle);
    RUN(test_null_and_empty_args);
    RUN(test_clean_traffic);
    RUN(test_demo_pcap_anomalies);
    RUN(test_port_scan_threshold_override);
    RUN(test_syn_flood_heuristics);
    RUN(test_tcp_retransmissions_per_flow);
    RUN(test_rst_spike_detection);
    RUN(test_suspicious_tcp_flag_variants);
    RUN(test_udp_burst_boundary);
    RUN(test_udp_burst_multiplier_boundary);
    RUN(test_udp_short_burst_detected);
    RUN(test_udp_burst_consecutive_merged);
    RUN(test_udp_burst_separate_runs);
    RUN(test_udp_flood_without_baseline);
    RUN(test_udp_burst_subject_edge_times);
    RUN(test_capture_integrity);
    RUN(test_port_scanner_not_syn_flood);
    RUN(test_syn_flood_single_port_with_scanner);
    RUN(test_demo_pcap_twice_no_syn_flood);
    printf("All anomaly detection tests PASSED.\n");
    return 0;
}
