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

    CHECK(list.count > 0);

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

    /* 5. UDP Burst: 120 pkts in single second window (sec 1704067202) */
    const anomaly_t *burst = find_anomaly(&list, "UDP Burst", NULL);
    CHECK(burst != NULL);
    CHECK(burst->severity == ANOMALY_WARNING);
    CHECK(strstr(burst->description, "120") != NULL);

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
    /* Sec 103: 100 pkts (total = 115, mean = 28.75, 3x mean = 86.25, pkts = 100 >= 100) */
    for (int i = 0; i < 100; ++i)
        send_pkt(&ctx, make_ipv4_pkt(103.0 + 0.008 * i, IPPROTO_UDP, 1, 2, 5000, 9999, 0, 50));

    CHECK(stats_finalize(&ctx) == PCAPSTAT_OK);

    anomaly_list_t list;
    CHECK(anomaly_list_init(&list) == PCAPSTAT_OK);
    CHECK(anomaly_detect(&ctx, NULL, &list) == PCAPSTAT_OK);

    const anomaly_t *burst = find_anomaly(&list, "UDP Burst", "Second 103");
    CHECK(burst != NULL);
    CHECK(burst->severity == ANOMALY_WARNING);

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
    printf("All anomaly detection tests PASSED.\n");
    return 0;
}
