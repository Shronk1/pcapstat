/**
 * @file test_parser.c
 * @brief Unit tests for the pcap parser module.
 *
 * Tests parsing of samples/demo.pcap (known deterministic packet counts)
 * and synthetic truncated/malformed buffers.
 */

#include "parser.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DEMO_PCAP  "samples/demo.pcap"

/* ── Counters filled by the callback ──────────────────────────────── */

typedef struct {
    uint32_t total;
    uint32_t tcp_ipv4;
    uint32_t tcp_ipv6;
    uint32_t udp_ipv4;
    uint32_t malformed;
    uint32_t ipv6;
    /* Specific flag counters for verification */
    uint32_t syn_only;      /* SYN set, ACK not set */
    uint32_t xmas;          /* FIN+PSH+URG */
    uint32_t null_scan;     /* no flags at all */
} test_counters_t;

static int count_cb(const parsed_packet_t *pkt, void *user_data)
{
    test_counters_t *c = (test_counters_t *)user_data;
    c->total++;

    if (pkt->is_malformed) {
        c->malformed++;
        return 0;
    }

    if (pkt->ip_version == 6)
        c->ipv6++;

    if (pkt->proto == IPPROTO_TCP) {
        if (pkt->ip_version == 4)
            c->tcp_ipv4++;
        else if (pkt->ip_version == 6)
            c->tcp_ipv6++;

        /* Flag analysis */
        uint8_t f = pkt->tcp_flags;
        if ((f & 0x02) && !(f & 0x10))  /* SYN, no ACK */
            c->syn_only++;
        if ((f & 0x01) && (f & 0x08) && (f & 0x20) && !(f & 0x02))
            c->xmas++;          /* FIN+PSH+URG, no SYN */
        if (f == 0x00)
            c->null_scan++;
    } else if (pkt->proto == IPPROTO_UDP) {
        if (pkt->ip_version == 4)
            c->udp_ipv4++;
    }

    return 0;
}

/* ── Test: parse demo.pcap and verify counts ─────────────────────── */

static void test_demo_pcap_counts(void)
{
    printf("  test_demo_pcap_counts...\n");

    test_counters_t c;
    memset(&c, 0, sizeof(c));

    int rc = parser_process_file(DEMO_PCAP, count_cb, &c);
    assert(rc == PCAPSTAT_OK);

    /*
     * Expected from gen_demo_pcap.c header:
     *   Total         : 183
     *   IPv4 TCP      :  52  (21 normal + 25 portscan + 3 retrans
     *                         + 1 xmas + 1 null + 1 VLAN)
     *   IPv4 UDP      : 126  (6 normal + 120 burst)
     *   IPv6 TCP      :   3
     *   Malformed     :   2
     *   Xmas scan     :   1
     *   Null scan     :   1
     */
    assert(c.total     == 183);
    assert(c.tcp_ipv4  ==  52);
    assert(c.udp_ipv4  == 126);
    assert(c.tcp_ipv6  ==   3);
    assert(c.ipv6      ==   3);
    assert(c.malformed ==   2);
    assert(c.xmas      ==   1);
    assert(c.null_scan ==   1);

    printf("    PASS (total=%u tcp4=%u udp4=%u tcp6=%u malformed=%u)\n",
           c.total, c.tcp_ipv4, c.udp_ipv4, c.tcp_ipv6, c.malformed);
}

/* ── Test: callback early-stop ───────────────────────────────────── */

static int stop_after_5(const parsed_packet_t *pkt, void *user_data)
{
    (void)pkt;
    uint32_t *count = (uint32_t *)user_data;
    (*count)++;
    if (*count >= 5)
        return 42;  /* arbitrary non-zero to stop */
    return 0;
}

static void test_early_stop(void)
{
    printf("  test_early_stop...\n");

    uint32_t count = 0;
    int rc = parser_process_file(DEMO_PCAP, stop_after_5, &count);
    assert(rc == 42);
    assert(count == 5);

    printf("    PASS (stopped after %u packets, rc=%d)\n", count, rc);
}

/* ── Test: nonexistent file ──────────────────────────────────────── */

static void test_nonexistent_file(void)
{
    printf("  test_nonexistent_file...\n");

    uint32_t count = 0;
    int rc = parser_process_file("/nonexistent.pcap", stop_after_5, &count);
    assert(rc == PCAPSTAT_ERR_IO);
    assert(count == 0);

    printf("    PASS (rc=%d)\n", rc);
}

/* ── Test: parser_format_ip ──────────────────────────────────────── */

static void test_format_ip(void)
{
    printf("  test_format_ip...\n");

    /* IPv4 */
    uint8_t ip4[16];
    memset(ip4, 0, sizeof(ip4));
    struct in_addr addr4;
    inet_pton(AF_INET, "10.0.0.1", &addr4);
    memcpy(ip4, &addr4, 4);

    char buf[64];
    parser_format_ip(4, ip4, buf, sizeof(buf));
    assert(strcmp(buf, "10.0.0.1") == 0);

    /* IPv6 */
    uint8_t ip6[16];
    struct in6_addr addr6;
    inet_pton(AF_INET6, "fd00::1", &addr6);
    memcpy(ip6, &addr6, 16);

    parser_format_ip(6, ip6, buf, sizeof(buf));
    assert(strcmp(buf, "fd00::1") == 0);

    /* Edge: zero-length buffer */
    parser_format_ip(4, ip4, buf, 0);

    printf("    PASS\n");
}

/* ── Test: TCP fields (ports, seq, flags) are correct ──────────── */

typedef struct {
    bool     found_https_syn;
    uint16_t https_syn_sport;
    uint32_t https_syn_seq;
} tcp_field_check_t;

static int tcp_field_cb(const parsed_packet_t *pkt, void *user_data)
{
    tcp_field_check_t *chk = (tcp_field_check_t *)user_data;

    if (pkt->is_malformed)
        return 0;

    /* Look for the first SYN to port 443 on IPv4 */
    if (!chk->found_https_syn &&
        pkt->ip_version == 4 &&
        pkt->proto == IPPROTO_TCP &&
        pkt->dst_port == 443 &&
        (pkt->tcp_flags & 0x02) &&     /* SYN set */
        !(pkt->tcp_flags & 0x10)) {    /* ACK not set */
        chk->found_https_syn = true;
        chk->https_syn_sport = pkt->src_port;
        chk->https_syn_seq   = pkt->tcp_seq;
    }

    return 0;
}

static void test_tcp_fields(void)
{
    printf("  test_tcp_fields...\n");

    tcp_field_check_t chk;
    memset(&chk, 0, sizeof(chk));

    int rc = parser_process_file(DEMO_PCAP, tcp_field_cb, &chk);
    assert(rc == PCAPSTAT_OK);
    assert(chk.found_https_syn);
    /* src_port should be non-zero (ephemeral) */
    assert(chk.https_syn_sport != 0);
    /* seq should be non-zero (set by generator) */
    assert(chk.https_syn_seq != 0);

    printf("    PASS (HTTPS SYN: sport=%u seq=%u)\n",
           chk.https_syn_sport, chk.https_syn_seq);
}

/* ── Test: payload_len for UDP packets ───────────────────────────── */

typedef struct {
    bool     found_dns;
    uint32_t dns_payload_len;
} udp_check_t;

static int udp_check_cb(const parsed_packet_t *pkt, void *user_data)
{
    udp_check_t *chk = (udp_check_t *)user_data;

    if (pkt->is_malformed)
        return 0;

    /* Find first UDP to port 53 */
    if (!chk->found_dns &&
        pkt->proto == IPPROTO_UDP &&
        pkt->dst_port == 53) {
        chk->found_dns       = true;
        chk->dns_payload_len = pkt->payload_len;
    }

    return 0;
}

static void test_udp_payload(void)
{
    printf("  test_udp_payload...\n");

    udp_check_t chk;
    memset(&chk, 0, sizeof(chk));

    int rc = parser_process_file(DEMO_PCAP, udp_check_cb, &chk);
    assert(rc == PCAPSTAT_OK);
    assert(chk.found_dns);
    /* Generator creates DNS packets with some payload */
    assert(chk.dns_payload_len > 0);

    printf("    PASS (DNS payload_len=%u)\n", chk.dns_payload_len);
}

/* ── main ───────────────────────────────────────────────────────────── */

int main(void)
{
    printf("=== test_parser ===\n");

    test_demo_pcap_counts();
    test_early_stop();
    test_nonexistent_file();
    test_format_ip();
    test_tcp_fields();
    test_udp_payload();

    printf("All parser tests PASSED.\n");
    return 0;
}
