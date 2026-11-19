/**
 * @file gen_demo_pcap.c
 * @brief Deterministic synthetic traffic generator for samples/demo.pcap.
 *
 * Compiled to bin/gen_demo_pcap; run once to create the demo capture.
 *
 * ═══════════════════════════════════════════════════════════════════════
 * PACKET SUMMARY (deterministic — counts used by test_parser.c)
 * ═══════════════════════════════════════════════════════════════════════
 *
 * Category                   Count   Notes
 * ─────────────────────────── ─────── ──────────────────────────────────
 * TCP — HTTPS:443 handshake      3   SYN, SYN-ACK, ACK
 * TCP — HTTPS:443 payload        2   data segments (PSH-ACK)
 * TCP — HTTPS:443 FIN            2   FIN-ACK each direction
 * TCP — HTTP:80  handshake       3   SYN, SYN-ACK, ACK
 * TCP — HTTP:80  payload         2   data segments (PSH-ACK)
 * TCP — HTTP:80  FIN             2   FIN-ACK each direction
 * TCP — SSH:22   handshake       3   SYN, SYN-ACK, ACK
 * TCP — SSH:22   payload         2   data segments (PSH-ACK)
 * TCP — SSH:22   FIN             2   FIN-ACK each direction
 * UDP — DNS:53                   4   2 queries + 2 responses
 * UDP — NTP:123                  2   request + response
 * IPv6 — TCP SYN to :443        3   SYN, SYN-ACK, ACK (IPv6)
 * 802.1Q VLAN — TCP SYN to :80  1   single VLAN-tagged SYN
 * Port scan (SYN)               25   SYN to 25 distinct dst ports
 * TCP retransmissions             3   repeated seq in HTTPS flow
 * Xmas Scan                      1   FIN+PSH+URG
 * Null Scan                      1   no flags
 * UDP burst                    120   120 pkts in 1-second window
 * Malformed — truncated IP       1   caplen < IP header
 * Malformed — bad IHL            1   ihl=2 (invalid)
 * ─────────────────────────── ─────── ──────────────────────────────────
 * TOTAL                        183
 *
 * Protocol breakdown:
 *   IPv4 TCP packets  :  52  (21 normal + 25 portscan + 3 retrans
 *                              + 1 xmas + 1 null + 1 VLAN-tagged)
 *   IPv4 UDP packets  : 126  (6 normal + 120 burst)
 *   IPv6 TCP packets  :   3
 *   Malformed          :   2
 *   VLAN-tagged        :   1  (also counted as TCP)
 *   TOTAL             : 183
 */

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Compile-time constants ──────────────────────────────────────── */

#define DEMO_PCAP_PATH  "samples/demo.pcap"
#define SNAP_LEN        65535
#define ETH_HDR_LEN     14
#define VLAN_TAG_LEN    4
#define IPV4_HDR_LEN    20
#define IPV6_HDR_LEN    40
#define TCP_HDR_LEN     20
#define UDP_HDR_LEN     8
#define MAX_PKT         1500

/* Fixed MAC addresses (arbitrary). */
static const uint8_t SRC_MAC[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
static const uint8_t DST_MAC[6] = {0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb};

/* Fixed IPv4 addresses. */
#define IP_SRC   "10.0.0.1"
#define IP_DST   "10.0.0.2"
#define IP_SCAN  "10.0.0.100"  /* port-scanner source */

/* Fixed IPv6 addresses. */
#define IP6_SRC  "fd00::1"
#define IP6_DST  "fd00::2"

/* ── Helpers ─────────────────────────────────────────────────────── */

static pcap_dumper_t *dumper;
static uint32_t pkt_count;

/* Base timestamp (2024-01-01 00:00:00 UTC). */
static struct timeval base_ts = {.tv_sec = 1704067200, .tv_usec = 0};

static void advance_ms(int ms)
{
    base_ts.tv_usec += (long)ms * 1000;
    while (base_ts.tv_usec >= 1000000) {
        base_ts.tv_sec  += 1;
        base_ts.tv_usec -= 1000000;
    }
}

/**
 * Compute Internet checksum (RFC 1071).
 */
static uint16_t ip_checksum(const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2) {
        sum += (uint16_t)((uint16_t)p[i] << 8 | p[i + 1]);
    }
    if (len & 1) {
        sum += (uint16_t)p[len - 1] << 8;
    }
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return htons((uint16_t)~sum);
}

/**
 * Write a raw buffer as a pcap packet.
 */
static void dump_pkt(const uint8_t *buf, uint32_t len, uint32_t caplen)
{
    struct pcap_pkthdr hdr;
    hdr.ts     = base_ts;
    hdr.caplen = caplen;
    hdr.len    = len;
    pcap_dump((u_char *)dumper, &hdr, buf);
    pkt_count++;
}

/* ── Ethernet frame builder ──────────────────────────────────────── */

static size_t build_eth(uint8_t *buf, uint16_t ethertype)
{
    memcpy(buf, DST_MAC, 6);
    memcpy(buf + 6, SRC_MAC, 6);
    buf[12] = (uint8_t)(ethertype >> 8);
    buf[13] = (uint8_t)(ethertype & 0xFF);
    return ETH_HDR_LEN;
}

static size_t build_eth_vlan(uint8_t *buf, uint16_t vlan_id,
                             uint16_t inner_ethertype)
{
    memcpy(buf, DST_MAC, 6);
    memcpy(buf + 6, SRC_MAC, 6);
    /* 802.1Q TPID */
    buf[12] = 0x81;
    buf[13] = 0x00;
    /* TCI: priority=0, DEI=0, VID */
    buf[14] = (uint8_t)((vlan_id >> 8) & 0x0F);
    buf[15] = (uint8_t)(vlan_id & 0xFF);
    /* Inner EtherType */
    buf[16] = (uint8_t)(inner_ethertype >> 8);
    buf[17] = (uint8_t)(inner_ethertype & 0xFF);
    return ETH_HDR_LEN + VLAN_TAG_LEN;
}

/* ── IPv4 header builder ─────────────────────────────────────────── */

static size_t build_ipv4(uint8_t *buf, const char *src, const char *dst,
                         uint8_t proto, uint16_t payload_len)
{
    memset(buf, 0, IPV4_HDR_LEN);
    buf[0] = 0x45;  /* version=4, ihl=5 */
    uint16_t total_len = IPV4_HDR_LEN + payload_len;
    buf[2] = (uint8_t)(total_len >> 8);
    buf[3] = (uint8_t)(total_len & 0xFF);
    buf[8] = 64;    /* TTL */
    buf[9] = proto;
    inet_pton(AF_INET, src, buf + 12);
    inet_pton(AF_INET, dst, buf + 16);
    uint16_t cksum = ip_checksum(buf, IPV4_HDR_LEN);
    memcpy(buf + 10, &cksum, 2);
    return IPV4_HDR_LEN;
}

/* ── IPv6 header builder ─────────────────────────────────────────── */

static size_t build_ipv6(uint8_t *buf, const char *src, const char *dst,
                         uint8_t next_hdr, uint16_t payload_len)
{
    memset(buf, 0, IPV6_HDR_LEN);
    buf[0] = 0x60;  /* version=6 */
    buf[4] = (uint8_t)(payload_len >> 8);
    buf[5] = (uint8_t)(payload_len & 0xFF);
    buf[6] = next_hdr;
    buf[7] = 64;  /* hop limit */
    inet_pton(AF_INET6, src, buf + 8);
    inet_pton(AF_INET6, dst, buf + 24);
    return IPV6_HDR_LEN;
}

/* ── TCP segment builder ─────────────────────────────────────────── */

static size_t build_tcp(uint8_t *buf, uint16_t src_port, uint16_t dst_port,
                        uint32_t seq, uint32_t ack, uint8_t flags,
                        uint16_t window, size_t payload_len)
{
    memset(buf, 0, TCP_HDR_LEN);
    uint16_t sp = htons(src_port);
    uint16_t dp = htons(dst_port);
    uint32_t sq = htonl(seq);
    uint32_t ak = htonl(ack);
    memcpy(buf + 0, &sp, 2);
    memcpy(buf + 2, &dp, 2);
    memcpy(buf + 4, &sq, 4);
    memcpy(buf + 8, &ak, 4);
    buf[12] = (TCP_HDR_LEN / 4) << 4;  /* data offset */
    buf[13] = flags;
    uint16_t win = htons(window);
    memcpy(buf + 14, &win, 2);
    /* checksum left as 0 (not validated by our parser) */
    (void)payload_len;
    return TCP_HDR_LEN;
}

/* ── UDP datagram builder ────────────────────────────────────────── */

static size_t build_udp(uint8_t *buf, uint16_t src_port, uint16_t dst_port,
                        uint16_t payload_len)
{
    uint16_t total = UDP_HDR_LEN + payload_len;
    uint16_t sp = htons(src_port);
    uint16_t dp = htons(dst_port);
    uint16_t ln = htons(total);
    memcpy(buf + 0, &sp, 2);
    memcpy(buf + 2, &dp, 2);
    memcpy(buf + 4, &ln, 2);
    buf[6] = 0; buf[7] = 0;  /* checksum = 0 */
    return UDP_HDR_LEN;
}

/* ── TCP flag constants ──────────────────────────────────────────── */

#define TH_SYN_FLAG  0x02
#define TH_ACK_FLAG  0x10
#define TH_FIN_FLAG  0x01
#define TH_RST_FLAG  0x04
#define TH_PSH_FLAG  0x08
#define TH_URG_FLAG  0x20

/* ── Composite packet emitters ───────────────────────────────────── */

/**
 * Emit IPv4 TCP packet (Ethernet + IPv4 + TCP + optional payload bytes).
 */
static void emit_tcp4(const char *src_ip, const char *dst_ip,
                      uint16_t src_port, uint16_t dst_port,
                      uint32_t seq, uint32_t ack, uint8_t flags,
                      size_t payload_len)
{
    uint8_t pkt[MAX_PKT];
    size_t off = 0;

    off += build_eth(pkt + off, ETHERTYPE_IP);
    off += build_ipv4(pkt + off, src_ip, dst_ip, IPPROTO_TCP,
                      (uint16_t)(TCP_HDR_LEN + payload_len));
    off += build_tcp(pkt + off, src_port, dst_port, seq, ack, flags,
                     65535, payload_len);
    /* Fill payload with 0xAA. */
    if (payload_len > 0) {
        memset(pkt + off, 0xAA, payload_len);
        off += payload_len;
    }
    dump_pkt(pkt, (uint32_t)off, (uint32_t)off);
}

/**
 * Emit IPv4 UDP packet (Ethernet + IPv4 + UDP + optional payload bytes).
 */
static void emit_udp4(const char *src_ip, const char *dst_ip,
                      uint16_t src_port, uint16_t dst_port,
                      size_t payload_len)
{
    uint8_t pkt[MAX_PKT];
    size_t off = 0;

    off += build_eth(pkt + off, ETHERTYPE_IP);
    off += build_ipv4(pkt + off, src_ip, dst_ip, IPPROTO_UDP,
                      (uint16_t)(UDP_HDR_LEN + payload_len));
    off += build_udp(pkt + off, src_port, dst_port, (uint16_t)payload_len);
    if (payload_len > 0) {
        memset(pkt + off, 0xBB, payload_len);
        off += payload_len;
    }
    dump_pkt(pkt, (uint32_t)off, (uint32_t)off);
}

/**
 * Emit IPv6 TCP packet (Ethernet + IPv6 + TCP).
 */
static void emit_tcp6(const char *src_ip, const char *dst_ip,
                      uint16_t src_port, uint16_t dst_port,
                      uint32_t seq, uint32_t ack, uint8_t flags)
{
    uint8_t pkt[MAX_PKT];
    size_t off = 0;

    off += build_eth(pkt + off, ETHERTYPE_IPV6);
    off += build_ipv6(pkt + off, src_ip, dst_ip, IPPROTO_TCP, TCP_HDR_LEN);
    off += build_tcp(pkt + off, src_port, dst_port, seq, ack, flags,
                     65535, 0);
    dump_pkt(pkt, (uint32_t)off, (uint32_t)off);
}

/**
 * Emit a VLAN-tagged (802.1Q) IPv4 TCP SYN.
 */
static void emit_vlan_tcp4_syn(uint16_t vlan_id,
                               const char *src_ip, const char *dst_ip,
                               uint16_t src_port, uint16_t dst_port)
{
    uint8_t pkt[MAX_PKT];
    size_t off = 0;

    off += build_eth_vlan(pkt + off, vlan_id, ETHERTYPE_IP);
    off += build_ipv4(pkt + off, src_ip, dst_ip, IPPROTO_TCP, TCP_HDR_LEN);
    off += build_tcp(pkt + off, src_port, dst_port, 1000, 0,
                     TH_SYN_FLAG, 65535, 0);
    dump_pkt(pkt, (uint32_t)off, (uint32_t)off);
}

/* ── Full TCP session helper (3-way handshake + N data + FIN) ──── */

static void emit_tcp_session(const char *src_ip, const char *dst_ip,
                             uint16_t src_port, uint16_t dst_port,
                             int data_pkts, size_t payload_per_pkt)
{
    uint32_t cli_seq = 100;
    uint32_t srv_seq = 5000;

    /* SYN */
    emit_tcp4(src_ip, dst_ip, src_port, dst_port,
              cli_seq, 0, TH_SYN_FLAG, 0);
    advance_ms(1);

    /* SYN-ACK */
    emit_tcp4(dst_ip, src_ip, dst_port, src_port,
              srv_seq, cli_seq + 1, TH_SYN_FLAG | TH_ACK_FLAG, 0);
    advance_ms(1);
    cli_seq++;

    /* ACK */
    emit_tcp4(src_ip, dst_ip, src_port, dst_port,
              cli_seq, srv_seq + 1, TH_ACK_FLAG, 0);
    advance_ms(1);
    srv_seq++;

    /* Data segments (PSH-ACK) */
    for (int i = 0; i < data_pkts; i++) {
        emit_tcp4(src_ip, dst_ip, src_port, dst_port,
                  cli_seq, srv_seq, TH_PSH_FLAG | TH_ACK_FLAG,
                  payload_per_pkt);
        cli_seq += (uint32_t)payload_per_pkt;
        advance_ms(5);
    }

    /* FIN-ACK (client) */
    emit_tcp4(src_ip, dst_ip, src_port, dst_port,
              cli_seq, srv_seq, TH_FIN_FLAG | TH_ACK_FLAG, 0);
    advance_ms(1);

    /* FIN-ACK (server) */
    emit_tcp4(dst_ip, src_ip, dst_port, src_port,
              srv_seq, cli_seq + 1, TH_FIN_FLAG | TH_ACK_FLAG, 0);
    advance_ms(1);
}

/* ═══════════════════════════════════════════════════════════════════ */

int main(void)
{
    pcap_t *dead = pcap_open_dead(DLT_EN10MB, SNAP_LEN);
    if (!dead) {
        fprintf(stderr, "pcap_open_dead failed\n");
        return 1;
    }

    dumper = pcap_dump_open(dead, DEMO_PCAP_PATH);
    if (!dumper) {
        fprintf(stderr, "pcap_dump_open(%s): %s\n",
                DEMO_PCAP_PATH, pcap_geterr(dead));
        pcap_close(dead);
        return 1;
    }

    pkt_count = 0;

    /* ── 1. Normal TCP sessions ──────────────────────────────────── */

    /* HTTPS:443 — 3 handshake + 2 data + 2 FIN = 7 */
    emit_tcp_session(IP_SRC, IP_DST, 50000, 443, 2, 200);
    advance_ms(100);

    /* HTTP:80 — 7 */
    emit_tcp_session(IP_SRC, IP_DST, 50001, 80, 2, 300);
    advance_ms(100);

    /* SSH:22 — 7 */
    emit_tcp_session(IP_SRC, IP_DST, 50002, 22, 2, 150);
    advance_ms(100);

    /* ── 2. Normal UDP traffic ───────────────────────────────────── */

    /* DNS:53 — 4 packets (2 queries + 2 responses) */
    emit_udp4(IP_SRC, IP_DST, 51000, 53, 40);
    advance_ms(5);
    emit_udp4(IP_DST, IP_SRC, 53, 51000, 100);
    advance_ms(50);
    emit_udp4(IP_SRC, IP_DST, 51001, 53, 35);
    advance_ms(5);
    emit_udp4(IP_DST, IP_SRC, 53, 51001, 90);
    advance_ms(100);

    /* NTP:123 — 2 packets */
    emit_udp4(IP_SRC, IP_DST, 51002, 123, 48);
    advance_ms(10);
    emit_udp4(IP_DST, IP_SRC, 123, 51002, 48);
    advance_ms(200);

    /* ── 3. IPv6 TCP handshake to :443 ───────────────────────────── */

    emit_tcp6(IP6_SRC, IP6_DST, 60000, 443, 200, 0, TH_SYN_FLAG);
    advance_ms(1);
    emit_tcp6(IP6_DST, IP6_SRC, 443, 60000, 8000, 201,
              TH_SYN_FLAG | TH_ACK_FLAG);
    advance_ms(1);
    emit_tcp6(IP6_SRC, IP6_DST, 60000, 443, 201, 8001, TH_ACK_FLAG);
    advance_ms(100);

    /* ── 4. VLAN-tagged TCP SYN ──────────────────────────────────── */

    emit_vlan_tcp4_syn(100, IP_SRC, IP_DST, 50010, 80);
    advance_ms(100);

    /* ── 5. Port Scan: 25 SYNs to distinct ports ────────────────── */

    for (int i = 0; i < 25; i++) {
        emit_tcp4(IP_SCAN, IP_DST, 55000, (uint16_t)(1024 + i),
                  1000 + (uint32_t)i, 0, TH_SYN_FLAG, 0);
        advance_ms(2);
    }
    advance_ms(100);

    /* ── 6. TCP Retransmissions (in HTTPS flow from IP_SRC) ────── */
    /* Repeated seq with payload > 0 simulates retransmission. */
    {
        uint32_t retrans_seq = 500;  /* seq already "seen" in that flow */
        emit_tcp4(IP_SRC, IP_DST, 50000, 443,
                  retrans_seq, 5001, TH_ACK_FLAG, 100);
        advance_ms(10);
        emit_tcp4(IP_SRC, IP_DST, 50000, 443,
                  retrans_seq, 5001, TH_ACK_FLAG, 100);
        advance_ms(10);
        emit_tcp4(IP_SRC, IP_DST, 50000, 443,
                  retrans_seq, 5001, TH_ACK_FLAG, 100);
        advance_ms(50);
    }

    /* ── 7. Xmas Scan (FIN+PSH+URG) ─────────────────────────────── */

    emit_tcp4(IP_SCAN, IP_DST, 55100, 8080,
              9000, 0, TH_FIN_FLAG | TH_PSH_FLAG | TH_URG_FLAG, 0);
    advance_ms(10);

    /* ── 8. Null Scan (no flags) ─────────────────────────────────── */

    emit_tcp4(IP_SCAN, IP_DST, 55200, 8081, 9100, 0, 0x00, 0);
    advance_ms(100);

    /* ── 9. UDP Burst: 120 packets in ~1 second ──────────────────── */

    /* Advance to a fresh second boundary. */
    base_ts.tv_sec  += 1;
    base_ts.tv_usec  = 0;

    for (int i = 0; i < 120; i++) {
        emit_udp4(IP_SRC, IP_DST, 52000, 9999, 64);
        /* ~8.3 ms apart = 120 pkts in ~1 second */
        advance_ms(8);
    }
    advance_ms(100);

    /* ── 10. Malformed packets ───────────────────────────────────── */

    /* 10a. Truncated IP header: caplen shorter than min IP header. */
    {
        uint8_t pkt[MAX_PKT];
        size_t off = build_eth(pkt, ETHERTYPE_IP);
        /* Write a partial IP header (only 10 bytes of the 20 needed). */
        memset(pkt + off, 0, 10);
        pkt[off] = 0x45;  /* version=4, ihl=5 */
        off += 10;
        /* caplen = ETH_HDR_LEN + 10, but wire len claims more. */
        dump_pkt(pkt, (uint32_t)(ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN),
                 (uint32_t)off);
    }
    advance_ms(10);

    /* 10b. Invalid IHL (ihl=2, minimum legal is 5). */
    {
        uint8_t pkt[MAX_PKT];
        size_t off = build_eth(pkt, ETHERTYPE_IP);
        /* Build a full IP-sized header area but set ihl=2. */
        memset(pkt + off, 0, IPV4_HDR_LEN);
        pkt[off] = 0x42;  /* version=4, ihl=2 */
        /* total_len set to something valid-looking. */
        uint16_t tl = IPV4_HDR_LEN + TCP_HDR_LEN;
        pkt[off + 2] = (uint8_t)(tl >> 8);
        pkt[off + 3] = (uint8_t)(tl & 0xFF);
        pkt[off + 9] = IPPROTO_TCP;
        off += IPV4_HDR_LEN;
        /* Add a fake TCP header so wire len looks normal. */
        memset(pkt + off, 0, TCP_HDR_LEN);
        off += TCP_HDR_LEN;
        dump_pkt(pkt, (uint32_t)off, (uint32_t)off);
    }

    /* ── Done ────────────────────────────────────────────────────── */

    pcap_dump_close(dumper);
    pcap_close(dead);

    printf("gen_demo_pcap: wrote %u packets to %s\n", pkt_count,
           DEMO_PCAP_PATH);
    return 0;
}
