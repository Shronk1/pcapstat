/**
 * @file gen_fixture_pcaps.c
 * @brief Deterministic edge-case capture generator for the integration tests.
 *
 * Usage: gen_fixture_pcaps <output-dir>
 *
 * Writes one small .pcap per edge case into <output-dir> (which must
 * exist). Built by `make fixtures` (and by `make test`); used by
 * tests/run_tests.sh, which runs every fixture through the release and
 * ASan binaries and checks the exit code and summary lines. Every file
 * is fully deterministic: fixed addresses, ports and timestamps
 * (base 2024-01-01 00:00:00 UTC unless stated otherwise).
 *
 * Fixture                Link     What it exercises
 * ────────────────────── ──────── ─────────────────────────────────────────
 * empty.pcap             EN10MB   global header only, zero packets
 * one_packet.pcap        EN10MB   a single TCP SYN (no duration, no rate)
 * tcp_only.pcap          EN10MB   clean TCP session, 16 packets
 * udp_only.pcap          EN10MB   10 DNS query/response pairs, 20 packets
 * arp_tcp.pcap           EN10MB   4 ARP frames + clean TCP session (non-IP)
 * truncated_tail.pcap    EN10MB   TCP session, last record cut short
 * corrupt_first.pcap     EN10MB   first record claims an impossible caplen
 * dlt_null.pcap          NULL     unsupported link type (BSD loopback)
 * extreme_ts.pcap        EN10MB   timestamps INT32_MIN .. INT32_MAX
 * unsorted_days.pcap     EN10MB   three days written out of order
 * ipv4_fragments.pcap    EN10MB   UDP datagram in 4 fragments + 30 TCP
 *                                 non-first fragments whose payload looks
 *                                 like scan probes (ports, null/xmas flags)
 * tso_totlen0.pcap       EN10MB   IPv4 tot_len == 0 and IPv6 plen == 0
 *                                 (TSO / BIG TCP captured on the sender)
 * udp_burst.pcap         EN10MB   2 quiet seconds around a 150-pkt UDP second
 * reorder_subms.pcap     EN10MB   30 TCP data segments, 10 adjacent pairs
 *                                 swapped 0.5 ms apart (first one in order)
 * sll.pcap               SLL      TCP session + DNS pair
 * sll2.pcap              SLL2     TCP session + DNS pair (if libpcap has it)
 * raw.pcap               RAW      IPv4 TCP session + IPv6 DNS pair
 * qinq.pcap              EN10MB   802.1ad + 802.1Q double tag, TCP + DNS
 * ipv6.pcap              EN10MB   IPv6 TCP session + DNS pair
 *
 * L4 checksums are left 0 (the analyzer does not verify them); the IPv4
 * header checksum is computed so the files also open cleanly in Wireshark.
 */

#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SNAP_LEN    65535
#define MAX_FRAME   4096
#define BASE_SEC    1704067200L  /* 2024-01-01 00:00:00 UTC */
#define DAY_SEC     86400L

#define PROTO_TCP   6
#define PROTO_UDP   17

#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20

/* Link-layer framing used by build_frame(). */
typedef enum { LINK_ETH, LINK_QINQ, LINK_SLL, LINK_SLL2, LINK_RAW } link_t;

/** One open output file. */
typedef struct {
    pcap_t        *pd;
    pcap_dumper_t *dumper;
    link_t         link;
    char           path[1024];
    unsigned       packets;
} out_t;

/** Description of one IP packet. */
typedef struct {
    int         ipv;        /* 4 or 6 */
    const char *src;
    const char *dst;
    uint8_t     proto;      /* PROTO_TCP or PROTO_UDP */
    uint16_t    sport;
    uint16_t    dport;
    uint8_t     flags;      /* TCP flags */
    uint32_t    seq;
    uint32_t    ack;
    uint32_t    payload;    /* L4 payload bytes (filled with a pattern) */
    bool        len_zero;   /* IPv4 tot_len = 0 / IPv6 plen = 0 (TSO) */
} ip_pkt_t;

static const char *g_dir;
static int g_failed;

/* ── Output files ─────────────────────────────────────────────────── */

static int link_dlt(link_t link)
{
    switch (link) {
    case LINK_SLL:  return DLT_LINUX_SLL;
#ifdef DLT_LINUX_SLL2
    case LINK_SLL2: return DLT_LINUX_SLL2;
#endif
    case LINK_RAW:  return DLT_RAW;
    default:        return DLT_EN10MB;
    }
}

static int out_open(out_t *o, const char *name, link_t link)
{
    memset(o, 0, sizeof(*o));
    o->link = link;
    snprintf(o->path, sizeof(o->path), "%s/%s", g_dir, name);
    o->pd = pcap_open_dead(link_dlt(link), SNAP_LEN);
    if (o->pd == NULL) {
        fprintf(stderr, "gen_fixture_pcaps: pcap_open_dead failed\n");
        return -1;
    }
    o->dumper = pcap_dump_open(o->pd, o->path);
    if (o->dumper == NULL) {
        fprintf(stderr, "gen_fixture_pcaps: %s: %s\n", o->path, pcap_geterr(o->pd));
        pcap_close(o->pd);
        o->pd = NULL;
        return -1;
    }
    return 0;
}

static void out_close(out_t *o)
{
    if (o->dumper != NULL)
        pcap_dump_close(o->dumper);
    if (o->pd != NULL)
        pcap_close(o->pd);
    printf("  %-22s %4u packets\n", strrchr(o->path, '/') + 1, o->packets);
    o->dumper = NULL;
    o->pd = NULL;
}

/** Write one record at @p sec + @p usec. */
static void out_put(out_t *o, long sec, long usec, const uint8_t *buf,
                    uint32_t len)
{
    struct pcap_pkthdr h;
    memset(&h, 0, sizeof(h));
    h.ts.tv_sec  = (time_t)sec;
    h.ts.tv_usec = (suseconds_t)usec;
    h.caplen = len;
    h.len    = len;
    pcap_dump((u_char *)o->dumper, &h, buf);
    o->packets++;
}

/* ── Frame builders ───────────────────────────────────────────────── */

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

static uint16_t ipv4_checksum(const uint8_t *hdr, size_t len)
{
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2)
        sum += (uint32_t)((hdr[i] << 8) | hdr[i + 1]);
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

/** Link header for @p ethertype; returns its length. */
static size_t build_link(uint8_t *buf, link_t link, uint16_t ethertype)
{
    static const uint8_t dmac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    static const uint8_t smac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

    switch (link) {
    case LINK_ETH:
        memcpy(buf, dmac, 6);
        memcpy(buf + 6, smac, 6);
        put16(buf + 12, ethertype);
        return 14;
    case LINK_QINQ:
        memcpy(buf, dmac, 6);
        memcpy(buf + 6, smac, 6);
        put16(buf + 12, 0x88A8);       /* 802.1ad service tag */
        put16(buf + 14, 100);          /* S-VLAN 100 */
        put16(buf + 16, 0x8100);       /* 802.1Q customer tag */
        put16(buf + 18, 200);          /* C-VLAN 200 */
        put16(buf + 20, ethertype);
        return 22;
    case LINK_SLL:                     /* Linux cooked v1, 16 bytes */
        memset(buf, 0, 16);
        put16(buf + 0, 0);             /* packet type: to us */
        put16(buf + 2, 1);             /* ARPHRD_ETHER */
        put16(buf + 4, 6);             /* address length */
        memcpy(buf + 6, smac, 6);
        put16(buf + 14, ethertype);
        return 16;
    case LINK_SLL2:                    /* Linux cooked v2, 20 bytes */
        memset(buf, 0, 20);
        put16(buf + 0, ethertype);
        put32(buf + 4, 2);             /* interface index */
        put16(buf + 8, 1);             /* ARPHRD_ETHER */
        buf[10] = 0;                   /* packet type */
        buf[11] = 6;                   /* address length */
        memcpy(buf + 12, smac, 6);
        return 20;
    case LINK_RAW:
    default:
        return 0;
    }
}

/** L4 header + payload pattern for @p p; returns its length. */
static size_t build_l4(uint8_t *buf, const ip_pkt_t *p)
{
    size_t hlen;
    if (p->proto == PROTO_TCP) {
        hlen = 20;
        memset(buf, 0, hlen);
        put16(buf + 0, p->sport);
        put16(buf + 2, p->dport);
        put32(buf + 4, p->seq);
        put32(buf + 8, p->ack);
        buf[12] = 5 << 4;              /* doff = 5 */
        buf[13] = p->flags;
        put16(buf + 14, 64240);
    } else {
        hlen = 8;
        memset(buf, 0, hlen);
        put16(buf + 0, p->sport);
        put16(buf + 2, p->dport);
        put16(buf + 4, (uint16_t)(8 + p->payload));
    }
    for (uint32_t i = 0; i < p->payload; i++)
        buf[hlen + i] = (uint8_t)('a' + i % 26);
    return hlen + p->payload;
}

/** IPv4/IPv6 header in front of @p l4len bytes already at buf + hdr. */
static size_t build_ip_hdr(uint8_t *buf, const ip_pkt_t *p, size_t l4len,
                           uint8_t proto, uint16_t frag_field, uint16_t ip_id)
{
    if (p->ipv == 6) {
        memset(buf, 0, 40);
        buf[0] = 0x60;
        put16(buf + 4, p->len_zero ? 0 : (uint16_t)l4len);
        buf[6] = proto;
        buf[7] = 64;
        inet_pton(AF_INET6, p->src, buf + 8);
        inet_pton(AF_INET6, p->dst, buf + 24);
        return 40;
    }
    memset(buf, 0, 20);
    buf[0] = 0x45;
    put16(buf + 2, p->len_zero ? 0 : (uint16_t)(20 + l4len));
    put16(buf + 4, ip_id);
    put16(buf + 6, frag_field);
    buf[8] = 64;
    buf[9] = proto;
    inet_pton(AF_INET, p->src, buf + 12);
    inet_pton(AF_INET, p->dst, buf + 16);
    put16(buf + 10, ipv4_checksum(buf, 20));
    return 20;
}

/** Build a complete frame for @p p; returns the frame length. */
static size_t build_frame(uint8_t *buf, link_t link, const ip_pkt_t *p)
{
    size_t off = build_link(buf, link, p->ipv == 6 ? 0x86DD : 0x0800);
    size_t iph = (p->ipv == 6) ? 40 : 20;
    size_t l4  = build_l4(buf + off + iph, p);
    build_ip_hdr(buf + off, p, l4, p->proto, 0x4000 /* DF */, 1);
    return off + iph + l4;
}

static void emit(out_t *o, long sec, long usec, const ip_pkt_t *p)
{
    uint8_t buf[MAX_FRAME];
    size_t len = build_frame(buf, o->link, p);
    out_put(o, sec, usec, buf, (uint32_t)len);
}

/* ── Traffic patterns ─────────────────────────────────────────────── */

/**
 * Clean TCP session (16 packets): handshake, 5 request/response pairs,
 * FIN/FIN/ACK. Starts at @p sec, one exchange per 200 ms.
 */
static void tcp_session(out_t *o, int ipv, const char *cli, const char *srv,
                        long sec)
{
    uint32_t cs = 1000, ss = 5000;
    long t = 0; /* microseconds since sec */
    ip_pkt_t c = {.ipv = ipv, .src = cli, .dst = srv, .proto = PROTO_TCP,
                  .sport = 43210, .dport = 80};
    ip_pkt_t s = {.ipv = ipv, .src = srv, .dst = cli, .proto = PROTO_TCP,
                  .sport = 80, .dport = 43210};

#define AT(us) (sec + (us) / 1000000), ((us) % 1000000)
    c.flags = TH_SYN; c.seq = cs; c.ack = 0;           emit(o, AT(t), &c); t += 1000;
    cs++;
    s.flags = TH_SYN | TH_ACK; s.seq = ss; s.ack = cs; emit(o, AT(t), &s); t += 1000;
    ss++;
    c.flags = TH_ACK; c.seq = cs; c.ack = ss;          emit(o, AT(t), &c); t += 1000;

    for (int i = 0; i < 5; i++) {
        t += 200000;
        c.flags = TH_PSH | TH_ACK; c.seq = cs; c.ack = ss; c.payload = 120;
        emit(o, AT(t), &c);
        cs += 120;
        t += 2000;
        s.flags = TH_PSH | TH_ACK; s.seq = ss; s.ack = cs; s.payload = 600;
        emit(o, AT(t), &s);
        ss += 600;
    }
    c.payload = 0;
    s.payload = 0;
    t += 10000;
    c.flags = TH_FIN | TH_ACK; c.seq = cs; c.ack = ss; emit(o, AT(t), &c); t += 1000;
    cs++;
    s.flags = TH_FIN | TH_ACK; s.seq = ss; s.ack = cs; emit(o, AT(t), &s); t += 1000;
    ss++;
    c.flags = TH_ACK; c.seq = cs; c.ack = ss;          emit(o, AT(t), &c);
#undef AT
}

/** DNS query + response pair at @p sec. */
static void dns_pair(out_t *o, int ipv, const char *cli, const char *srv,
                     uint16_t cport, long sec)
{
    ip_pkt_t q = {.ipv = ipv, .src = cli, .dst = srv, .proto = PROTO_UDP,
                  .sport = cport, .dport = 53, .payload = 40};
    ip_pkt_t r = {.ipv = ipv, .src = srv, .dst = cli, .proto = PROTO_UDP,
                  .sport = 53, .dport = cport, .payload = 90};
    emit(o, sec, 100000, &q);
    emit(o, sec, 101500, &r);
}

/* ── Fixtures ─────────────────────────────────────────────────────── */

#define OPEN_OR_FAIL(o, name, link)               \
    do {                                          \
        if (out_open((o), (name), (link)) != 0) { \
            g_failed = 1;                         \
            return;                               \
        }                                         \
    } while (0)

static void fx_empty(void)
{
    out_t o;
    OPEN_OR_FAIL(&o, "empty.pcap", LINK_ETH);
    out_close(&o);
}

static void fx_one_packet(void)
{
    out_t o;
    OPEN_OR_FAIL(&o, "one_packet.pcap", LINK_ETH);
    ip_pkt_t p = {.ipv = 4, .src = "10.1.0.1", .dst = "10.1.0.2",
                  .proto = PROTO_TCP, .sport = 40000, .dport = 80,
                  .flags = TH_SYN, .seq = 1};
    emit(&o, BASE_SEC, 0, &p);
    out_close(&o);
}

static void fx_tcp_only(void)
{
    out_t o;
    OPEN_OR_FAIL(&o, "tcp_only.pcap", LINK_ETH);
    tcp_session(&o, 4, "10.1.1.1", "10.1.1.2", BASE_SEC);
    out_close(&o);
}

static void fx_udp_only(void)
{
    out_t o;
    OPEN_OR_FAIL(&o, "udp_only.pcap", LINK_ETH);
    for (int i = 0; i < 10; i++)
        dns_pair(&o, 4, "10.2.0.1", "10.2.0.53", (uint16_t)(50000 + i), BASE_SEC + i);
    out_close(&o);
}

/** ARP request/reply frame (42 bytes, EtherType 0x0806). */
static void emit_arp(out_t *o, long sec, long usec, bool reply)
{
    uint8_t buf[64];
    size_t off = build_link(buf, LINK_ETH, 0x0806);
    uint8_t *a = buf + off;
    put16(a + 0, 1);            /* HTYPE Ethernet */
    put16(a + 2, 0x0800);       /* PTYPE IPv4 */
    a[4] = 6;
    a[5] = 4;
    put16(a + 6, reply ? 2 : 1);
    memset(a + 8, 0x02, 6);
    inet_pton(AF_INET, reply ? "10.1.2.2" : "10.1.2.1", a + 14);
    memset(a + 18, reply ? 0x02 : 0x00, 6);
    inet_pton(AF_INET, reply ? "10.1.2.1" : "10.1.2.2", a + 24);
    out_put(o, sec, usec, buf, (uint32_t)(off + 28));
}

static void fx_arp_tcp(void)
{
    out_t o;
    OPEN_OR_FAIL(&o, "arp_tcp.pcap", LINK_ETH);
    emit_arp(&o, BASE_SEC, 0, false);
    emit_arp(&o, BASE_SEC, 500, true);
    tcp_session(&o, 4, "10.1.2.1", "10.1.2.2", BASE_SEC);
    emit_arp(&o, BASE_SEC + 2, 0, false);
    emit_arp(&o, BASE_SEC + 2, 500, true);
    out_close(&o);
}

/** Truncate @p path by @p cut bytes (cuts into the last record). */
static int chop_file(const char *path, long cut)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL)
        return -1;
    uint8_t *data = malloc(1 << 20);
    size_t n = data ? fread(data, 1, 1 << 20, f) : 0;
    fclose(f);
    if (data == NULL || (long)n <= cut) {
        free(data);
        return -1;
    }
    f = fopen(path, "wb");
    if (f == NULL) {
        free(data);
        return -1;
    }
    size_t keep = n - (size_t)cut;
    int rc = (fwrite(data, 1, keep, f) == keep) ? 0 : -1;
    if (fclose(f) != 0)
        rc = -1;
    free(data);
    return rc;
}

static void fx_truncated_tail(void)
{
    out_t o;
    OPEN_OR_FAIL(&o, "truncated_tail.pcap", LINK_ETH);
    tcp_session(&o, 4, "10.1.3.1", "10.1.3.2", BASE_SEC);
    out_close(&o);
    /* The last record is a 54-byte ACK: drop 20 of its data bytes, as if
     * the capture had been killed mid-write. */
    if (chop_file(o.path, 20) != 0) {
        fprintf(stderr, "gen_fixture_pcaps: cannot truncate %s\n", o.path);
        g_failed = 1;
    }
}

/** Raw little-endian pcap global header (magic a1b2c3d4, v2.4). */
static void put_global_header(FILE *f, uint32_t linktype)
{
    const uint32_t hdr[6] = {0xa1b2c3d4u, 0x00040002u, 0, 0, SNAP_LEN, linktype};
    fwrite(hdr, sizeof(hdr), 1, f);
}

static void fx_corrupt_first(void)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/corrupt_first.pcap", g_dir);
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        g_failed = 1;
        return;
    }
    put_global_header(f, 1 /* LINKTYPE_ETHERNET */);
    /* ts_sec, ts_usec, caplen (impossible: 2 GiB > snaplen), len */
    const uint32_t rec[4] = {(uint32_t)BASE_SEC, 0, 0x7FFFFFF0u, 0x7FFFFFF0u};
    fwrite(rec, sizeof(rec), 1, f);
    const uint8_t junk[64] = {0};
    fwrite(junk, sizeof(junk), 1, f);
    if (fclose(f) != 0)
        g_failed = 1;
    printf("  %-22s %4s\n", "corrupt_first.pcap", "(bad first record)");
}

static void fx_dlt_null(void)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/dlt_null.pcap", g_dir);
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        g_failed = 1;
        return;
    }
    put_global_header(f, 0 /* LINKTYPE_NULL (BSD loopback) */);
    /* One record: 4-byte AF_INET family + 20-byte IPv4 header. */
    const uint32_t rec[4] = {(uint32_t)BASE_SEC, 0, 24, 24};
    fwrite(rec, sizeof(rec), 1, f);
    uint8_t pkt[24] = {2, 0, 0, 0, 0x45, 0, 0, 20, 0, 1, 0, 0, 64, 17};
    fwrite(pkt, sizeof(pkt), 1, f);
    if (fclose(f) != 0)
        g_failed = 1;
    printf("  %-22s %4d packets\n", "dlt_null.pcap", 1);
}

static void fx_extreme_ts(void)
{
    out_t o;
    OPEN_OR_FAIL(&o, "extreme_ts.pcap", LINK_ETH);
    /* The classic pcap record stores a signed 32-bit tv_sec: these are the
     * extremes a file can hold (1901-12-13 .. 2038-01-19). */
    const long secs[4] = {-2147483647L - 1, -2147483647L, 2147483646L, 2147483647L};
    for (int i = 0; i < 4; i++) {
        ip_pkt_t p = {.ipv = 4, .src = "10.1.4.1", .dst = "10.1.4.53",
                      .proto = PROTO_UDP, .sport = (uint16_t)(51000 + i),
                      .dport = 53, .payload = 40};
        emit(&o, secs[i], 0, &p);
    }
    out_close(&o);
}

static void fx_unsorted_days(void)
{
    out_t o;
    OPEN_OR_FAIL(&o, "unsorted_days.pcap", LINK_ETH);
    /* One DNS pair + 3 TCP data segments per day, days written 2, 0, 1.
     * Sequence numbers rise chronologically, so a correct engine rebases
     * (no retransmission) when time goes backwards between files/days. */
    const int order[3] = {2, 0, 1};
    for (int k = 0; k < 3; k++) {
        int d = order[k];
        long sec = BASE_SEC + d * DAY_SEC;
        dns_pair(&o, 4, "10.1.5.1", "10.1.5.53", (uint16_t)(52000 + d), sec);
        for (int i = 0; i < 3; i++) {
            ip_pkt_t p = {.ipv = 4, .src = "10.1.5.1", .dst = "10.1.5.2",
                          .proto = PROTO_TCP, .sport = 44000, .dport = 443,
                          .flags = TH_PSH | TH_ACK, .ack = 1, .payload = 200,
                          .seq = (uint32_t)(1000 + (d * 3 + i) * 200)};
            emit(&o, sec + 1, i * 10000L, &p);
        }
    }
    out_close(&o);
}

/** IPv4 fragment: IP header + @p len raw bytes at fragment @p off8 (8-byte units). */
static void emit_v4_fragment(out_t *o, long sec, long usec, const char *src,
                             const char *dst, uint8_t proto, uint16_t id,
                             uint16_t off8, bool more, const uint8_t *data,
                             size_t len)
{
    uint8_t buf[MAX_FRAME];
    ip_pkt_t p = {.ipv = 4, .src = src, .dst = dst};
    size_t off = build_link(buf, o->link, 0x0800);
    memcpy(buf + off + 20, data, len);
    build_ip_hdr(buf + off, &p, len, proto,
                 (uint16_t)((more ? 0x2000 : 0) | (off8 & 0x1FFF)), id);
    out_put(o, sec, usec, buf, (uint32_t)(off + 20 + len));
}

static void fx_ipv4_fragments(void)
{
    out_t o;
    OPEN_OR_FAIL(&o, "ipv4_fragments.pcap", LINK_ETH);

    /* A 1216-byte UDP datagram (8 + 1208) split into 4 x 304 bytes. The
     * first carries the real UDP header (5000 -> 6000); the others start
     * with bytes that would decode as random ports if parsed as L4. */
    uint8_t dgram[1216];
    ip_pkt_t u = {.ipv = 4, .proto = PROTO_UDP, .sport = 5000, .dport = 6000,
                  .payload = 1208};
    build_l4(dgram, &u);
    for (int i = 1; i < 4; i++)
        put32(dgram + i * 304, 0x1F000000u + (uint32_t)i * 0x00010001u);
    for (int i = 0; i < 4; i++)
        emit_v4_fragment(&o, BASE_SEC, i * 100L, "10.3.0.1", "10.3.0.2",
                         PROTO_UDP, 0x1234, (uint16_t)(i * 38), i < 3,
                         dgram + i * 304, 304);

    /* 30 non-first TCP fragments from one host. Their first 20 bytes look
     * like TCP headers to 30 distinct ports with SYN, null, Xmas, SYN+FIN
     * and SYN+RST flags: decoding them as L4 would fabricate a port scan,
     * a SYN flood and suspicious-flag findings. */
    static const uint8_t fake_flags[5] = {
        TH_SYN, 0x00, TH_FIN | TH_PSH | TH_URG, TH_SYN | TH_FIN, TH_SYN | TH_RST};
    for (int i = 0; i < 30; i++) {
        uint8_t frag[64];
        ip_pkt_t t = {.ipv = 4, .proto = PROTO_TCP, .sport = 31337,
                      .dport = (uint16_t)(1000 + i), .flags = fake_flags[i % 5],
                      .seq = (uint32_t)i, .payload = 44};
        build_l4(frag, &t);
        emit_v4_fragment(&o, BASE_SEC + 1, i * 1000L, "10.3.0.66", "10.3.0.2",
                         PROTO_TCP, (uint16_t)(0x2000 + i), 185, false, frag, 64);
    }
    out_close(&o);
}

static void fx_tso_totlen0(void)
{
    out_t o;
    OPEN_OR_FAIL(&o, "tso_totlen0.pcap", LINK_ETH);
    const char *cli = "10.6.0.1", *srv = "10.6.0.2";
    ip_pkt_t c = {.ipv = 4, .src = cli, .dst = srv, .proto = PROTO_TCP,
                  .sport = 45000, .dport = 5001};
    ip_pkt_t s = {.ipv = 4, .src = srv, .dst = cli, .proto = PROTO_TCP,
                  .sport = 5001, .dport = 45000};
    uint32_t cs = 100;

    c.flags = TH_SYN; c.seq = cs;                       emit(&o, BASE_SEC, 0, &c);
    cs++;
    s.flags = TH_SYN | TH_ACK; s.seq = 900; s.ack = cs; emit(&o, BASE_SEC, 500, &s);
    c.flags = TH_ACK; c.seq = cs; c.ack = 901;          emit(&o, BASE_SEC, 1000, &c);
    /* Four 2896-byte super-segments with tot_len = 0, each ACKed. */
    for (int i = 0; i < 4; i++) {
        c.flags = TH_PSH | TH_ACK; c.seq = cs; c.payload = 2896; c.len_zero = true;
        emit(&o, BASE_SEC, 10000L + i * 10000L, &c);
        cs += 2896;
        s.flags = TH_ACK; s.seq = 901; s.ack = cs;
        emit(&o, BASE_SEC, 10500L + i * 10000L, &s);
    }
    /* Two IPv6 segments with payload length 0 (BIG TCP). */
    ip_pkt_t v6 = {.ipv = 6, .src = "fd00:6::1", .dst = "fd00:6::2",
                   .proto = PROTO_TCP, .sport = 45001, .dport = 5001,
                   .flags = TH_PSH | TH_ACK, .ack = 1, .payload = 2896,
                   .len_zero = true};
    v6.seq = 1;    emit(&o, BASE_SEC, 60000, &v6);
    v6.seq = 2897; emit(&o, BASE_SEC, 61000, &v6);
    out_close(&o);
}

static void fx_udp_burst(void)
{
    out_t o;
    OPEN_OR_FAIL(&o, "udp_burst.pcap", LINK_ETH);
    /* Three active seconds: quiet, 150 UDP pkt/s burst, quiet. With the
     * burst included in its own mean (old rule) 150 > 3 * 51.3 never holds;
     * the leave-one-out baseline is 2 pkt/s. */
    dns_pair(&o, 4, "10.4.0.1", "10.4.0.53", 53000, BASE_SEC);
    for (int i = 0; i < 150; i++) {
        ip_pkt_t p = {.ipv = 4, .src = "10.4.0.9", .dst = "10.4.0.2",
                      .proto = PROTO_UDP, .sport = 7000, .dport = 9000,
                      .payload = 100};
        emit(&o, BASE_SEC + 1, i * 6000L, &p);
    }
    dns_pair(&o, 4, "10.4.0.1", "10.4.0.53", 53001, BASE_SEC + 2);
    out_close(&o);
}

static void fx_reorder_subms(void)
{
    out_t o;
    OPEN_OR_FAIL(&o, "reorder_subms.pcap", LINK_ETH);
    const char *cli = "10.5.0.1", *srv = "10.5.0.2";
    ip_pkt_t c = {.ipv = 4, .src = cli, .dst = srv, .proto = PROTO_TCP,
                  .sport = 41000, .dport = 8080};
    ip_pkt_t s = {.ipv = 4, .src = srv, .dst = cli, .proto = PROTO_TCP,
                  .sport = 8080, .dport = 41000};

    c.flags = TH_SYN; c.seq = 0;                      emit(&o, BASE_SEC, 0, &c);
    s.flags = TH_SYN | TH_ACK; s.seq = 0; s.ack = 1;  emit(&o, BASE_SEC, 500, &s);
    c.flags = TH_ACK; c.seq = 1; c.ack = 1;           emit(&o, BASE_SEC, 1000, &c);

    /* Segment k carries [1 + 100k, 1 + 100(k+1)). Pairs (3j+1, 3j+2),
     * j = 0..9, arrive swapped 0.5 ms apart; segment 0 is always first,
     * because SYN is not tracked (a swapped first pair would count as one
     * retransmission). Expected: 10 out-of-order, 0 retransmissions. */
    c.flags = TH_PSH | TH_ACK;
    c.payload = 100;
    long t = 10000;
    for (int k = 0; k < 30; k++) {
        int seg = k;
        if (k % 3 == 1)
            seg = k + 1;
        else if (k % 3 == 2)
            seg = k - 1;
        c.seq = 1u + 100u * (uint32_t)seg;
        emit(&o, BASE_SEC, t, &c);
        t += (k % 3 == 1) ? 500 : 10000;
    }
    out_close(&o);
}

/** TCP session + DNS pair on @p link (@p ipv for the session). */
static void fx_link(const char *name, link_t link, int tcp_ipv, int dns_ipv)
{
    out_t o;
    OPEN_OR_FAIL(&o, name, link);
    if (tcp_ipv == 6)
        tcp_session(&o, 6, "fd00:7::1", "fd00:7::2", BASE_SEC);
    else
        tcp_session(&o, 4, "10.7.0.1", "10.7.0.2", BASE_SEC);
    if (dns_ipv == 6)
        dns_pair(&o, 6, "fd00:7::1", "fd00:7::53", 54000, BASE_SEC + 2);
    else
        dns_pair(&o, 4, "10.7.0.1", "10.7.0.53", 54000, BASE_SEC + 2);
    out_close(&o);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <output-dir>\n", argc > 0 ? argv[0] : "gen_fixture_pcaps");
        return 2;
    }
    g_dir = argv[1];
    printf("gen_fixture_pcaps: writing fixtures to %s\n", g_dir);

    fx_empty();
    fx_one_packet();
    fx_tcp_only();
    fx_udp_only();
    fx_arp_tcp();
    fx_truncated_tail();
    fx_corrupt_first();
    fx_dlt_null();
    fx_extreme_ts();
    fx_unsorted_days();
    fx_ipv4_fragments();
    fx_tso_totlen0();
    fx_udp_burst();
    fx_reorder_subms();
    fx_link("sll.pcap", LINK_SLL, 4, 4);
#ifdef DLT_LINUX_SLL2
    fx_link("sll2.pcap", LINK_SLL2, 4, 4);
#else
    printf("  %-22s (skipped: libpcap has no DLT_LINUX_SLL2)\n", "sll2.pcap");
#endif
    fx_link("raw.pcap", LINK_RAW, 4, 6);
    fx_link("qinq.pcap", LINK_QINQ, 4, 4);
    fx_link("ipv6.pcap", LINK_ETH, 6, 6);

    if (g_failed) {
        fprintf(stderr, "gen_fixture_pcaps: failed to write some fixtures\n");
        return 1;
    }
    return 0;
}
