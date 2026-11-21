/**
 * @file test_parser.c
 * @brief Unit tests for the pcap parser module.
 *
 * Tests parsing of samples/demo.pcap (known deterministic packet counts)
 * and of synthetic captures built inside the tests (temp files created
 * with mkstemp(), written via pcap_open_dead()/pcap_dump() or raw fwrite):
 * non-IP frames, IPv4 fragments, TSO/BIG TCP length fields, every
 * supported link type, VLAN/QinQ, IPv4 options, malformed L3/L4 headers,
 * and truncated/corrupt files (including the stderr warning).
 */

#include "parser.h"

#include <assert.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DEMO_PCAP  "samples/demo.pcap"

/* Unlike assert(), never compiled out by -DNDEBUG (side effects safe). */
#define CHECK(c)                                                          \
    do {                                                                  \
        if (!(c)) {                                                       \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__,        \
                    __LINE__, #c);                                        \
            abort();                                                      \
        }                                                                 \
    } while (0)

/* ── Counters filled by the callback ──────────────────────────────── */

typedef struct {
    uint32_t total;
    uint32_t tcp_ipv4;
    uint32_t tcp_ipv6;
    uint32_t udp_ipv4;
    uint32_t malformed;
    uint32_t ipv6;
    uint32_t non_ip;
    uint32_t fragments;
    /* Specific flag counters for verification */
    uint32_t syn_only;      /* SYN set, ACK not set */
    uint32_t xmas;          /* FIN+PSH+URG */
    uint32_t null_scan;     /* no flags at all */
} test_counters_t;

static int count_cb(const parsed_packet_t *pkt, void *user_data)
{
    test_counters_t *c = (test_counters_t *)user_data;
    c->total++;

    if (pkt->is_non_ip)
        c->non_ip++;
    if (pkt->is_fragment)
        c->fragments++;

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
    /* The demo contains neither non-IP frames nor IPv4 fragments. */
    assert(c.non_ip    ==   0);
    assert(c.fragments ==   0);

    /* The _ex variant reports the same file as complete, not truncated. */
    test_counters_t c2;
    memset(&c2, 0, sizeof(c2));
    parser_file_info_t info;
    memset(&info, 0xAB, sizeof(info));   /* must be overwritten */
    rc = parser_process_file_ex(DEMO_PCAP, count_cb, &c2, &info);
    CHECK(rc == PCAPSTAT_OK);
    CHECK(c2.total == 183);
    CHECK(info.packets == 183);
    CHECK(!info.truncated);
    CHECK(info.error[0] == '\0');

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

/* ══ Synthetic captures ══════════════════════════════════════════════ */

#define FRAME_MAX     256
#define COLLECT_MAX   16
#define TEST_TS_BASE  1700000000u

#define F_FIN 0x01
#define F_SYN 0x02
#define F_RST 0x04
#define F_PSH 0x08
#define F_ACK 0x10
#define F_URG 0x20

#define IP4_MF 0x2000   /* more-fragments flag in frag_off */
#define IP4_DF 0x4000   /* don't-fragment flag in frag_off */

#define LINKTYPE_ETHERNET_RAW 1u   /* pcap file header value for Ethernet */

/* Room for a captured stderr line containing a full-length path. */
#define MSG_MAX (PCAPSTAT_MAX_PATH + 512)

typedef struct {
    uint8_t  data[FRAME_MAX];
    uint32_t caplen;     /* bytes of data[] stored in the file */
    uint32_t wire_len;   /* original length recorded in the record header */
} frame_t;

/* Copies of the delivered packets; optionally stops at packet stop_at. */
typedef struct {
    size_t          count;
    size_t          stop_at;    /* 1-based; 0 = never stop */
    int             stop_rc;
    parsed_packet_t pkts[COLLECT_MAX];
} collector_t;

static int collect_cb(const parsed_packet_t *pkt, void *user_data)
{
    collector_t *c = (collector_t *)user_data;
    if (c->count < COLLECT_MAX)
        c->pkts[c->count] = *pkt;
    c->count++;
    if (c->stop_at != 0 && c->count == c->stop_at)
        return c->stop_rc;
    return 0;
}

/* ── Byte writers (network order) and header builders ─────────────── */

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFF);
}

static void put32(uint8_t *p, uint32_t v)
{
    put16(p, (uint16_t)(v >> 16));
    put16(p + 2, (uint16_t)(v & 0xFFFF));
}

static size_t put_eth(uint8_t *b, uint16_t ethertype)
{
    static const uint8_t macs[12] = { 0x02, 0, 0, 0, 0, 0x02,
                                      0x02, 0, 0, 0, 0, 0x01 };
    memcpy(b, macs, sizeof(macs));
    put16(b + 12, ethertype);
    return 14;
}

/* 802.1Q/802.1ad tag body: TCI + inner EtherType (TPID is the preceding
 * EtherType field). */
static size_t put_vlan_tag(uint8_t *b, uint16_t vid, uint16_t inner_type)
{
    put16(b, (uint16_t)(vid & 0x0FFF));
    put16(b + 2, inner_type);
    return 4;
}

/* IPv4 10.0.0.1 -> 10.0.0.2; @p ihl in 32-bit words (>= 5), options 0. */
static size_t put_ipv4(uint8_t *b, uint8_t ihl, uint16_t tot_len,
                       uint16_t frag_off, uint8_t proto)
{
    size_t hl = (size_t)ihl * 4;
    memset(b, 0, hl);
    b[0] = (uint8_t)(0x40 | (ihl & 0x0F));
    put16(b + 2, tot_len);
    put16(b + 4, 0x1234);       /* identification */
    put16(b + 6, frag_off);
    b[8] = 64;
    b[9] = proto;
    b[12] = 10; b[15] = 1;
    b[16] = 10; b[19] = 2;
    return hl;
}

/* IPv6 fd00::1 -> fd00::2. */
static size_t put_ipv6(uint8_t *b, uint16_t plen, uint8_t next_hdr)
{
    memset(b, 0, 40);
    b[0] = 0x60;
    put16(b + 4, plen);
    b[6] = next_hdr;
    b[7] = 64;
    b[8]  = 0xfd; b[23] = 1;
    b[24] = 0xfd; b[39] = 2;
    return 40;
}

/* TCP header; @p doff in 32-bit words.  Always writes >= 20 bytes so that
 * a doff < 5 header is still fully captured. */
static size_t put_tcp(uint8_t *b, uint16_t sport, uint16_t dport,
                      uint32_t seq, uint8_t flags, uint8_t doff)
{
    size_t hl = doff >= 5 ? (size_t)doff * 4 : 20;
    memset(b, 0, hl);
    put16(b, sport);
    put16(b + 2, dport);
    put32(b + 4, seq);
    put32(b + 8, 0x0A0B0C0Du);  /* ack */
    b[12] = (uint8_t)(doff << 4);
    b[13] = flags;
    put16(b + 14, 4096);        /* window */
    return hl;
}

static size_t put_udp(uint8_t *b, uint16_t sport, uint16_t dport,
                      uint16_t udp_len)
{
    put16(b, sport);
    put16(b + 2, dport);
    put16(b + 4, udp_len);
    put16(b + 6, 0);
    return 8;
}

/* Fill @p n payload bytes with a pattern and finish the frame. */
static void frame_finish(frame_t *f, size_t hdr_len, size_t payload)
{
    CHECK(hdr_len + payload <= FRAME_MAX);
    for (size_t i = 0; i < payload; i++)
        f->data[hdr_len + i] = (uint8_t)(0xA0 + i);
    f->caplen   = (uint32_t)(hdr_len + payload);
    f->wire_len = f->caplen;
}

/* Ethernet + IPv4 (ihl 5) + TCP (no payload): 54 bytes. */
static void build_eth_tcp4(frame_t *f, uint16_t sport, uint16_t dport,
                           uint8_t flags)
{
    memset(f, 0, sizeof(*f));
    size_t o = put_eth(f->data, 0x0800);
    o += put_ipv4(f->data + o, 5, 40, 0, IPPROTO_TCP);
    o += put_tcp(f->data + o, sport, dport, 1000, flags, 5);
    frame_finish(f, o, 0);
}

/* ── Temp files ───────────────────────────────────────────────────── */

static void tmp_template(char *buf, size_t len)
{
    const char *dir = getenv("TMPDIR");
    if (dir == NULL || dir[0] == '\0')
        dir = "/tmp";
    int n = snprintf(buf, len, "%s/pcapstat_test_parser_XXXXXX", dir);
    CHECK(n > 0 && (size_t)n < len);
}

/* Write @p n frames with link type @p dlt into a new temp file whose path
 * is stored in @p path.  The caller unlinks it. */
static void write_pcap(char *path, size_t path_len, int dlt,
                       const frame_t *frames, size_t n)
{
    tmp_template(path, path_len);
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    FILE *fp = fdopen(fd, "wb");
    CHECK(fp != NULL);

    pcap_t *dead = pcap_open_dead(dlt, 65535);
    CHECK(dead != NULL);
    pcap_dumper_t *d = pcap_dump_fopen(dead, fp);   /* owns fp now */
    CHECK(d != NULL);
    for (size_t i = 0; i < n; i++) {
        struct pcap_pkthdr h;
        memset(&h, 0, sizeof(h));
        h.ts.tv_sec = (time_t)(TEST_TS_BASE + i);
        h.caplen    = frames[i].caplen;
        h.len       = frames[i].wire_len;
        pcap_dump((u_char *)d, &h, frames[i].data);
    }
    pcap_dump_close(d);
    pcap_close(dead);
}

/* Raw pcap writer for files libpcap itself refuses to produce. */
static FILE *raw_pcap_create(char *path, size_t path_len)
{
    tmp_template(path, path_len);
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    FILE *fp = fdopen(fd, "wb");
    CHECK(fp != NULL);

    const uint32_t magic = 0xA1B2C3D4u;   /* native order, µs timestamps */
    const uint16_t vmaj = 2, vmin = 4;
    const int32_t  zone = 0;
    const uint32_t sigfigs = 0, snaplen = 65535;
    const uint32_t linktype = LINKTYPE_ETHERNET_RAW;
    uint8_t h[24];
    memcpy(h + 0,  &magic,    4);
    memcpy(h + 4,  &vmaj,     2);
    memcpy(h + 6,  &vmin,     2);
    memcpy(h + 8,  &zone,     4);
    memcpy(h + 12, &sigfigs,  4);
    memcpy(h + 16, &snaplen,  4);
    memcpy(h + 20, &linktype, 4);
    CHECK(fwrite(h, 1, sizeof(h), fp) == sizeof(h));
    return fp;
}

/* Record header (first @p hdr_bytes of its 16 bytes) followed by the first
 * @p data_bytes bytes of @p data.  Short counts simulate a cut file. */
static void raw_pcap_record(FILE *fp, uint32_t sec, uint32_t caplen,
                            uint32_t wire_len, const uint8_t *data,
                            size_t hdr_bytes, size_t data_bytes)
{
    const uint32_t usec = 0;
    uint8_t h[16];
    memcpy(h + 0,  &sec,      4);
    memcpy(h + 4,  &usec,     4);
    memcpy(h + 8,  &caplen,   4);
    memcpy(h + 12, &wire_len, 4);
    CHECK(hdr_bytes <= sizeof(h));
    CHECK(fwrite(h, 1, hdr_bytes, fp) == hdr_bytes);
    if (data_bytes > 0)
        CHECK(fwrite(data, 1, data_bytes, fp) == data_bytes);
}

static void raw_pcap_full_record(FILE *fp, uint32_t sec, const frame_t *f)
{
    raw_pcap_record(fp, sec, f->caplen, f->wire_len, f->data, 16, f->caplen);
}

/* ── stderr capture ───────────────────────────────────────────────── */

typedef struct {
    int  saved_fd;
    char path[PCAPSTAT_MAX_PATH];
} stderr_capture_t;

static void stderr_capture_begin(stderr_capture_t *cap)
{
    fflush(stderr);
    tmp_template(cap->path, sizeof(cap->path));
    int fd = mkstemp(cap->path);
    CHECK(fd >= 0);
    cap->saved_fd = dup(STDERR_FILENO);
    CHECK(cap->saved_fd >= 0);
    CHECK(dup2(fd, STDERR_FILENO) >= 0);
    close(fd);
}

/* Restore stderr and return what was written to it (NUL-terminated). */
static void stderr_capture_end(stderr_capture_t *cap, char *out,
                               size_t out_len)
{
    fflush(stderr);
    CHECK(dup2(cap->saved_fd, STDERR_FILENO) >= 0);
    close(cap->saved_fd);

    FILE *fp = fopen(cap->path, "rb");
    CHECK(fp != NULL);
    size_t n = fread(out, 1, out_len - 1, fp);
    out[n] = '\0';
    fclose(fp);
    unlink(cap->path);
}

/* ── Parse helpers ────────────────────────────────────────────────── */

/* Write frames, parse them with parser_process_file_ex(), delete the file.
 * stderr output is captured into @p err (pass NULL to require silence). */
static int parse_frames(int dlt, const frame_t *frames, size_t n,
                        collector_t *col, parser_file_info_t *info,
                        char *err, size_t err_len)
{
    char path[PCAPSTAT_MAX_PATH];
    char quiet[MSG_MAX];
    stderr_capture_t cap;

    write_pcap(path, sizeof(path), dlt, frames, n);
    memset(col, 0, sizeof(*col));
    stderr_capture_begin(&cap);
    int rc = parser_process_file_ex(path, collect_cb, col, info);
    if (err != NULL) {
        stderr_capture_end(&cap, err, err_len);
    } else {
        stderr_capture_end(&cap, quiet, sizeof(quiet));
        CHECK(quiet[0] == '\0');
    }
    CHECK(unlink(path) == 0);
    return rc;
}

static void check_ipv4_addrs(const parsed_packet_t *p)
{
    static const uint8_t src[16] = { 10, 0, 0, 1 };
    static const uint8_t dst[16] = { 10, 0, 0, 2 };
    CHECK(p->ip_version == 4);
    CHECK(memcmp(p->src_ip, src, sizeof(src)) == 0);
    CHECK(memcmp(p->dst_ip, dst, sizeof(dst)) == 0);
}

static void check_ipv6_addrs(const parsed_packet_t *p)
{
    uint8_t src[16] = { 0xfd };
    uint8_t dst[16] = { 0xfd };
    src[15] = 1;
    dst[15] = 2;
    CHECK(p->ip_version == 6);
    CHECK(memcmp(p->src_ip, src, sizeof(src)) == 0);
    CHECK(memcmp(p->dst_ip, dst, sizeof(dst)) == 0);
}

/* All L4-derived fields are zero. */
static void check_no_l4(const parsed_packet_t *p)
{
    CHECK(p->src_port == 0);
    CHECK(p->dst_port == 0);
    CHECK(p->tcp_flags == 0);
    CHECK(p->tcp_seq == 0);
    CHECK(p->tcp_ack == 0);
    CHECK(p->tcp_window == 0);
    CHECK(p->payload_len == 0);
}

static void check_clean(const parsed_packet_t *p)
{
    CHECK(!p->is_malformed);
    CHECK(!p->is_non_ip);
    CHECK(!p->is_fragment);
}

/* ── Test: non-IP frames are flagged, not malformed (H2) ──────────── */

static void test_non_ip_frames(void)
{
    printf("  test_non_ip_frames...\n");

    frame_t f[6];
    memset(f, 0, sizeof(f));
    size_t o;

    /* 0: ARP request over Ethernet II. */
    o = put_eth(f[0].data, 0x0806);
    put16(f[0].data + o, 1);          /* htype Ethernet */
    put16(f[0].data + o + 2, 0x0800); /* ptype IPv4 (inside ARP!) */
    f[0].data[o + 4] = 6;
    f[0].data[o + 5] = 4;
    put16(f[0].data + o + 6, 1);      /* request */
    frame_finish(&f[0], o + 28, 0);

    /* 1: LLDP. */
    o = put_eth(f[1].data, 0x88CC);
    frame_finish(&f[1], o, 32);

    /* 2: 802.3 length field + LLC (STP BPDU). */
    o = put_eth(f[2].data, 38);
    f[2].data[o] = 0x42;
    f[2].data[o + 1] = 0x42;
    f[2].data[o + 2] = 0x03;
    frame_finish(&f[2], o + 3, 35);

    /* 3: VLAN-tagged ARP: the tag is peeled, then non-IP. */
    o = put_eth(f[3].data, 0x8100);
    o += put_vlan_tag(f[3].data + o, 10, 0x0806);
    frame_finish(&f[3], o, 28);

    /* 4: 802.1Q tag cut short by caplen: still malformed. */
    o = put_eth(f[4].data, 0x8100);
    frame_finish(&f[4], o, 2);

    /* 5: QinQ whose inner 802.1Q tag is cut short: malformed. */
    o = put_eth(f[5].data, 0x88A8);
    o += put_vlan_tag(f[5].data + o, 100, 0x8100);
    frame_finish(&f[5], o, 3);

    collector_t col;
    parser_file_info_t info;
    int rc = parse_frames(DLT_EN10MB, f, 6, &col, &info, NULL, 0);
    CHECK(rc == PCAPSTAT_OK);
    CHECK(col.count == 6);
    CHECK(info.packets == 6);

    for (size_t i = 0; i < 4; i++) {
        const parsed_packet_t *p = &col.pkts[i];
        CHECK(!p->is_malformed);
        CHECK(p->is_non_ip);
        CHECK(!p->is_fragment);
        CHECK(p->ip_version == 0);
        CHECK(p->proto == 0);
        check_no_l4(p);
        CHECK(p->wire_len == f[i].wire_len);
    }
    for (size_t i = 4; i < 6; i++) {
        CHECK(col.pkts[i].is_malformed);
        CHECK(!col.pkts[i].is_non_ip);
    }

    /* Linux cooked capture v1 carrying ARP. */
    frame_t s;
    memset(&s, 0, sizeof(s));
    put16(s.data + 2, 1);             /* ARPHRD_ETHER */
    put16(s.data + 4, 6);             /* address length */
    put16(s.data + 14, 0x0806);       /* protocol */
    frame_finish(&s, 16, 28);
    rc = parse_frames(DLT_LINUX_SLL, &s, 1, &col, &info, NULL, 0);
    CHECK(rc == PCAPSTAT_OK);
    CHECK(col.count == 1);
    CHECK(col.pkts[0].is_non_ip);
    CHECK(!col.pkts[0].is_malformed);
    CHECK(col.pkts[0].ip_version == 0);

    printf("    PASS\n");
}

/* ── Test: IPv4 non-first fragments skip L4 decoding (H3) ─────────── */

static void test_ipv4_fragments(void)
{
    printf("  test_ipv4_fragments...\n");

    frame_t f[6];
    memset(f, 0, sizeof(f));
    size_t o;

    /* 0: last TCP fragment at offset 1480; its payload looks like a TCP
     *    header with SYN+FIN+RST+PSH+URG (old code reported those). */
    o = put_eth(f[0].data, 0x0800);
    o += put_ipv4(f[0].data + o, 5, 20 + 40, 1480 / 8, IPPROTO_TCP);
    o += put_tcp(f[0].data + o, 1234, 80, 77,
                 F_SYN | F_FIN | F_RST | F_PSH | F_URG, 5);
    frame_finish(&f[0], o, 20);

    /* 1: middle UDP fragment (MF set, offset 8 bytes = smallest). */
    o = put_eth(f[1].data, 0x0800);
    o += put_ipv4(f[1].data + o, 5, 20 + 64, IP4_MF | 1, IPPROTO_UDP);
    o += put_udp(f[1].data + o, 5555, 53, 100);
    frame_finish(&f[1], o, 56);

    /* 2: non-first ICMP fragment with DF noise: flagged regardless of proto. */
    o = put_eth(f[2].data, 0x0800);
    o += put_ipv4(f[2].data + o, 5, 20 + 16, IP4_DF | 0x1FFF, IPPROTO_ICMP);
    frame_finish(&f[2], o, 16);

    /* 3: first UDP fragment (MF, offset 0): decoded, UDP length covers the
     *    whole datagram. */
    o = put_eth(f[3].data, 0x0800);
    o += put_ipv4(f[3].data + o, 5, 20 + 8 + 32, IP4_MF, IPPROTO_UDP);
    o += put_udp(f[3].data + o, 5555, 53, 8 + 1472);
    frame_finish(&f[3], o, 32);

    /* 4: first TCP fragment (MF, offset 0): decoded. */
    o = put_eth(f[4].data, 0x0800);
    o += put_ipv4(f[4].data + o, 5, 20 + 20 + 24, IP4_MF, IPPROTO_TCP);
    o += put_tcp(f[4].data + o, 40000, 443, 0x11223344u, F_ACK, 5);
    frame_finish(&f[4], o, 24);

    /* 5: DF set, offset 0: an ordinary packet (flag bits are not offset). */
    o = put_eth(f[5].data, 0x0800);
    o += put_ipv4(f[5].data + o, 5, 20 + 20, IP4_DF, IPPROTO_TCP);
    o += put_tcp(f[5].data + o, 40001, 22, 5, F_SYN, 5);
    frame_finish(&f[5], o, 0);

    collector_t col;
    parser_file_info_t info;
    int rc = parse_frames(DLT_EN10MB, f, 6, &col, &info, NULL, 0);
    CHECK(rc == PCAPSTAT_OK);
    CHECK(col.count == 6);

    static const uint8_t frag_proto[3] = { IPPROTO_TCP, IPPROTO_UDP,
                                           IPPROTO_ICMP };
    for (size_t i = 0; i < 3; i++) {
        const parsed_packet_t *p = &col.pkts[i];
        CHECK(p->is_fragment);
        CHECK(!p->is_malformed);
        CHECK(!p->is_non_ip);
        check_ipv4_addrs(p);
        CHECK(p->proto == frag_proto[i]);
        check_no_l4(p);
    }

    const parsed_packet_t *u = &col.pkts[3];
    check_clean(u);
    check_ipv4_addrs(u);
    CHECK(u->proto == IPPROTO_UDP);
    CHECK(u->src_port == 5555 && u->dst_port == 53);
    CHECK(u->payload_len == 1472);

    const parsed_packet_t *t = &col.pkts[4];
    check_clean(t);
    CHECK(t->proto == IPPROTO_TCP);
    CHECK(t->src_port == 40000 && t->dst_port == 443);
    CHECK(t->tcp_seq == 0x11223344u);
    CHECK(t->tcp_flags == F_ACK);
    CHECK(t->payload_len == 24);

    const parsed_packet_t *d = &col.pkts[5];
    check_clean(d);
    CHECK(d->src_port == 40001 && d->dst_port == 22);
    CHECK(d->tcp_flags == F_SYN);

    printf("    PASS\n");
}

/* ── Test: tot_len == 0 / ip6_plen == 0 take length from frame (M8) ── */

static void test_length_from_frame(void)
{
    printf("  test_length_from_frame...\n");

    frame_t f[4];
    memset(f, 0, sizeof(f));
    size_t o;

    /* 0: TSO super-packet, snaplen-cut capture: 1000 payload bytes on the
     *    wire, only 16 captured. */
    o = put_eth(f[0].data, 0x0800);
    o += put_ipv4(f[0].data + o, 5, 0, IP4_DF, IPPROTO_TCP);
    o += put_tcp(f[0].data + o, 50000, 443, 1, F_ACK | F_PSH, 5);
    frame_finish(&f[0], o, 16);
    f[0].wire_len = 14 + 20 + 20 + 1000;

    /* 1: BIG TCP packet larger than 64 KiB (does not fit in tot_len). */
    o = put_eth(f[1].data, 0x0800);
    o += put_ipv4(f[1].data + o, 5, 0, IP4_DF, IPPROTO_TCP);
    o += put_tcp(f[1].data + o, 50000, 443, 1001, F_ACK, 5);
    frame_finish(&f[1], o, 16);
    f[1].wire_len = 14 + 20 + 20 + 100000;

    /* 2: IPv6 BIG TCP: plen == 0. */
    o = put_eth(f[2].data, 0x86DD);
    o += put_ipv6(f[2].data + o, 0, IPPROTO_TCP);
    o += put_tcp(f[2].data + o, 50001, 80, 7, F_ACK, 5);
    frame_finish(&f[2], o, 8);
    f[2].wire_len = 14 + 40 + 20 + 500;

    /* 3: IPv4 tot_len == 0, IP options, frame fully captured. */
    o = put_eth(f[3].data, 0x0800);
    o += put_ipv4(f[3].data + o, 6, 0, 0, IPPROTO_TCP);
    o += put_tcp(f[3].data + o, 50002, 25, 9, F_ACK, 5);
    frame_finish(&f[3], o, 30);

    collector_t col;
    parser_file_info_t info;
    int rc = parse_frames(DLT_EN10MB, f, 4, &col, &info, NULL, 0);
    CHECK(rc == PCAPSTAT_OK);
    CHECK(col.count == 4);

    check_clean(&col.pkts[0]);
    check_ipv4_addrs(&col.pkts[0]);
    CHECK(col.pkts[0].src_port == 50000 && col.pkts[0].dst_port == 443);
    CHECK(col.pkts[0].tcp_flags == (F_ACK | F_PSH));
    CHECK(col.pkts[0].payload_len == 1000);

    check_clean(&col.pkts[1]);
    CHECK(col.pkts[1].payload_len == 100000);

    check_clean(&col.pkts[2]);
    check_ipv6_addrs(&col.pkts[2]);
    CHECK(col.pkts[2].dst_port == 80);
    CHECK(col.pkts[2].payload_len == 500);

    check_clean(&col.pkts[3]);
    CHECK(col.pkts[3].dst_port == 25);
    CHECK(col.pkts[3].payload_len == 30);

    printf("    PASS\n");
}

/* tot_len == 0 but the frame is shorter than the IP header (a record whose
 * wire length is below its caplen): still malformed. */
static void test_length_from_frame_too_short(void)
{
    printf("  test_length_from_frame_too_short...\n");

    frame_t f;
    memset(&f, 0, sizeof(f));
    size_t o = put_eth(f.data, 0x0800);
    o += put_ipv4(f.data + o, 6, 0, 0, IPPROTO_TCP);
    o += put_tcp(f.data + o, 1, 2, 3, F_ACK, 5);
    frame_finish(&f, o, 0);
    f.wire_len = 14 + 20;        /* frame-derived tot_len 20 < ihl*4 = 24 */

    collector_t col;
    parser_file_info_t info;
    int rc = parse_frames(DLT_EN10MB, &f, 1, &col, &info, NULL, 0);
    CHECK(rc == PCAPSTAT_OK);
    CHECK(col.count == 1);
    CHECK(col.pkts[0].wire_len == 14 + 20);
    CHECK(col.pkts[0].is_malformed);

    printf("    PASS\n");
}

/* ── Test: link layers SLL, SLL2, RAW v4/v6 ───────────────────────── */

static void test_link_layers(void)
{
    printf("  test_link_layers...\n");

    collector_t col;
    parser_file_info_t info;
    frame_t f;
    size_t o;
    int rc;

    /* DLT_LINUX_SLL: 16-byte header, protocol at bytes 14-15. */
    memset(&f, 0, sizeof(f));
    put16(f.data + 2, 1);
    put16(f.data + 4, 6);
    put16(f.data + 14, 0x0800);
    o = 16;
    o += put_ipv4(f.data + o, 5, 20 + 8 + 4, 0, IPPROTO_UDP);
    o += put_udp(f.data + o, 1111, 53, 8 + 4);
    frame_finish(&f, o, 4);
    rc = parse_frames(DLT_LINUX_SLL, &f, 1, &col, &info, NULL, 0);
    CHECK(rc == PCAPSTAT_OK && col.count == 1);
    check_clean(&col.pkts[0]);
    check_ipv4_addrs(&col.pkts[0]);
    CHECK(col.pkts[0].proto == IPPROTO_UDP);
    CHECK(col.pkts[0].src_port == 1111 && col.pkts[0].dst_port == 53);
    CHECK(col.pkts[0].payload_len == 4);

#ifdef DLT_LINUX_SLL2
    /* DLT_LINUX_SLL2: 20-byte header, protocol at bytes 0-1. */
    memset(&f, 0, sizeof(f));
    put16(f.data, 0x86DD);
    put32(f.data + 4, 2);             /* ifindex */
    put16(f.data + 8, 1);             /* ARPHRD_ETHER */
    f.data[11] = 6;                   /* address length */
    o = 20;
    o += put_ipv6(f.data + o, 20, IPPROTO_TCP);
    o += put_tcp(f.data + o, 2222, 443, 42, F_SYN, 5);
    frame_finish(&f, o, 0);
    rc = parse_frames(DLT_LINUX_SLL2, &f, 1, &col, &info, NULL, 0);
    CHECK(rc == PCAPSTAT_OK && col.count == 1);
    check_clean(&col.pkts[0]);
    check_ipv6_addrs(&col.pkts[0]);
    CHECK(col.pkts[0].proto == IPPROTO_TCP);
    CHECK(col.pkts[0].src_port == 2222 && col.pkts[0].dst_port == 443);
    CHECK(col.pkts[0].tcp_seq == 42);
    CHECK(col.pkts[0].tcp_flags == F_SYN);
#else
    printf("    (DLT_LINUX_SLL2 not defined by this libpcap; skipped)\n");
#endif

    /* DLT_RAW: IPv4, IPv6, and an invalid version nibble. */
    frame_t r[3];
    memset(r, 0, sizeof(r));
    o = put_ipv4(r[0].data, 5, 20 + 20 + 10, 0, IPPROTO_TCP);
    o += put_tcp(r[0].data + o, 3333, 22, 99, F_ACK | F_PSH, 5);
    frame_finish(&r[0], o, 10);

    o = put_ipv6(r[1].data, 8 + 48, IPPROTO_UDP);
    o += put_udp(r[1].data + o, 4444, 123, 8 + 48);
    frame_finish(&r[1], o, 48);

    o = put_ipv4(r[2].data, 5, 40, 0, IPPROTO_TCP);
    r[2].data[0] = 0x55;              /* version 5 */
    frame_finish(&r[2], o, 20);

    rc = parse_frames(DLT_RAW, r, 3, &col, &info, NULL, 0);
    CHECK(rc == PCAPSTAT_OK && col.count == 3);

    check_clean(&col.pkts[0]);
    check_ipv4_addrs(&col.pkts[0]);
    CHECK(col.pkts[0].src_port == 3333 && col.pkts[0].dst_port == 22);
    CHECK(col.pkts[0].tcp_flags == (F_ACK | F_PSH));
    CHECK(col.pkts[0].payload_len == 10);

    check_clean(&col.pkts[1]);
    check_ipv6_addrs(&col.pkts[1]);
    CHECK(col.pkts[1].proto == IPPROTO_UDP);
    CHECK(col.pkts[1].src_port == 4444 && col.pkts[1].dst_port == 123);
    CHECK(col.pkts[1].payload_len == 48);

    CHECK(col.pkts[2].is_malformed);
    CHECK(!col.pkts[2].is_non_ip);

    printf("    PASS\n");
}

/* ── Test: QinQ double tag and IPv4 options ───────────────────────── */

static void test_qinq_and_ip_options(void)
{
    printf("  test_qinq_and_ip_options...\n");

    frame_t f[2];
    memset(f, 0, sizeof(f));
    size_t o;

    /* 0: 802.1ad outer tag + 802.1Q inner tag + IPv4 TCP. */
    o = put_eth(f[0].data, 0x88A8);
    o += put_vlan_tag(f[0].data + o, 100, 0x8100);
    o += put_vlan_tag(f[0].data + o, 200, 0x0800);
    o += put_ipv4(f[0].data + o, 5, 20 + 20, 0, IPPROTO_TCP);
    o += put_tcp(f[0].data + o, 5555, 8080, 12345, F_SYN, 5);
    frame_finish(&f[0], o, 0);

    /* 1: IPv4 with 4 bytes of options (ihl = 6). */
    o = put_eth(f[1].data, 0x0800);
    o += put_ipv4(f[1].data + o, 6, 24 + 20 + 5, 0, IPPROTO_TCP);
    o += put_tcp(f[1].data + o, 6666, 25, 0x01020304u, F_PSH | F_ACK, 5);
    frame_finish(&f[1], o, 5);

    collector_t col;
    parser_file_info_t info;
    int rc = parse_frames(DLT_EN10MB, f, 2, &col, &info, NULL, 0);
    CHECK(rc == PCAPSTAT_OK && col.count == 2);

    check_clean(&col.pkts[0]);
    check_ipv4_addrs(&col.pkts[0]);
    CHECK(col.pkts[0].src_port == 5555 && col.pkts[0].dst_port == 8080);
    CHECK(col.pkts[0].tcp_seq == 12345);
    CHECK(col.pkts[0].tcp_flags == F_SYN);

    check_clean(&col.pkts[1]);
    check_ipv4_addrs(&col.pkts[1]);
    CHECK(col.pkts[1].src_port == 6666 && col.pkts[1].dst_port == 25);
    CHECK(col.pkts[1].tcp_seq == 0x01020304u);
    CHECK(col.pkts[1].tcp_ack == 0x0A0B0C0Du);
    CHECK(col.pkts[1].tcp_window == 4096);
    CHECK(col.pkts[1].tcp_flags == (F_PSH | F_ACK));
    CHECK(col.pkts[1].payload_len == 5);

    printf("    PASS\n");
}

/* ── Test: malformed L3/L4 headers ────────────────────────────────── */

static void test_malformed_headers(void)
{
    printf("  test_malformed_headers...\n");

    frame_t f[8];
    memset(f, 0, sizeof(f));
    size_t o;

    /* 0: TCP doff 4 (< 5). */
    o = put_eth(f[0].data, 0x0800);
    o += put_ipv4(f[0].data + o, 5, 40, 0, IPPROTO_TCP);
    o += put_tcp(f[0].data + o, 1, 2, 3, F_ACK, 4);
    frame_finish(&f[0], o, 0);

    /* 1: UDP length 4 (< 8). */
    o = put_eth(f[1].data, 0x0800);
    o += put_ipv4(f[1].data + o, 5, 28, 0, IPPROTO_UDP);
    o += put_udp(f[1].data + o, 1, 2, 4);
    frame_finish(&f[1], o, 0);

    /* 2: tot_len 16 < ihl*4 = 20. */
    o = put_eth(f[2].data, 0x0800);
    o += put_ipv4(f[2].data + o, 5, 16, 0, IPPROTO_TCP);
    o += put_tcp(f[2].data + o, 1, 2, 3, F_ACK, 5);
    frame_finish(&f[2], o, 0);

    /* 3: ihl 6, tot_len 22 < 24. */
    o = put_eth(f[3].data, 0x0800);
    o += put_ipv4(f[3].data + o, 6, 22, 0, IPPROTO_TCP);
    o += put_tcp(f[3].data + o, 1, 2, 3, F_ACK, 5);
    frame_finish(&f[3], o, 0);

    /* 4: IPv4 options run past caplen. */
    o = put_eth(f[4].data, 0x0800);
    put_ipv4(f[4].data + o, 15, 60 + 20, 0, IPPROTO_TCP);
    frame_finish(&f[4], o + 40, 0);

    /* 5: TCP header cut by caplen. */
    o = put_eth(f[5].data, 0x0800);
    o += put_ipv4(f[5].data + o, 5, 40, 0, IPPROTO_TCP);
    put_tcp(f[5].data + o, 1, 2, 3, F_ACK, 5);
    frame_finish(&f[5], o + 10, 0);

    /* 6: TCP options (doff 8) run past caplen. */
    o = put_eth(f[6].data, 0x0800);
    o += put_ipv4(f[6].data + o, 5, 20 + 32, 0, IPPROTO_TCP);
    put_tcp(f[6].data + o, 1, 2, 3, F_ACK, 8);
    frame_finish(&f[6], o + 20, 0);

    /* 7: IPv6 header cut by caplen. */
    o = put_eth(f[7].data, 0x86DD);
    put_ipv6(f[7].data + o, 20, IPPROTO_TCP);
    frame_finish(&f[7], o + 30, 0);

    collector_t col;
    parser_file_info_t info;
    int rc = parse_frames(DLT_EN10MB, f, 8, &col, &info, NULL, 0);
    CHECK(rc == PCAPSTAT_OK);
    CHECK(col.count == 8);
    for (size_t i = 0; i < 8; i++) {
        CHECK(col.pkts[i].is_malformed);
        CHECK(!col.pkts[i].is_non_ip);
        CHECK(!col.pkts[i].is_fragment);
    }

    printf("    PASS\n");
}

/* ── Test: empty capture ──────────────────────────────────────────── */

static void test_empty_pcap(void)
{
    printf("  test_empty_pcap...\n");

    collector_t col;
    parser_file_info_t info;
    memset(&info, 0xAB, sizeof(info));
    int rc = parse_frames(DLT_EN10MB, NULL, 0, &col, &info, NULL, 0);
    CHECK(rc == PCAPSTAT_OK);
    CHECK(col.count == 0);
    CHECK(info.packets == 0);
    CHECK(!info.truncated);
    CHECK(info.error[0] == '\0');

    printf("    PASS\n");
}

/* ── Test: truncated tail → OK + warning + info.truncated (H1) ────── */

static void test_truncated_tail(void)
{
    printf("  test_truncated_tail...\n");

    frame_t good;
    build_eth_tcp4(&good, 40000, 80, F_SYN);

    char path[PCAPSTAT_MAX_PATH];
    char err[MSG_MAX];
    char expect[MSG_MAX];
    stderr_capture_t cap;
    collector_t col;
    parser_file_info_t info;
    int rc;

    /* A: 3 complete records + a 4th cut in the middle of its data. */
    FILE *fp = raw_pcap_create(path, sizeof(path));
    for (uint32_t i = 0; i < 3; i++)
        raw_pcap_full_record(fp, TEST_TS_BASE + i, &good);
    raw_pcap_record(fp, TEST_TS_BASE + 3, good.caplen, good.wire_len,
                    good.data, 16, good.caplen / 2);
    CHECK(fclose(fp) == 0);

    memset(&col, 0, sizeof(col));
    stderr_capture_begin(&cap);
    rc = parser_process_file_ex(path, collect_cb, &col, &info);
    stderr_capture_end(&cap, err, sizeof(err));
    CHECK(rc == PCAPSTAT_OK);
    CHECK(col.count == 3);
    CHECK(info.packets == 3);
    CHECK(info.truncated);
    CHECK(info.error[0] != '\0');
    snprintf(expect, sizeof(expect),
             "pcapstat: warning: '%s': %s (stopped after 3 packets)\n",
             path, info.error);
    CHECK(strcmp(err, expect) == 0);
    for (size_t i = 0; i < 3; i++) {
        check_clean(&col.pkts[i]);
        CHECK(col.pkts[i].dst_port == 80);
    }

    /* Same file through the info-less wrapper: still OK, still warns. */
    memset(&col, 0, sizeof(col));
    stderr_capture_begin(&cap);
    rc = parser_process_file(path, collect_cb, &col);
    stderr_capture_end(&cap, err, sizeof(err));
    CHECK(rc == PCAPSTAT_OK);
    CHECK(col.count == 3);
    CHECK(strcmp(err, expect) == 0);

    /* A callback that stops before the damaged record wins: its value is
     * returned and nothing is reported as truncated. */
    memset(&col, 0, sizeof(col));
    col.stop_at = 2;
    col.stop_rc = 9;
    stderr_capture_begin(&cap);
    rc = parser_process_file_ex(path, collect_cb, &col, &info);
    stderr_capture_end(&cap, err, sizeof(err));
    CHECK(rc == 9);
    CHECK(col.count == 2);
    CHECK(info.packets == 2);
    CHECK(!info.truncated);
    CHECK(info.error[0] == '\0');
    CHECK(err[0] == '\0');
    CHECK(unlink(path) == 0);

    /* B: 2 complete records + half of the 3rd record header. */
    fp = raw_pcap_create(path, sizeof(path));
    for (uint32_t i = 0; i < 2; i++)
        raw_pcap_full_record(fp, TEST_TS_BASE + i, &good);
    raw_pcap_record(fp, TEST_TS_BASE + 2, good.caplen, good.wire_len,
                    good.data, 8, 0);
    CHECK(fclose(fp) == 0);

    memset(&col, 0, sizeof(col));
    stderr_capture_begin(&cap);
    rc = parser_process_file_ex(path, collect_cb, &col, &info);
    stderr_capture_end(&cap, err, sizeof(err));
    CHECK(rc == PCAPSTAT_OK);
    CHECK(col.count == 2);
    CHECK(info.packets == 2);
    CHECK(info.truncated);
    CHECK(strstr(err, "pcapstat: warning: '") == err);
    CHECK(strstr(err, "(stopped after 2 packets)\n") != NULL);
    CHECK(unlink(path) == 0);

    printf("    PASS\n");
}

/* ── Test: corrupt records (H1) ───────────────────────────────────── */

static void test_corrupt_records(void)
{
    printf("  test_corrupt_records...\n");

    frame_t good;
    build_eth_tcp4(&good, 40000, 80, F_SYN);

    char path[PCAPSTAT_MAX_PATH];
    char err[MSG_MAX];
    char expect[MSG_MAX];
    stderr_capture_t cap;
    collector_t col;
    parser_file_info_t info;
    int rc;

    /* First record claims an impossible caplen: nothing readable. */
    FILE *fp = raw_pcap_create(path, sizeof(path));
    raw_pcap_record(fp, TEST_TS_BASE, 0x7FFFFFF0u, 0x7FFFFFF0u, good.data,
                    16, good.caplen);
    CHECK(fclose(fp) == 0);

    memset(&col, 0, sizeof(col));
    stderr_capture_begin(&cap);
    rc = parser_process_file_ex(path, collect_cb, &col, &info);
    stderr_capture_end(&cap, err, sizeof(err));
    CHECK(rc == PCAPSTAT_ERR_PCAP);
    CHECK(col.count == 0);
    CHECK(info.packets == 0);
    CHECK(!info.truncated);
    CHECK(info.error[0] != '\0');
    snprintf(expect, sizeof(expect), "pcapstat: cannot read '%s': %s\n",
             path, info.error);
    CHECK(strcmp(err, expect) == 0);

    /* Same through the wrapper. */
    stderr_capture_begin(&cap);
    rc = parser_process_file(path, collect_cb, &col);
    stderr_capture_end(&cap, err, sizeof(err));
    CHECK(rc == PCAPSTAT_ERR_PCAP);
    CHECK(unlink(path) == 0);

    /* Corrupt caplen after 2 good records: keep the 2, warn. */
    fp = raw_pcap_create(path, sizeof(path));
    for (uint32_t i = 0; i < 2; i++)
        raw_pcap_full_record(fp, TEST_TS_BASE + i, &good);
    raw_pcap_record(fp, TEST_TS_BASE + 2, 0x7FFFFFF0u, 60, good.data,
                    16, good.caplen);
    raw_pcap_full_record(fp, TEST_TS_BASE + 3, &good);
    CHECK(fclose(fp) == 0);

    memset(&col, 0, sizeof(col));
    stderr_capture_begin(&cap);
    rc = parser_process_file_ex(path, collect_cb, &col, &info);
    stderr_capture_end(&cap, err, sizeof(err));
    CHECK(rc == PCAPSTAT_OK);
    CHECK(col.count == 2);
    CHECK(info.packets == 2);
    CHECK(info.truncated);
    snprintf(expect, sizeof(expect),
             "pcapstat: warning: '%s': %s (stopped after 2 packets)\n",
             path, info.error);
    CHECK(strcmp(err, expect) == 0);
    CHECK(unlink(path) == 0);

    printf("    PASS\n");
}

/* ── Test: callback stop value of any sign is returned unchanged ──── */

static void test_callback_stop_any_sign(void)
{
    printf("  test_callback_stop_any_sign...\n");

    frame_t f[4];
    for (size_t i = 0; i < 4; i++)
        build_eth_tcp4(&f[i], (uint16_t)(1000 + i), 80, F_SYN);

    char path[PCAPSTAT_MAX_PATH];
    write_pcap(path, sizeof(path), DLT_EN10MB, f, 4);

    static const int stop_values[3] = { PCAPSTAT_ERR_NOMEM, -1000, 7 };
    for (size_t i = 0; i < 3; i++) {
        collector_t col;
        parser_file_info_t info;
        memset(&col, 0, sizeof(col));
        col.stop_at = 2;
        col.stop_rc = stop_values[i];
        int rc = parser_process_file_ex(path, collect_cb, &col, &info);
        CHECK(rc == stop_values[i]);
        CHECK(col.count == 2);
        CHECK(info.packets == 2);
        CHECK(!info.truncated);
        CHECK(info.error[0] == '\0');

        memset(&col, 0, sizeof(col));
        col.stop_at = 2;
        col.stop_rc = stop_values[i];
        rc = parser_process_file(path, collect_cb, &col);
        CHECK(rc == stop_values[i]);
        CHECK(col.count == 2);
    }

    CHECK(unlink(path) == 0);
    printf("    PASS\n");
}

/* ── Test: open / link-type failures fill info ────────────────────── */

static void test_open_and_link_errors(void)
{
    printf("  test_open_and_link_errors...\n");

    char err[MSG_MAX];
    stderr_capture_t cap;
    collector_t col;
    parser_file_info_t info;

    /* Unsupported link type (BSD loopback). */
    frame_t f;
    memset(&f, 0, sizeof(f));
    frame_finish(&f, 4, 40);
    int rc = parse_frames(DLT_NULL, &f, 1, &col, &info, err, sizeof(err));
    CHECK(rc == PCAPSTAT_ERR_PCAP);
    CHECK(col.count == 0);
    CHECK(info.packets == 0);
    CHECK(!info.truncated);
    CHECK(strstr(info.error, "unsupported link type") != NULL);
    CHECK(strstr(err, "pcapstat: unsupported link type") == err);

    /* Missing file. */
    memset(&col, 0, sizeof(col));
    stderr_capture_begin(&cap);
    rc = parser_process_file_ex("/nonexistent/x.pcap", collect_cb, &col,
                                &info);
    stderr_capture_end(&cap, err, sizeof(err));
    CHECK(rc == PCAPSTAT_ERR_IO);
    CHECK(col.count == 0);
    CHECK(info.packets == 0);
    CHECK(!info.truncated);
    CHECK(info.error[0] != '\0');
    CHECK(strstr(err, "pcapstat: cannot open '/nonexistent/x.pcap'") == err);

    printf("    PASS\n");
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

    test_non_ip_frames();
    test_ipv4_fragments();
    test_length_from_frame();
    test_length_from_frame_too_short();
    test_link_layers();
    test_qinq_and_ip_options();
    test_malformed_headers();
    test_empty_pcap();
    test_truncated_tail();
    test_corrupt_records();
    test_callback_stop_any_sign();
    test_open_and_link_errors();

    printf("All parser tests PASSED.\n");
    return 0;
}
