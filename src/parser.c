/**
 * @file parser.c
 * @brief Safe L2/L3/L4 packet parser implementation.
 *
 * All network headers are read via memcpy() into stack-local structs
 * to avoid unaligned-access UB.  Every read is preceded by a caplen
 * bounds check.
 */

#include "parser.h"

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>

/* ── Link-layer constants ───────────────────────────────────────────── */

#define ETH_HLEN_CONST   14   /* Ethernet II header length             */
#define VLAN_TAG_LEN      4   /* 802.1Q tag length (TPID + TCI)        */
#define SLL_HDR_LEN      16   /* Linux cooked capture v1               */
#define SLL2_HDR_LEN     20   /* Linux cooked capture v2               */
#define IPV6_HDR_LEN     40   /* Base IPv6 header (no extensions)      */

/* EtherType values */
#define ETHERTYPE_VLAN_8021Q  0x8100
#define ETHERTYPE_VLAN_QINQ   0x88A8

/* ── Forward declarations ───────────────────────────────────────────── */

static void decode_ip(const uint8_t *data, uint32_t caplen,
                      uint32_t offset, uint16_t ethertype,
                      parsed_packet_t *pkt);
static void decode_ipv4(const uint8_t *data, uint32_t caplen,
                        uint32_t offset, parsed_packet_t *pkt);
static void decode_ipv6(const uint8_t *data, uint32_t caplen,
                        uint32_t offset, parsed_packet_t *pkt);
static void decode_tcp(const uint8_t *data, uint32_t caplen,
                       uint32_t offset, uint32_t ip_payload_len,
                       parsed_packet_t *pkt);
static void decode_udp(const uint8_t *data, uint32_t caplen,
                       uint32_t offset, parsed_packet_t *pkt);

/* ── Public API ─────────────────────────────────────────────────────── */

int parser_process_file(const char *filepath,
                        packet_handler_fn cb,
                        void *user_data)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(filepath, errbuf);
    if (!handle) {
        fprintf(stderr, "pcapstat: cannot open '%s': %s\n", filepath, errbuf);
        return PCAPSTAT_ERR_IO;
    }

    int dlt = pcap_datalink(handle);
    bool dlt_is_en10mb  = false;
    bool dlt_is_sll     = false;
    bool dlt_is_sll2    = false;
    bool dlt_is_raw     = false;

    switch (dlt) {
    case DLT_EN10MB:     dlt_is_en10mb = true;  break;
    case DLT_LINUX_SLL:  dlt_is_sll    = true;  break;
#ifdef DLT_LINUX_SLL2
    case DLT_LINUX_SLL2: dlt_is_sll2   = true;  break;
#endif
    case DLT_RAW:        dlt_is_raw    = true;  break;
    default:
        fprintf(stderr, "pcapstat: unsupported link type %d in '%s'\n",
                dlt, filepath);
        pcap_close(handle);
        return PCAPSTAT_ERR_PCAP;
    }

    struct pcap_pkthdr *hdr = NULL;
    const uint8_t *raw      = NULL;
    int rc;
    int ret = PCAPSTAT_OK;

    while ((rc = pcap_next_ex(handle, &hdr, &raw)) == 1) {
        parsed_packet_t pkt;
        memset(&pkt, 0, sizeof(pkt));

        pkt.timestamp = (double)hdr->ts.tv_sec
                      + (double)hdr->ts.tv_usec / 1e6;
        pkt.wire_len  = (uint32_t)hdr->len;
        pkt.cap_len   = (uint32_t)hdr->caplen;

        uint32_t offset = 0;
        uint16_t ethertype = 0;

        /* ── L2 decode ─────────────────────────────────────────────── */
        if (dlt_is_en10mb) {
            if (pkt.cap_len < ETH_HLEN_CONST) {
                pkt.is_malformed = true;
                goto invoke_cb;
            }
            /* Read EtherType from bytes 12-13 of Ethernet header. */
            uint16_t etype_raw;
            memcpy(&etype_raw, raw + 12, sizeof(etype_raw));
            ethertype = ntohs(etype_raw);
            offset = ETH_HLEN_CONST;

            /* Peel 802.1Q / QinQ VLAN tags */
            while ((ethertype == ETHERTYPE_VLAN_8021Q ||
                    ethertype == ETHERTYPE_VLAN_QINQ) &&
                   offset + VLAN_TAG_LEN <= pkt.cap_len) {
                /* bytes 0-1 of VLAN tag = TCI, bytes 2-3 = inner EtherType */
                uint16_t inner_raw;
                memcpy(&inner_raw, raw + offset + 2, sizeof(inner_raw));
                ethertype = ntohs(inner_raw);
                offset += VLAN_TAG_LEN;
            }
        } else if (dlt_is_sll) {
            if (pkt.cap_len < SLL_HDR_LEN) {
                pkt.is_malformed = true;
                goto invoke_cb;
            }
            /* SLL protocol field at bytes 14-15 */
            uint16_t proto_raw;
            memcpy(&proto_raw, raw + 14, sizeof(proto_raw));
            ethertype = ntohs(proto_raw);
            offset = SLL_HDR_LEN;
        } else if (dlt_is_sll2) {
            if (pkt.cap_len < SLL2_HDR_LEN) {
                pkt.is_malformed = true;
                goto invoke_cb;
            }
            /* SLL2 protocol field at bytes 0-1 */
            uint16_t proto_raw;
            memcpy(&proto_raw, raw, sizeof(proto_raw));
            ethertype = ntohs(proto_raw);
            offset = SLL2_HDR_LEN;
        } else if (dlt_is_raw) {
            offset = 0;
            /* Determine IP version from first nibble */
            if (pkt.cap_len < 1) {
                pkt.is_malformed = true;
                goto invoke_cb;
            }
            uint8_t ver = (raw[0] >> 4) & 0x0F;
            if (ver == 4)
                ethertype = ETHERTYPE_IP;
            else if (ver == 6)
                ethertype = ETHERTYPE_IPV6;
            else {
                pkt.is_malformed = true;
                goto invoke_cb;
            }
        }

        /* ── L3/L4 decode ──────────────────────────────────────────── */
        decode_ip(raw, pkt.cap_len, offset, ethertype, &pkt);

invoke_cb:
        ret = cb(&pkt, user_data);
        if (ret != 0)
            break;
    }

    pcap_close(handle);
    return ret;
}

void parser_format_ip(uint8_t ip_version,
                      const uint8_t ip[16],
                      char *buf,
                      size_t buf_len)
{
    if (buf_len == 0)
        return;
    buf[0] = '\0';

    if (ip_version == 4) {
        inet_ntop(AF_INET, ip, buf, (socklen_t)buf_len);
    } else if (ip_version == 6) {
        inet_ntop(AF_INET6, ip, buf, (socklen_t)buf_len);
    }
}

/* ── Static helpers ─────────────────────────────────────────────────── */

static void decode_ip(const uint8_t *data, uint32_t caplen,
                      uint32_t offset, uint16_t ethertype,
                      parsed_packet_t *pkt)
{
    if (ethertype == ETHERTYPE_IP) {
        decode_ipv4(data, caplen, offset, pkt);
    } else if (ethertype == ETHERTYPE_IPV6) {
        decode_ipv6(data, caplen, offset, pkt);
    } else {
        /* Unknown or unsupported L3 — not necessarily malformed,
         * just not TCP/UDP traffic we care about. */
        pkt->is_malformed = true;
    }
}

static void decode_ipv4(const uint8_t *data, uint32_t caplen,
                        uint32_t offset, parsed_packet_t *pkt)
{
    /* Need at least 20 bytes for a minimal IPv4 header */
    if (offset + (uint32_t)sizeof(struct iphdr) > caplen) {
        pkt->is_malformed = true;
        return;
    }

    struct iphdr iph;
    memcpy(&iph, data + offset, sizeof(iph));

    uint8_t ihl = iph.ihl;
    if (ihl < 5) {
        pkt->is_malformed = true;
        return;
    }

    uint32_t ip_hdr_len = (uint32_t)ihl * 4;
    uint16_t tot_len    = ntohs(iph.tot_len);

    if (tot_len < ip_hdr_len) {
        pkt->is_malformed = true;
        return;
    }

    /* Verify the full IP header (including options) is captured */
    if (offset + ip_hdr_len > caplen) {
        pkt->is_malformed = true;
        return;
    }

    pkt->ip_version = 4;
    memcpy(pkt->src_ip, &iph.saddr, 4);
    memcpy(pkt->dst_ip, &iph.daddr, 4);
    pkt->proto = iph.protocol;

    uint32_t l4_offset      = offset + ip_hdr_len;
    uint32_t ip_payload_len = (uint32_t)tot_len - ip_hdr_len;

    /* Decode L4 */
    if (pkt->proto == IPPROTO_TCP) {
        decode_tcp(data, caplen, l4_offset, ip_payload_len, pkt);
    } else if (pkt->proto == IPPROTO_UDP) {
        decode_udp(data, caplen, l4_offset, pkt);
    }
    /* Other protocols: leave ports/flags zeroed, not malformed. */
}

static void decode_ipv6(const uint8_t *data, uint32_t caplen,
                        uint32_t offset, parsed_packet_t *pkt)
{
    if (offset + IPV6_HDR_LEN > caplen) {
        pkt->is_malformed = true;
        return;
    }

    struct ip6_hdr ip6h;
    memcpy(&ip6h, data + offset, sizeof(ip6h));

    pkt->ip_version = 6;
    memcpy(pkt->src_ip, &ip6h.ip6_src, 16);
    memcpy(pkt->dst_ip, &ip6h.ip6_dst, 16);
    pkt->proto = ip6h.ip6_nxt;

    uint32_t ip_payload_len = (uint32_t)ntohs(ip6h.ip6_plen);
    uint32_t l4_offset      = offset + IPV6_HDR_LEN;

    /* NOTE: We decode only the base header (next-header directly).
     * Extension header chaining is not implemented. */
    if (pkt->proto == IPPROTO_TCP) {
        decode_tcp(data, caplen, l4_offset, ip_payload_len, pkt);
    } else if (pkt->proto == IPPROTO_UDP) {
        decode_udp(data, caplen, l4_offset, pkt);
    }
}

static void decode_tcp(const uint8_t *data, uint32_t caplen,
                       uint32_t offset, uint32_t ip_payload_len,
                       parsed_packet_t *pkt)
{
    /* Need at least 20 bytes for a minimal TCP header */
    if (offset + (uint32_t)sizeof(struct tcphdr) > caplen) {
        pkt->is_malformed = true;
        return;
    }

    struct tcphdr th;
    memcpy(&th, data + offset, sizeof(th));

    uint8_t doff = th.doff;
    if (doff < 5) {
        pkt->is_malformed = true;
        return;
    }

    uint32_t tcp_hdr_len = (uint32_t)doff * 4;

    /* Verify the full TCP header (including options) fits in capture */
    if (offset + tcp_hdr_len > caplen) {
        pkt->is_malformed = true;
        return;
    }

    pkt->src_port   = ntohs(th.source);
    pkt->dst_port   = ntohs(th.dest);
    pkt->tcp_seq    = ntohl(th.seq);
    pkt->tcp_ack    = ntohl(th.ack_seq);
    pkt->tcp_window = ntohs(th.window);

    /* Build flags byte: bit layout FIN=0x01 SYN=0x02 RST=0x04
     * PSH=0x08 ACK=0x10 URG=0x20 ECE=0x40 CWR=0x80.
     * Linux struct tcphdr uses bitfields; read from raw byte instead
     * to avoid endian/bitfield layout assumptions. */
    uint8_t flags_byte;
    memcpy(&flags_byte, data + offset + 13, 1);
    pkt->tcp_flags = flags_byte;

    /* Payload length: IP payload minus TCP header, clamped to 0 */
    if (ip_payload_len > tcp_hdr_len)
        pkt->payload_len = ip_payload_len - tcp_hdr_len;
    else
        pkt->payload_len = 0;
}

static void decode_udp(const uint8_t *data, uint32_t caplen,
                       uint32_t offset, parsed_packet_t *pkt)
{
    if (offset + (uint32_t)sizeof(struct udphdr) > caplen) {
        pkt->is_malformed = true;
        return;
    }

    struct udphdr uh;
    memcpy(&uh, data + offset, sizeof(uh));

    uint16_t udp_len = ntohs(uh.len);
    if (udp_len < 8) {
        pkt->is_malformed = true;
        return;
    }

    pkt->src_port    = ntohs(uh.source);
    pkt->dst_port    = ntohs(uh.dest);
    pkt->payload_len = (uint32_t)(udp_len - 8);
}
