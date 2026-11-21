/**
 * @file parser.h
 * @brief Safe L2/L3/L4 packet parser for pcap captures.
 *
 * Reads .pcap files via libpcap, decoding Ethernet (with 802.1Q/QinQ),
 * Linux SLL/SLL2, and raw IP frames into a unified @ref parsed_packet_t
 * struct.  All header reads use memcpy() into local variables to avoid
 * unaligned-access UB, and every read is bounds-checked against caplen.
 */

#ifndef PCAPSTAT_PARSER_H
#define PCAPSTAT_PARSER_H

#include "common.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Unified decoded packet representation.
 *
 * Filled by the parser for every packet (including malformed ones).
 * IPv4 addresses occupy the first 4 bytes of src_ip/dst_ip with the
 * remaining 12 bytes zeroed; IPv6 uses all 16 bytes.
 * All multi-byte fields are in host byte order.  Every field not set by
 * the decoder is zero/false.
 *
 * Classification flags (at most one of them is true):
 *   - @c is_malformed — a header was invalid or cut short by caplen;
 *     L3/L4 fields may be partially filled and must not be trusted.
 *   - @c is_non_ip    — the link layer decoded fine but carries another
 *     protocol (ARP, LLDP, STP, ...); @c ip_version == 0.
 *   - @c is_fragment  — IPv4 non-first fragment; L3 fields and @c proto
 *     are valid, L4 fields are 0.
 */
typedef struct {
    double   timestamp;      /**< Seconds since epoch (µs precision). */
    uint32_t wire_len;       /**< Original packet length on the wire. */
    uint32_t cap_len;        /**< Captured bytes available in buffer. */

    uint8_t  ip_version;     /**< 4 or 6; 0 if L3 could not be decoded
                                  or the frame is not IP (@c is_non_ip). */
    uint8_t  src_ip[16];     /**< Source IP (4 B for v4, 16 B for v6). */
    uint8_t  dst_ip[16];     /**< Destination IP. */
    uint8_t  proto;          /**< IPPROTO_TCP, IPPROTO_UDP, or other. */

    uint16_t src_port;       /**< Source port (host order); 0 if N/A
                                  (including IPv4 non-first fragments). */
    uint16_t dst_port;       /**< Destination port (host order); 0 if N/A. */

    /* TCP-specific (zeroed for non-TCP packets and fragments). */
    uint8_t  tcp_flags;      /**< Raw TCP flags byte (SYN, ACK, …). */
    uint32_t tcp_seq;        /**< TCP sequence number (host order). */
    uint32_t tcp_ack;        /**< TCP acknowledgement number. */
    uint16_t tcp_window;     /**< TCP window size (unscaled). */
    uint32_t payload_len;    /**< L4 payload bytes (wire, not captured).
                                  TCP: IP payload minus TCP header, where an
                                  IPv4 @c tot_len of 0 or IPv6 @c plen of 0
                                  (TSO / BIG TCP on the sending host) means
                                  "length taken from @c wire_len".
                                  UDP: UDP length field minus 8.
                                  0 for fragments and other protocols. */

    bool     is_malformed;   /**< true if any L2/L3/L4 header was invalid
                                  or truncated by caplen (including a VLAN
                                  tag cut short by caplen). */
    bool     is_non_ip;      /**< true if L2 decoded fine, but the
                                  EtherType/SLL protocol is not IPv4/IPv6
                                  (ARP, LLDP, STP, ...).  Then
                                  @c is_malformed == false and
                                  @c ip_version == 0. */
    bool     is_fragment;    /**< true for an IPv4 non-first fragment
                                  (fragment offset != 0).  L3 fields valid,
                                  @c proto set; ports, TCP fields and
                                  @c payload_len are 0.  First fragments
                                  (offset 0, MF set) are decoded normally
                                  and leave this false. */
} parsed_packet_t;

/**
 * @brief Per-file outcome reported by @ref parser_process_file_ex.
 *
 * Caller-owned (typically on the stack); the parser zeroes it on entry
 * and fills it before returning, on success and on failure.  Contains no
 * pointers, so nothing needs to be freed.
 */
typedef struct {
    uint64_t packets;     /**< Frames delivered to the callback (including
                               the one whose non-zero return stopped
                               parsing). */
    bool     truncated;   /**< true if reading stopped on PCAP_ERROR after
                               >= 1 packet (truncated or corrupt tail); the
                               function still returns PCAPSTAT_OK. */
    char     error[256];  /**< NUL-terminated libpcap error text
                               (pcap_geterr(), or the open/link-type error)
                               if the file was truncated or failed, else
                               "". */
} parser_file_info_t;

/**
 * @brief Per-packet callback invoked by @ref parser_process_file_ex.
 *
 * @param pkt       Pointer to a fully populated parsed_packet_t.
 *                  **Borrowed** — valid only for the duration of this
 *                  callback invocation.  The caller must copy any data
 *                  it wishes to retain.
 * @param user_data Opaque pointer forwarded from parser_process_file_ex().
 *
 * @return 0 to continue with the next packet; any non-zero value (of
 *         either sign) stops parsing immediately, and that value is
 *         returned unchanged by parser_process_file_ex() /
 *         parser_process_file().  Packets after it are not read.
 */
typedef int (*packet_handler_fn)(const parsed_packet_t *pkt, void *user_data);

/**
 * @brief Open a .pcap file and invoke @p cb for every packet.
 *
 * Supported link-layer types (via pcap_datalink()):
 *   - DLT_EN10MB   — Ethernet II, with 802.1Q (0x8100) and QinQ (0x88A8)
 *   - DLT_LINUX_SLL  — Linux cooked capture v1 (16-byte header)
 *   - DLT_LINUX_SLL2 — Linux cooked capture v2 (20-byte header)
 *   - DLT_RAW        — Raw IPv4/IPv6 (no link-layer header; a version
 *                      nibble other than 4/6 is malformed)
 *
 * Every header field is read via memcpy() into stack-local structs.
 * Before each read, `offset + sizeof(hdr) <= caplen` is verified;
 * on failure the packet is marked @c is_malformed and the callback is
 * still invoked so downstream code can count it.  Non-IP frames and
 * IPv4 non-first fragments are delivered with @c is_non_ip /
 * @c is_fragment set (see @ref parsed_packet_t).  IPv6 extension headers
 * are not walked: such packets carry the extension's next-header value
 * in @c proto.
 *
 * Damaged files: a read error (PCAP_ERROR, e.g. a record cut short
 * because the capture was killed, or an impossible caplen) before the
 * first packet prints an error and fails; after >= 1 packet it prints
 * `pcapstat: warning: '<file>': <pcap error> (stopped after N packets)`
 * to stderr, sets @c info->truncated, and returns PCAPSTAT_OK so the
 * readable part is still analyzed.
 *
 * @param filepath   Path to the .pcap file (must be readable).
 * @param cb         Callback receiving each decoded packet.
 * @param user_data  Opaque context forwarded to @p cb.
 * @param info       Optional (may be NULL) caller-owned outcome record;
 *                   zeroed on entry and always filled on return.
 *
 * @return PCAPSTAT_OK        if the whole file was read, or reading stopped
 *                            on a read error after >= 1 packet
 *                            (@c info->truncated set, warning printed).
 * @return PCAPSTAT_ERR_IO    if the file cannot be opened (missing,
 *                            unreadable, or not a valid pcap header).
 * @return PCAPSTAT_ERR_PCAP  if the link-layer type is unsupported, or a
 *                            read error occurs before any packet.
 * @return (other non-zero)   the value returned by @p cb to stop early,
 *                            unchanged (any sign).
 */
int parser_process_file_ex(const char *filepath,
                           packet_handler_fn cb,
                           void *user_data,
                           parser_file_info_t *info);

/**
 * @brief Convenience wrapper without the outcome record.
 *
 * Exactly equivalent to
 * `parser_process_file_ex(filepath, cb, user_data, NULL)`, including the
 * stderr warning for truncated files.
 *
 * @param filepath   Path to the .pcap file (must be readable).
 * @param cb         Callback receiving each decoded packet.
 * @param user_data  Opaque context forwarded to @p cb.
 *
 * @return Same values as @ref parser_process_file_ex.
 */
int parser_process_file(const char *filepath,
                        packet_handler_fn cb,
                        void *user_data);

/**
 * @brief Format an IP address into a human-readable string.
 *
 * Uses inet_ntop() internally.  For IPv4 (@p ip_version == 4) only the
 * first 4 bytes of @p ip are used; for IPv6 all 16 bytes.  Any other
 * version (e.g. 0 for non-IP or malformed frames), or a @p buf too small
 * for the address, yields an empty string.  Nothing is written when
 * @p buf_len is 0.
 *
 * @param ip_version  4 or 6.
 * @param ip          16-byte IP buffer (as stored in parsed_packet_t);
 *                    borrowed, read only.
 * @param buf         Output buffer (caller-owned), always NUL-terminated
 *                    when @p buf_len > 0.
 * @param buf_len     Size of @p buf (>= INET6_ADDRSTRLEN recommended).
 */
void parser_format_ip(uint8_t ip_version,
                      const uint8_t ip[16],
                      char *buf,
                      size_t buf_len);

#endif /* PCAPSTAT_PARSER_H */
