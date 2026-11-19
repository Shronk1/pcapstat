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
 * All multi-byte fields are in host byte order.
 */
typedef struct {
    double   timestamp;      /**< Seconds since epoch (µs precision). */
    uint32_t wire_len;       /**< Original packet length on the wire. */
    uint32_t cap_len;        /**< Captured bytes available in buffer. */

    uint8_t  ip_version;     /**< 4 or 6; 0 if L3 could not be decoded. */
    uint8_t  src_ip[16];     /**< Source IP (4 B for v4, 16 B for v6). */
    uint8_t  dst_ip[16];     /**< Destination IP. */
    uint8_t  proto;          /**< IPPROTO_TCP, IPPROTO_UDP, or other. */

    uint16_t src_port;       /**< Source port (host order); 0 if N/A. */
    uint16_t dst_port;       /**< Destination port (host order); 0 if N/A. */

    /* TCP-specific (zeroed for non-TCP packets). */
    uint8_t  tcp_flags;      /**< Raw TCP flags byte (SYN, ACK, …). */
    uint32_t tcp_seq;        /**< TCP sequence number (host order). */
    uint32_t tcp_ack;        /**< TCP acknowledgement number. */
    uint16_t tcp_window;     /**< TCP window size (unscaled). */
    uint32_t payload_len;    /**< L4 payload bytes (wire, not captured). */

    bool     is_malformed;   /**< true if any L2/L3/L4 header was invalid
                                  or truncated by caplen. */
} parsed_packet_t;

/**
 * @brief Per-packet callback invoked by @ref parser_process_file.
 *
 * @param pkt       Pointer to a fully populated parsed_packet_t.
 *                  **Borrowed** — valid only for the duration of this
 *                  callback invocation.  The caller must copy any data
 *                  it wishes to retain.
 * @param user_data Opaque pointer forwarded from parser_process_file().
 *
 * @return 0 to continue processing; non-zero to stop iteration early
 *         (the value is propagated as the return of parser_process_file).
 */
typedef int (*packet_handler_fn)(const parsed_packet_t *pkt, void *user_data);

/**
 * @brief Open a .pcap file and invoke @p cb for every packet.
 *
 * Supported link-layer types (via pcap_datalink()):
 *   - DLT_EN10MB   — Ethernet II, with 802.1Q (0x8100) and QinQ (0x88A8)
 *   - DLT_LINUX_SLL  — Linux cooked capture v1 (16-byte header)
 *   - DLT_LINUX_SLL2 — Linux cooked capture v2 (20-byte header)
 *   - DLT_RAW        — Raw IPv4/IPv6 (no link-layer header)
 *
 * Every header field is read via memcpy() into stack-local structs.
 * Before each read, `offset + sizeof(hdr) <= caplen` is verified;
 * on failure the packet is marked @c is_malformed and the callback is
 * still invoked so downstream code can count it.
 *
 * @param filepath   Path to the .pcap file (must be readable).
 * @param cb         Callback receiving each decoded packet.
 * @param user_data  Opaque context forwarded to @p cb.
 *
 * @return PCAPSTAT_OK        on success (all packets processed).
 * @return PCAPSTAT_ERR_IO    if the file cannot be opened.
 * @return PCAPSTAT_ERR_PCAP  if the link-layer type is unsupported.
 * @return (positive)         value returned by @p cb to stop early.
 */
int parser_process_file(const char *filepath,
                        packet_handler_fn cb,
                        void *user_data);

/**
 * @brief Format an IP address into a human-readable string.
 *
 * Uses inet_ntop() internally.  For IPv4 (@p ip_version == 4) only the
 * first 4 bytes of @p ip are used; for IPv6 all 16 bytes.
 *
 * @param ip_version  4 or 6.
 * @param ip          16-byte IP buffer (as stored in parsed_packet_t).
 * @param buf         Output buffer (caller-owned).
 * @param buf_len     Size of @p buf (>= INET6_ADDRSTRLEN recommended).
 */
void parser_format_ip(uint8_t ip_version,
                      const uint8_t ip[16],
                      char *buf,
                      size_t buf_len);

#endif /* PCAPSTAT_PARSER_H */
