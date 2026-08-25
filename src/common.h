#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

/* Standard Ethernet + IPv4 + UDP frame, no custom protocol fields except
 * an 8-byte big-endian sequence number as the first 8 bytes of the UDP
 * payload - this is what the real embedded device sends, so this app
 * needs to speak real UDP, not a made-up format.
 *
 *   [0:6)     dst MAC
 *   [6:12)    src MAC
 *   [12:14)   ethertype = 0x0800 (IPv4)
 *   [14]      version/IHL = 0x45 (IPv4, 20-byte header, no options)
 *   [15]      DSCP/ECN = 0
 *   [16:18)   total length (IP header + UDP header + UDP payload)
 *   [18:20)   identification = 0
 *   [20:22)   flags/fragment offset = 0
 *   [22]      TTL = 64
 *   [23]      protocol = 17 (UDP)
 *   [24:26)   IPv4 header checksum (computed)
 *   [26:30)   src IP
 *   [30:34)   dst IP
 *   [34:36)   UDP src port
 *   [36:38)   UDP dst port
 *   [38:40)   UDP length (UDP header + UDP payload)
 *   [40:42)   UDP checksum (computed) - a real checksum, not the RFC 768
 *             "0 = not computed" shortcut, since real NIC RX hardware has
 *             been observed silently dropping zero-checksum UDP frames
 *   [42:50)   seq (8 bytes, big-endian) - the sequence number
 *   [50:...)  payload, then zero-padded to the packet's total on-wire
 *             length
 *
 * There's no built-in way to tell this traffic apart from anything else
 * on the wire the way a custom EtherType + magic number could - the
 * receiver is expected to filter by UDP destination port and/or exact
 * frame size instead (see receiver's --port/--pkt-size).
 */

#define ETHER_ADDR_LEN   6
#define ETH_HDR_LEN      14u
#define IPV4_HDR_LEN     20u
#define UDP_HDR_LEN      8u
#define SEQ_LEN          8u
#define APP_HDR_LEN      (ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN + SEQ_LEN)  /* 50 */

extern const uint8_t g_broadcast_mac[ETHER_ADDR_LEN];

/* Writes a full Ethernet+IPv4+UDP frame into buf: MACs, IPv4 header (with
 * a correct header checksum), UDP header, an 8-byte sequence number, then
 * payload padded with zeros up to total_pkt_len bytes.
 *
 * src_ip/dst_ip are 4-byte arrays, network byte order (as from
 * inet_pton/similar - see sender.c's IP parsing).
 *
 * Returns 0 on success, -1 if total_pkt_len can't fit APP_HDR_LEN +
 * payload_len, or exceeds buf_capacity. */
int app_build_packet(uint8_t *buf, uint32_t buf_capacity, uint32_t total_pkt_len,
                      const uint8_t dst_mac[ETHER_ADDR_LEN],
                      const uint8_t src_mac[ETHER_ADDR_LEN],
                      const uint8_t src_ip[4], const uint8_t dst_ip[4],
                      uint16_t src_port, uint16_t dst_port,
                      uint64_t seq, const uint8_t *payload, uint32_t payload_len);

/* Parses buf as an Ethernet+IPv4+UDP frame. On success returns 0 and sets
 * *out_dst_port, *out_seq, *out_payload (points into buf, right after the
 * 8-byte sequence number), *out_payload_len. Returns -1 if this isn't a
 * well-formed IPv4/UDP frame, or too short to contain a sequence number -
 * the caller should treat that as "not one of ours", not as an error,
 * since real non-UDP traffic (ARP, LLDP, ...) will show up on the wire.
 *
 * Does NOT filter by port or size - deliberately left to the caller
 * (receiver.c), since those are runtime-configurable, not protocol
 * constants. */
int app_parse_packet(const uint8_t *buf, uint32_t len, uint16_t *out_dst_port,
                      uint64_t *out_seq, const uint8_t **out_payload,
                      uint32_t *out_payload_len);

/* Parses "A.B.C.D" into 4 bytes (network byte order). Returns 0 on
 * success, -1 on malformed input. */
int app_parse_ipv4(const char *s, uint8_t out[4]);

#endif
