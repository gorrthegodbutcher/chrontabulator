/* Copied verbatim from dpdk-app-example's src/common.c (the sibling
 * traffic-generator project this repo captures from) - no DPDK/SPDK
 * dependency, so it's portable as-is. Keep in sync with that project if
 * its wire format ever changes. */
#include <string.h>
#include <stdio.h>
#include "common.h"

const uint8_t g_broadcast_mac[ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static void
put_be16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)(v);
}

static void
put_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)(v);
}

static void
put_be64(uint8_t *p, uint64_t v)
{
	put_be32(p, (uint32_t)(v >> 32));
	put_be32(p + 4, (uint32_t)v);
}

static uint16_t
get_be16(const uint8_t *p)
{
	return ((uint16_t)p[0] << 8) | p[1];
}

static uint64_t
get_be64(const uint8_t *p)
{
	uint64_t hi = ((uint64_t)p[0] << 24) | ((uint64_t)p[1] << 16) |
		      ((uint64_t)p[2] << 8) | (uint64_t)p[3];
	uint64_t lo = ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
		      ((uint64_t)p[6] << 8) | (uint64_t)p[7];
	return (hi << 32) | lo;
}

/* Standard one's-complement-of-one's-complement-sum IPv4 header checksum.
 * Called with the checksum field itself already zeroed. */
static uint16_t
ip_checksum(const uint8_t *hdr, uint32_t len)
{
	uint32_t sum = 0;
	for (uint32_t i = 0; i + 1 < len; i += 2)
		sum += get_be16(hdr + i);
	if (len & 1)
		sum += (uint32_t)hdr[len - 1] << 8;
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	return (uint16_t)~sum;
}

/* UDP checksum over the IPv4 pseudo-header + UDP header + payload. Called
 * with the UDP checksum field itself already zeroed. A zero UDP checksum
 * is valid per RFC 768 ("not computed"), but some NIC RX hardware treats
 * it as invalid and silently drops the frame - so compute a real one
 * rather than relying on that exception. Per RFC 768, a computed result
 * of exactly 0 is transmitted as all-ones instead (0 is reserved to mean
 * "not computed"). */
static uint16_t
udp_checksum(const uint8_t src_ip[4], const uint8_t dst_ip[4],
	     const uint8_t *udp, uint32_t udp_len)
{
	uint32_t sum = 0;

	sum += get_be16(src_ip);
	sum += get_be16(src_ip + 2);
	sum += get_be16(dst_ip);
	sum += get_be16(dst_ip + 2);
	sum += 17; /* protocol = UDP */
	sum += udp_len;

	for (uint32_t i = 0; i + 1 < udp_len; i += 2)
		sum += get_be16(udp + i);
	if (udp_len & 1)
		sum += (uint32_t)udp[udp_len - 1] << 8;

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	uint16_t result = (uint16_t)~sum;
	return result == 0 ? 0xFFFF : result;
}

int
app_build_packet(uint8_t *buf, uint32_t buf_capacity, uint32_t total_pkt_len,
		  const uint8_t dst_mac[ETHER_ADDR_LEN], const uint8_t src_mac[ETHER_ADDR_LEN],
		  const uint8_t src_ip[4], const uint8_t dst_ip[4],
		  uint16_t src_port, uint16_t dst_port,
		  uint64_t seq, const uint8_t *payload, uint32_t payload_len)
{
	if (total_pkt_len < APP_HDR_LEN + payload_len || total_pkt_len > buf_capacity)
		return -1;

	/* Ethernet */
	memcpy(buf, dst_mac, ETHER_ADDR_LEN);
	memcpy(buf + 6, src_mac, ETHER_ADDR_LEN);
	put_be16(buf + 12, 0x0800); /* IPv4 */

	/* IPv4 */
	uint8_t *ip = buf + ETH_HDR_LEN;
	/* Derived from total_pkt_len, NOT payload_len - a caller building a
	 * fixed-size packet with a real payload shorter than total_pkt_len
	 * (e.g. run_seq_mode()'s --size=N with payload=NULL,0, relying on
	 * the zero-padding below to reach N bytes) needs the header's own
	 * declared length to cover that full padded size. Using payload_len
	 * alone here was a real bug: the zero-padding was written to the
	 * buffer correctly, but the IP/UDP headers declared a much shorter
	 * packet, so any correct parser (including this project's own
	 * app_parse_packet()) read back payload_len=0 for every "512-byte"
	 * packet sent this way - confirmed live via chrontabulator capturing
	 * real traffic and seeing len=0 on every record despite genuinely
	 * larger frames on the wire. total_pkt_len is already validated
	 * above (>= APP_HDR_LEN + payload_len), so this is always >= the
	 * minimum header size. */
	uint32_t ip_total_len = total_pkt_len - ETH_HDR_LEN;
	ip[0] = 0x45;
	ip[1] = 0x00;
	put_be16(ip + 2, (uint16_t)ip_total_len);
	put_be16(ip + 4, 0);      /* identification */
	put_be16(ip + 6, 0);      /* flags/fragment offset */
	ip[8] = 64;               /* TTL */
	ip[9] = 17;               /* UDP */
	put_be16(ip + 10, 0);     /* checksum, filled in below */
	memcpy(ip + 12, src_ip, 4);
	memcpy(ip + 16, dst_ip, 4);
	put_be16(ip + 10, ip_checksum(ip, IPV4_HDR_LEN));

	/* UDP */
	uint8_t *udp = ip + IPV4_HDR_LEN;
	/* Same total_pkt_len-derived fix as ip_total_len above. */
	uint32_t udp_len = total_pkt_len - ETH_HDR_LEN - IPV4_HDR_LEN;
	put_be16(udp, src_port);
	put_be16(udp + 2, dst_port);
	put_be16(udp + 4, (uint16_t)udp_len);
	put_be16(udp + 6, 0); /* checksum filled in below, once the full segment is written */

	/* seq + payload */
	uint8_t *body = udp + UDP_HDR_LEN;
	put_be64(body, seq);
	if (payload_len > 0)
		memcpy(body + SEQ_LEN, payload, payload_len);

	uint32_t used = APP_HDR_LEN + payload_len;
	if (used < total_pkt_len)
		memset(buf + used, 0, total_pkt_len - used);

	put_be16(udp + 6, udp_checksum(src_ip, dst_ip, udp, udp_len));

	return 0;
}

int
app_parse_packet(const uint8_t *buf, uint32_t len, uint16_t *out_dst_port,
		  uint64_t *out_seq, const uint8_t **out_payload, uint32_t *out_payload_len)
{
	if (len < ETH_HDR_LEN + IPV4_HDR_LEN)
		return -1;

	if (get_be16(buf + 12) != 0x0800)
		return -1;

	const uint8_t *ip = buf + ETH_HDR_LEN;
	if ((ip[0] >> 4) != 4)
		return -1;
	uint32_t ip_hdr_len = (uint32_t)(ip[0] & 0x0F) * 4;
	if (ip_hdr_len < IPV4_HDR_LEN || len < ETH_HDR_LEN + ip_hdr_len + UDP_HDR_LEN)
		return -1;
	if (ip[9] != 17) /* not UDP */
		return -1;

	const uint8_t *udp = ip + ip_hdr_len;
	uint16_t dst_port = get_be16(udp + 2);
	uint32_t udp_len = get_be16(udp + 4);
	if (udp_len < UDP_HDR_LEN + SEQ_LEN ||
	    ETH_HDR_LEN + ip_hdr_len + udp_len > len)
		return -1;

	const uint8_t *body = udp + UDP_HDR_LEN;
	uint64_t seq = get_be64(body);
	uint32_t payload_len = udp_len - UDP_HDR_LEN - SEQ_LEN;

	*out_dst_port = dst_port;
	*out_seq = seq;
	*out_payload = body + SEQ_LEN;
	*out_payload_len = payload_len;
	return 0;
}

int
app_parse_ipv4(const char *s, uint8_t out[4])
{
	unsigned int b[4];
	int n = sscanf(s, "%u.%u.%u.%u", &b[0], &b[1], &b[2], &b[3]);
	if (n != 4)
		return -1;
	for (int i = 0; i < 4; i++) {
		if (b[i] > 255)
			return -1;
		out[i] = (uint8_t)b[i];
	}
	return 0;
}
