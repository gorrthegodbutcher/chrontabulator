/* Minimal ARP + ICMP-echo responder, "just enough to fake it" rather than
 * a network stack. Deliberately does NOT handle: IP fragmentation, VLAN
 * tags, IPv6/NDP, ARP replies/gratuitous ARP (only answers opcode
 * REQUEST), IP header options (only the plain 20-byte header), or any
 * ICMP type other than echo request. Anything outside that scope is left
 * completely alone for the caller's existing UDP-capture path to see and
 * (correctly) ignore.
 *
 * Both handlers use the classic DPDK "reflect" pattern: rewrite the
 * request in place into a reply and hand the same mbuf straight to
 * rte_eth_tx_burst() - no second mempool, no resize (an ARP reply is the
 * same size as the request, and an ICMP echo reply is required to mirror
 * the request's payload byte-for-byte anyway). If the burst can't accept
 * it (ring momentarily full), the packet is just dropped, no retry -
 * unlike dpdk-app-example's sender.c, this isn't a correctness bug for
 * this use case: ARP/ping traffic is inherently low-rate and the peer's
 * own ARP/ping stack already retries on its own timeout, so there's no
 * risk of a saturated ring jamming permanently the way an unthrottled
 * bulk UDP sender could. */

#include <string.h>
#include <netinet/in.h>

#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_icmp.h>
#include <rte_ip4.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_byteorder.h>

#include "chrono_ctx.h"
#include "net_responder.h"

static bool
tx_or_free(struct app_context_t *ctx, struct rte_mbuf *m)
{
	if (rte_eth_tx_burst(ctx->port, 0, &m, 1) == 0)
		rte_pktmbuf_free(m);
	return true;
}

static bool
try_arp(struct app_context_t *ctx, struct rte_mbuf *m, struct rte_ether_hdr *eth)
{
	if (rte_pktmbuf_data_len(m) < sizeof(*eth) + sizeof(struct rte_arp_hdr))
		return false;

	struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);

	if (arp->arp_hardware != rte_cpu_to_be_16(RTE_ARP_HRD_ETHER) ||
	    arp->arp_protocol != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4) ||
	    arp->arp_hlen != RTE_ETHER_ADDR_LEN || arp->arp_plen != 4 ||
	    arp->arp_opcode != rte_cpu_to_be_16(RTE_ARP_OP_REQUEST) ||
	    memcmp(&arp->arp_data.arp_tip, ctx->opts.local_ip, 4) != 0)
		return false;

	rte_ether_addr_copy(&eth->src_addr, &eth->dst_addr);
	rte_ether_addr_copy(&ctx->local_mac, &eth->src_addr);

	arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
	rte_ether_addr_copy(&arp->arp_data.arp_sha, &arp->arp_data.arp_tha);
	arp->arp_data.arp_tip = arp->arp_data.arp_sip;
	rte_ether_addr_copy(&ctx->local_mac, &arp->arp_data.arp_sha);
	memcpy(&arp->arp_data.arp_sip, ctx->opts.local_ip, 4);

	return tx_or_free(ctx, m);
}

static bool
try_icmp_echo(struct app_context_t *ctx, struct rte_mbuf *m, struct rte_ether_hdr *eth)
{
	uint32_t len = rte_pktmbuf_data_len(m);

	if (len < sizeof(*eth) + sizeof(struct rte_ipv4_hdr))
		return false;

	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);

	/* version 4, no options - a real ping never sends options, and
	 * skipping them entirely keeps this "just enough to fake it". */
	if (ip->version_ihl != 0x45 || ip->next_proto_id != IPPROTO_ICMP)
		return false;

	uint32_t ip_total_len = rte_be_to_cpu_16(ip->total_length);
	if (ip_total_len < sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr) ||
	    len < sizeof(*eth) + ip_total_len)
		return false;

	if (memcmp(&ip->dst_addr, ctx->opts.local_ip, 4) != 0)
		return false;

	struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)(ip + 1);
	if (icmp->icmp_type != RTE_ICMP_TYPE_ECHO_REQUEST || icmp->icmp_code != 0)
		return false;

	rte_ether_addr_copy(&eth->src_addr, &eth->dst_addr);
	rte_ether_addr_copy(&ctx->local_mac, &eth->src_addr);

	rte_be32_t requester_ip = ip->src_addr;
	ip->src_addr = ip->dst_addr;
	ip->dst_addr = requester_ip;
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	/* ICMP checksum has no IP pseudo-header (unlike UDP/TCP) - just the
	 * ICMP message itself, echo request and reply are the same length. */
	icmp->icmp_type = RTE_ICMP_TYPE_ECHO_REPLY;
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = ~rte_raw_cksum(icmp, ip_total_len - sizeof(struct rte_ipv4_hdr));

	return tx_or_free(ctx, m);
}

bool
net_responder_try_handle(struct app_context_t *ctx, struct rte_mbuf *m)
{
	if (!ctx->opts.have_local_ip)
		return false;

	if (rte_pktmbuf_data_len(m) < sizeof(struct rte_ether_hdr))
		return false;

	struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	switch (rte_be_to_cpu_16(eth->ether_type)) {
	case RTE_ETHER_TYPE_ARP:
		return try_arp(ctx, m, eth);
	case RTE_ETHER_TYPE_IPV4:
		return try_icmp_echo(ctx, m, eth);
	default:
		return false;
	}
}
