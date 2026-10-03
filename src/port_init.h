#ifndef PORT_INIT_H
#define PORT_INIT_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_ether.h>
#include <rte_mempool.h>

/* Configures port for 1 RX queue, starts it, and enables promiscuous mode
 * (needed since we're not ARP-resolved - traffic may arrive addressed to
 * broadcast or a peer's MAC we don't own). No TX queue - this is a
 * capture-only recorder, it never sends.
 *
 * Adapted from dpdk-app-example's port_init.c, trimmed to what a pure
 * receiver needs (no reset-and-retry, no live web-status wiring - this
 * project doesn't have that infrastructure). The two hard-won lessons
 * from that project's investigation are kept: --mtu is required (not
 * automatic) to receive frames above the standard 1500 bytes, and
 * force_10g restricts advertised speed to rule out autonegotiation as a
 * factor on hardware that's physically only capable of one speed anyway.
 *
 * strip_vlan requests hardware VLAN-tag stripping (RTE_ETH_RX_OFFLOAD_
 * VLAN_STRIP) when the bound PMD actually advertises it in dev_info.
 * rx_offload_capa - checked here at runtime rather than assumed from the
 * vendor, since this project links against more than one NIC driver
 * (atlantic, enic) with no guarantee both support the same offloads.
 * *hw_vlan_strip_out is set to whether it was actually enabled; the
 * caller (main.c's capture_poll()) still needs its own software fallback
 * for whichever PMD/offload combination comes back false.
 *
 * Returns 0 on success. Prints only genuine DPDK function errors to
 * stderr - nothing else. */
int chrono_port_init(uint16_t port, struct rte_mempool *mbuf_pool, uint16_t mtu,
		      bool force_10g, bool strip_vlan, bool *hw_vlan_strip_out,
		      struct rte_ether_addr *mac_addr_out);

#endif
