#include <string.h>
#include <stdio.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include "port_init.h"

#define RX_RING_SIZE 1024

int
chrono_port_init(uint16_t port, struct rte_mempool *mbuf_pool, uint16_t mtu,
		  bool force_10g, struct rte_ether_addr *mac_addr_out)
{
	struct rte_eth_conf port_conf;
	uint16_t nb_rxd = RX_RING_SIZE;
	int retval;
	struct rte_eth_dev_info dev_info;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	memset(&port_conf, 0, sizeof(port_conf));

	if (force_10g)
		port_conf.link_speeds = RTE_ETH_LINK_SPEED_10G;

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		fprintf(stderr, "Error getting device (port %u) info: %s\n",
			port, strerror(-retval));
		return retval;
	}

	if (mtu != 0) {
		if (mtu < dev_info.min_mtu || mtu > dev_info.max_mtu) {
			fprintf(stderr, "Requested MTU %u outside device range [%u, %u]\n",
				mtu, dev_info.min_mtu, dev_info.max_mtu);
			return -1;
		}
		port_conf.rxmode.mtu = mtu;
		if (mtu > RTE_ETHER_MTU && (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_SCATTER))
			port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_SCATTER;
	}

	retval = rte_eth_dev_configure(port, 1, 0, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, NULL);
	if (retval != 0)
		return retval;

	retval = rte_eth_rx_queue_setup(port, 0, nb_rxd, rte_eth_dev_socket_id(port),
					 NULL, mbuf_pool);
	if (retval < 0)
		return retval;

	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	retval = rte_eth_macaddr_get(port, mac_addr_out);
	if (retval != 0)
		return retval;

	/* rte_eth_link_get() is documented as blocking until link training
	 * settles, but the atlantic PMD returns an immediate DOWN reading
	 * instead - autonegotiation genuinely takes a few seconds on this
	 * hardware, so poll for it ourselves. */
	struct rte_eth_link link;
	const uint32_t max_wait_ms = 10000, poll_interval_ms = 200;
	uint32_t waited_ms = 0;
	do {
		(void)rte_eth_link_get_nowait(port, &link);
		if (link.link_status == RTE_ETH_LINK_UP)
			break;
		rte_delay_us(poll_interval_ms * 1000);
		waited_ms += poll_interval_ms;
	} while (waited_ms < max_wait_ms);

	retval = rte_eth_promiscuous_enable(port);
	if (retval != 0)
		return retval;

	return 0;
}
