#ifndef NET_RESPONDER_H
#define NET_RESPONDER_H

#include <stdbool.h>
#include <rte_mbuf.h>

struct app_context_t;

/* Answers ARP requests and ICMP echo (ping) requests targeting
 * ctx->opts.local_ip - just enough to make chrontabulator resolvable and
 * pingable on its L2 segment, not a network stack. See net_responder.c's
 * header comment for the exact (deliberately small) scope.
 *
 * On a match, m is reflected back out via rte_eth_tx_burst() (or freed, if
 * the burst fails) and this returns true - ownership of m has been given
 * up either way, the caller must not touch it again. Returns false for
 * anything not recognized or not addressed to ctx->opts.local_ip, leaving
 * m completely untouched for the caller's normal capture path. */
bool net_responder_try_handle(struct app_context_t *ctx, struct rte_mbuf *m);

#endif
