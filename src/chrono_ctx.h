#ifndef CHRONO_CTX_H
#define CHRONO_CTX_H

/* Shared app_context_t definition, split out of main.c so chrono_admin.c
 * (the SPDK-reactor-thread side of the web bridge) and web_status.c (the
 * pthread side) can both see the full struct - main.c keeps ownership of
 * everything that actually operates on it, this header exists purely so
 * three .c files can agree on its layout. */

#include "spdk/bdev.h"
#include "spdk/thread.h"

#include <rte_mempool.h>
#include <rte_ether.h>

#include <stdatomic.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include "record.h"
#include "chrono_admin.h"

#define NUM_WRITE_BUFFERS 4

struct app_opts_t {
	char *bdev_name;
	uint16_t udp_port;
	uint16_t mtu;
	bool force_10g;
	uint64_t count_limit; /* 0 = unlimited */
	bool dump_mode;
	bool init_mode;
	bool force;
	bool dump_segment_given;
	uint32_t dump_segment_id;
	bool serve_mode;
	uint16_t web_port; /* 0 = daemon runs headless, no web server */

	/* -I <ip>: the address net_responder.c answers ARP/ICMP-echo for.
	 * Optional - if never given, have_local_ip stays false and
	 * net_responder_try_handle() never matches anything, so behavior is
	 * identical to before this feature existed. Network byte order, 4
	 * bytes, same convention as app_parse_ipv4()'s other callers. */
	uint8_t local_ip[4];
	bool have_local_ip;
};

struct write_buf {
	uint8_t *data;
	uint32_t used;
	bool in_flight;
};

/* Sentinel for "no segment currently recording" - 0 is a valid segment id,
 * so this can't be 0. */
#define CHRONO_NO_SEGMENT UINT32_MAX

struct app_context_t {
	struct app_opts_t opts;

	struct spdk_bdev *bdev;
	struct spdk_bdev_desc *bdev_desc;
	struct spdk_io_channel *bdev_io_channel;
	uint32_t block_size;
	uint32_t buf_size; /* one write chunk, a multiple of block_size */
	uint32_t buf_size_blocks;

	struct write_buf buffers[NUM_WRITE_BUFFERS];
	int cur_buf;
	uint64_t next_write_block;

	struct spdk_bdev_io_wait_entry bdev_io_wait;
	struct write_buf *retry_buf;

	uint16_t port;
	struct rte_mempool *mbuf_pool;
	int mbuf_socket_id; /* rte_socket_id(), captured once on the reactor
			      * thread (a real EAL thread) when mbuf_pool is
			      * created - rte_socket_id() returns -1 if called
			      * from the web pthread instead, since DPDK never
			      * registered it as an EAL thread. Same
			      * write-before-thread-creation safety as
			      * mbuf_pool itself. */
	struct rte_ether_addr local_mac; /* this port's own MAC, captured
					   * once from chrono_port_init()'s
					   * mac_addr_out - net_responder.c
					   * needs it to fill in ARP replies
					   * and the reflected Ethernet src. */
	struct spdk_poller *rx_poller;

	/* Single writer (capture_poll, on the reactor thread) in both CLI
	 * and daemon modes; _Atomic so the web thread can read live values
	 * for /status.json without a lock - relaxed ordering is fine, this
	 * is display data, not a synchronization point. */
	_Atomic uint64_t record_count;
	_Atomic uint64_t dropped_count;
	_Atomic uint64_t first_capture_tsc;
	_Atomic uint64_t last_capture_tsc;

	int pending_writes;
	bool stopping;

	/* Volume header + a per-mode I/O buffer shared across capture's
	 * claim/finalize single-block TOC writes, list mode's TOC scan,
	 * dump-one-segment's record reads, and init's TOC zero-fill writes -
	 * only one of those things ever happens per process invocation in
	 * CLI mode (and, in daemon mode, io_buf is only touched from the
	 * reactor thread inside a bridged admin call, serialized with
	 * capture the same way claim/finalize already are). vol_buf is
	 * block_size (holds one chrono_volume_header, block-padded); io_buf
	 * is buf_size (matches the capture path's own write granularity,
	 * and comfortably holds one chrono_segment_entry too). */
	struct chrono_volume_header vol;
	uint8_t *vol_buf;
	uint8_t *io_buf;

	uint32_t segment_id;
	uint64_t segment_start_block;
	uint64_t segment_wall_start_sec;
	uint32_t segment_wall_start_nsec;

	/* --init mode only: current block being zero-filled in the TOC
	 * region, [vol.toc_start_block, vol.data_start_block). */
	uint64_t init_cur_block;

	/* -D (dump/list) mode only. Reused for both "list all segments"
	 * (counting/scanning TOC slots) and "-S <id>: dump one segment's
	 * records" (counting/scanning that segment's data blocks) - the two
	 * never run in the same process invocation. */
	uint64_t dump_target_count;
	uint64_t dump_records_seen;
	uint64_t dump_cur_block;
	uint64_t dump_first_capture_tsc;
	uint64_t dump_tsc_hz;

	/* --serve (daemon) mode only. */
	_Atomic bool recording;
	_Atomic bool shutting_down;
	_Atomic uint32_t current_segment_id; /* CHRONO_NO_SEGMENT when idle */
	/* Mirrors of ctx->vol's fields the web thread needs every 1Hz poll -
	 * kept separate from ctx->vol itself (which the reactor thread
	 * freely mutates mid-claim/finalize) so a torn read is never
	 * possible; updated by the reactor right after each mutation to
	 * ctx->vol. */
	_Atomic uint32_t mirror_next_segment_id;
	_Atomic uint64_t mirror_next_data_block;
	uint64_t cached_num_blocks; /* set once at daemon_start, never changes */
	_Atomic uint64_t bytes_written_total;
	_Atomic uint64_t writes_completed_total;
	_Atomic uint64_t write_errors_total;
	time_t start_time; /* set once at daemon_start, before the web
			     * thread is created - safe for that thread to
			     * read without atomics, since pthread_create()
			     * is itself a happens-before synchronization
			     * point for everything written beforehand. The
			     * same reasoning covers ctx->vol.toc_slot_count/
			     * data_start_block/block_size and
			     * cached_num_blocks below: all set once during
			     * daemon_start(), never mutated again, so a
			     * plain (non-atomic) read from the web thread is
			     * correct, not just "practically fine". Only
			     * next_segment_id/next_data_block actually
			     * change during the daemon's life, which is why
			     * those two get dedicated atomic mirrors instead. */
	struct spdk_thread *app_thread; /* captured at daemon_start via
					  * spdk_get_thread(), so the web
					  * thread has somewhere to
					  * spdk_thread_send_msg() to */
	/* Reused by the admin bridge's TOC scans (list/records/delete) too -
	 * capture_poll() never touches io_buf (only buffers[]/cur_buf), and
	 * only one admin request is ever in flight at a time (the single
	 * admin_req slot serializes them, including claim/finalize's own
	 * brief io_buf use), so there's no real aliasing window to guard
	 * against. A separate scratch buffer would just be another
	 * allocation with nothing to protect. */
	struct chrono_admin_request admin_req;
};

#endif
