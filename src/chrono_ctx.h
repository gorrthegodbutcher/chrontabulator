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

/* Write buffer count and per-buffer chunk size are both live-tunable (see
 * CHRONO_ADMIN_SET_WRITE_BUFFERS/CHRONO_ADMIN_SET_WRITE_CHUNK in
 * chrono_admin.h, gated to !ctx->recording) without ever reallocating DMA
 * memory: every slot up to MAX_WRITE_BUFFERS is pre-allocated at
 * MAX_WRITE_CHUNK_BYTES bytes once at startup, and ctx->write_buf_count/
 * ctx->buf_size (chrono_ctx.h below) just say how much of that
 * pre-allocated headroom is currently active - changing either is a plain
 * field write, safe between recordings since every buffer is guaranteed
 * idle then (used=0, in_flight=false - see claim_header_write_complete()/
 * daemon_claim_header_write_complete()). MAX_WRITE_BUFFERS(32) *
 * MAX_WRITE_CHUNK_BYTES(2MB) = 64MB reserved regardless of what's actually
 * in use - trivial against the multi-hundred-MB-to-GB of hugepage memory
 * this app already has available (see /eal.json). */
#define MAX_WRITE_BUFFERS 32
#define MAX_WRITE_CHUNK_BYTES (2 * 1024 * 1024)
#define MIN_WRITE_CHUNK_BYTES (4 * 1024)

/* Why a recording stopped, surfaced in /status.json so a stall or a broken
 * write path never has to be diagnosed by grepping logs - see main.c's
 * write-failure circuit breaker and disk-full check, and chrono_admin.c's
 * admin_do_recording_stop(). */
enum chrono_stop_reason {
	CHRONO_STOP_NONE,          /* still recording, or never started */
	CHRONO_STOP_USER,          /* POST /recording/stop */
	CHRONO_STOP_COUNT_LIMIT,   /* hit the requested record count */
	CHRONO_STOP_DISK_FULL,     /* would have run off the physical end of
				    * the device */
	CHRONO_STOP_WRITE_FAILURES, /* CHRONO_WRITE_FAILURE_THRESHOLD
				      * consecutive spdk_bdev_write() failures -
				      * the device stopped accepting writes for
				      * some reason other than being full (bad
				      * argument, detached, etc.) */
};

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

	/* Startup defaults for the two live-tunable write-path knobs (see
	 * MAX_WRITE_BUFFERS's comment above) - seed ctx->write_buf_count/
	 * ctx->buf_size once at process start; --write-buffers/--write-chunk-kb
	 * override them, otherwise DEFAULT_WRITE_BUFFERS/WRITE_CHUNK_TARGET
	 * (main.c) apply. Surfaced read-only on the status page alongside the
	 * live values, so a startup command line is never the only place to
	 * see what a daemon was actually launched with. */
	uint32_t write_buf_count;
	uint32_t write_chunk_bytes;
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
	uint32_t write_unit_bytes; /* device's minimum atomic write granularity
				     * in bytes - cached once at startup (see
				     * app_started()) so chrono_round_write_chunk()
				     * doesn't need to re-query the bdev on every
				     * live CHRONO_ADMIN_SET_WRITE_CHUNK call */
	uint32_t buf_size; /* ACTIVE write chunk size, a multiple of block_size,
			     * <= MAX_WRITE_CHUNK_BYTES - live-tunable while
			     * !recording, see MAX_WRITE_BUFFERS's comment above */
	uint32_t buf_size_blocks;
	uint32_t write_buf_count; /* ACTIVE buffer count, 1..MAX_WRITE_BUFFERS -
				    * live-tunable while !recording, same as
				    * buf_size above */

	struct write_buf buffers[MAX_WRITE_BUFFERS]; /* every slot always
							* allocated at
							* MAX_WRITE_CHUNK_BYTES,
							* regardless of the
							* current buf_size */
	int cur_buf;
	uint64_t next_write_block;

	struct spdk_bdev_io_wait_entry bdev_io_wait;
	struct write_buf *retry_buf;

	uint16_t port;
	bool nic_up; /* true once chrono_port_init() has actually started the
		      * port - guards chrono_port_teardown() (main.c) so it
		      * only runs, and only once, when there is really a port
		      * to stop/close. fail_started()/cleanup_and_stop() are
		      * catch-all exit points reachable both before and after
		      * NIC bring-up (dump/list/init modes never bring the NIC
		      * up at all), so this can't just be "ctx->port != 0". */
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
	_Atomic uint32_t last_stop_reason; /* enum chrono_stop_reason - set by
					     * whichever code path calls
					     * daemon_stop_recording()/
					     * begin_shutdown(), just before
					     * calling it */

	int pending_writes;
	bool stopping;
	/* Single writer (write_complete()/retry_flush(), reactor thread only)
	 * - consecutive spdk_bdev_write() failures (submission or completion,
	 * either counts) since the last success. Reset to 0 on any success;
	 * crossing CHRONO_WRITE_FAILURE_THRESHOLD stops recording instead of
	 * retrying forever - see main.c. */
	uint32_t consecutive_write_failures;

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
	/* QUICK_FORMAT (daemon mode) only: the fresh header being built while
	 * the TOC region is zeroed - kept separate from ctx->vol itself so a
	 * write failure partway through a format can never leave the live
	 * volume header (still serving reads/status while this runs) in a
	 * half-formatted state. Only copied into ctx->vol once the new
	 * header's own on-disk write actually succeeds - see main.c's
	 * daemon_quick_format_write_header_complete(). Named for the reset
	 * it actually performs (TOC + header only, data blocks untouched) -
	 * a real full-disk zero-write is a distinct, much slower operation
	 * this doesn't attempt (see the web UI's separate messaging on that
	 * distinction). */
	struct chrono_volume_header qf_staged_vol;
	uint8_t *vol_buf;
	uint8_t *io_buf;

	uint32_t segment_id;
	uint64_t segment_start_block;
	uint64_t segment_wall_start_sec;
	uint32_t segment_wall_start_nsec;

	/* --init mode, and daemon mode's QUICK_FORMAT admin op (which mirrors
	 * --init's zero-fill chain - see main.c's daemon_quick_format_zero_toc_chunk()):
	 * current block being zero-filled in the TOC region,
	 * [vol.toc_start_block, vol.data_start_block) (CLI) or
	 * [qf_staged_vol.toc_start_block, qf_staged_vol.data_start_block)
	 * (daemon) - the two never run in the same process invocation, so
	 * sharing this one field is safe. */
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
