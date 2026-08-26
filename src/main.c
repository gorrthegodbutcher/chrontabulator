/* Chrontabulator: captures UDP packets (dpdk-app-example's wire format -
 * see common.h) off a DPDK-owned NIC and records them to a raw NVMe bdev
 * via SPDK, with enough per-record metadata (sequence number + a locally
 * assigned capture timestamp) for a later, separate pass to sort them
 * back into correct order. Sorted replay itself is out of scope for this
 * pass - see README.md.
 *
 * Single SPDK-native process: DPDK ethdev RX polling and spdk_bdev_*
 * writes both run inside the same SPDK reactor, following the pattern
 * spdk-app-example already proved out for the bdev half (this file
 * borrows its app_started/app_write/write_complete shape directly).
 *
 * On-disk format is a fixed volume header + segment table of contents
 * (record.h) - a device is formatted once (--init), then any number of
 * independent capture segments can be recorded onto it without one run
 * clobbering another. See record.h for the full on-disk layout.
 */

#include "spdk/stdinc.h"
#include "spdk/thread.h"
#include "spdk/bdev.h"
#include "spdk/env.h"
#include "spdk/event.h"
#include "spdk/log.h"
#include "spdk/string.h"

#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_mbuf.h>

#include <getopt.h>
#include <time.h>

#include "common.h"
#include "port_init.h"
#include "record.h"

#define NUM_MBUFS        8191
#define MBUF_CACHE_SIZE  250
#define MBUF_DATA_SIZE   9216
#define BURST_SIZE       32
#define NUM_WRITE_BUFFERS 4
#define VOLUME_HEADER_BLOCK 0
#define WRITE_CHUNK_TARGET (64 * 1024) /* rounded up to the device's own
					 * write granularity below - not a
					 * hard size, just comfortably bigger
					 * than one jumbo (~9KB) record */

/* SPDK's own app framework reserves long-option values 256-274 or so for
 * its own flags (see lib/event/app.c's *_OPT_IDX defines, e.g.
 * INTERRUPT_MODE_OPT_IDX == 256) - both option arrays get merged into one
 * getopt_long() call and one switch, so a colliding value here gets
 * silently handled as the SPDK flag it happens to match instead of ours.
 * Confirmed the hard way: CHRONO_OPT_INIT at 0x100 (256) made --init
 * silently behave as SPDK's own --interrupt-mode instead. Picked well
 * clear of SPDK's range, with margin for that range to grow. */
enum {
	CHRONO_OPT_INIT = 0x1000,
	CHRONO_OPT_FORCE,
};

static const struct option chrono_long_opts[] = {
	{"init",  no_argument, NULL, CHRONO_OPT_INIT},
	{"force", no_argument, NULL, CHRONO_OPT_FORCE},
	{NULL, 0, NULL, 0},
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
};

struct write_buf {
	uint8_t *data;
	uint32_t used;
	bool in_flight;
};

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
	struct spdk_poller *rx_poller;

	uint64_t record_count;
	uint64_t dropped_count;
	uint64_t first_capture_tsc;
	uint64_t last_capture_tsc;

	int pending_writes;
	bool stopping;

	/* Volume header + a per-mode I/O buffer shared across capture's
	 * claim/finalize single-block TOC writes, list mode's TOC scan,
	 * dump-one-segment's record reads, and init's TOC zero-fill writes -
	 * only one of those things ever happens per process invocation, so
	 * one buffer each is enough. vol_buf is block_size (holds one
	 * chrono_volume_header, block-padded); io_buf is buf_size (matches
	 * the capture path's own write granularity, and comfortably holds
	 * one chrono_segment_entry too). */
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
};

static struct app_context_t g_ctx;

static void
app_usage(void)
{
	printf(" -b <bdev>                 name of the bdev to record to (required)\n");
	printf(" -P <port>                 UDP destination port to capture (required unless -D or --init)\n");
	printf(" -M <mtu>                  set the NIC's MTU (0 = device default)\n");
	printf(" -F                        restrict advertised link speed to 10G only\n");
	printf(" -C <count>                stop after this many records (0 = unlimited)\n");
	printf(" -D                        list segments on the bdev instead of capturing\n");
	printf(" -D -S <id>                dump one segment's records instead of listing\n");
	printf(" --init                    format the bdev as a fresh, empty chrontabulator volume\n");
	printf(" --force                   with --init, reformat a bdev that already has one\n");
}

static int
app_parse_arg(int ch, char *arg)
{
	switch (ch) {
	case 'b':
		g_ctx.opts.bdev_name = arg;
		break;
	case 'P':
		g_ctx.opts.udp_port = (uint16_t)strtoul(arg, NULL, 10);
		break;
	case 'M':
		g_ctx.opts.mtu = (uint16_t)strtoul(arg, NULL, 10);
		break;
	case 'F':
		g_ctx.opts.force_10g = true;
		break;
	case 'C':
		g_ctx.opts.count_limit = strtoull(arg, NULL, 10);
		break;
	case 'D':
		g_ctx.opts.dump_mode = true;
		break;
	case 'S':
		g_ctx.opts.dump_segment_given = true;
		g_ctx.opts.dump_segment_id = (uint32_t)strtoul(arg, NULL, 10);
		break;
	case CHRONO_OPT_INIT:
		g_ctx.opts.init_mode = true;
		break;
	case CHRONO_OPT_FORCE:
		g_ctx.opts.force = true;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static void
begin_shutdown(struct app_context_t *ctx);

static bool
volume_header_is_valid(const struct chrono_volume_header *hdr)
{
	return hdr->magic == CHRONO_VOLUME_MAGIC && hdr->version == CHRONO_FORMAT_VERSION;
}

/* Releases whatever app_started() had already allocated before hitting a
 * fatal setup error (in any of the three modes - capture, dump/list,
 * init), then stops the app with a nonzero exit code. spdk_app_stop()
 * alone isn't enough here: SPDK's subsystem teardown waits for
 * outstanding bdev descriptors and I/O channels to close, so calling it
 * while ctx->bdev_desc/bdev_io_channel are still open leaves the reactor
 * running indefinitely instead of exiting. Safe to call at any point -
 * every field it touches is NULL/zero until actually allocated (g_ctx is
 * memset at startup), and buffers[] is only ever populated well into the
 * capture path, never in dump/list/init. */
static void
fail_started(struct app_context_t *ctx)
{
	for (int i = 0; i < NUM_WRITE_BUFFERS; i++) {
		if (ctx->buffers[i].data)
			spdk_dma_free(ctx->buffers[i].data);
	}
	if (ctx->vol_buf)
		spdk_dma_free(ctx->vol_buf);
	if (ctx->io_buf)
		spdk_dma_free(ctx->io_buf);
	if (ctx->bdev_io_channel)
		spdk_put_io_channel(ctx->bdev_io_channel);
	if (ctx->bdev_desc)
		spdk_bdev_close(ctx->bdev_desc);
	spdk_app_stop(-1);
}

/* Clean-completion counterpart to fail_started() - used once a mode has
 * finished successfully (dump/list, init) or, for capture, once the
 * segment's TOC entry is finalized. Deliberately does NOT free
 * buffers[]: today's capture path never frees those at clean shutdown
 * either (SPDK's DMA/hugepage memory is fine to leave allocated until
 * process exit), so this preserves that existing, verified behavior
 * rather than "fixing" something that was never broken. */
static void
cleanup_and_stop(struct app_context_t *ctx, int rc)
{
	if (ctx->vol_buf)
		spdk_dma_free(ctx->vol_buf);
	if (ctx->io_buf)
		spdk_dma_free(ctx->io_buf);
	if (ctx->bdev_io_channel)
		spdk_put_io_channel(ctx->bdev_io_channel);
	if (ctx->bdev_desc)
		spdk_bdev_close(ctx->bdev_desc);
	spdk_app_stop(rc);
}

/* ---- capture: segment finalize (clean shutdown) ---- */

static void
finalize_toc_write_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct app_context_t *ctx = cb_arg;

	if (bdev_io != NULL)
		spdk_bdev_free_io(bdev_io);
	if (!success)
		SPDK_ERRLOG("failed to finalize segment %u's TOC entry\n", ctx->segment_id);

	SPDK_NOTICELOG("Recorded %" PRIu64 " packets (%" PRIu64 " dropped due to backpressure)"
		       " in segment %u\n",
		       ctx->record_count, ctx->dropped_count, ctx->segment_id);

	cleanup_and_stop(ctx, 0);
}

/* Writes this segment's finalized TOC entry, then stops. Called only
 * after the volume header's next_data_block has already been advanced
 * and written (see finalize_segment_and_stop() below) - that ordering is
 * what makes a crash between the two writes safe: worst case is a
 * fully-intact segment stuck showing as OPEN, never a silently
 * overwritten one. */
static void
finalize_header_write_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct app_context_t *ctx = cb_arg;
	struct chrono_segment_entry *seg;
	struct timespec ts;
	int rc;

	if (bdev_io != NULL)
		spdk_bdev_free_io(bdev_io);
	if (!success)
		SPDK_ERRLOG("failed to update volume header at finalize - segment %u's data"
			    " may be at risk of being overwritten by a future capture\n",
			    ctx->segment_id);

	memset(ctx->io_buf, 0, ctx->block_size);
	seg = (struct chrono_segment_entry *)ctx->io_buf;
	seg->magic = CHRONO_SEGMENT_MAGIC;
	seg->segment_id = ctx->segment_id;
	seg->state = CHRONO_SEGMENT_FINALIZED;
	seg->start_block = ctx->segment_start_block;
	seg->block_count = ctx->next_write_block - ctx->segment_start_block;
	seg->record_count = ctx->record_count;
	seg->dropped_count = ctx->dropped_count;
	seg->first_capture_tsc = ctx->first_capture_tsc;
	seg->last_capture_tsc = ctx->last_capture_tsc;
	seg->tsc_hz = rte_get_tsc_hz();
	seg->wall_clock_start_sec = ctx->segment_wall_start_sec;
	seg->wall_clock_start_nsec = ctx->segment_wall_start_nsec;
	clock_gettime(CLOCK_REALTIME, &ts);
	seg->wall_clock_end_sec = (uint64_t)ts.tv_sec;
	seg->wall_clock_end_nsec = (uint32_t)ts.tv_nsec;

	rc = spdk_bdev_write(ctx->bdev_desc, ctx->bdev_io_channel, ctx->io_buf,
			      (ctx->vol.toc_start_block + ctx->segment_id) * ctx->block_size,
			      ctx->block_size, finalize_toc_write_complete, ctx);
	if (rc != 0) {
		SPDK_ERRLOG("%s finalizing segment %u's TOC entry\n", spdk_strerror(-rc),
			    ctx->segment_id);
		finalize_toc_write_complete(NULL, false, ctx);
	}
}

/* Segment finalize, step 1 of 2: advance and write the volume header's
 * next_data_block high-water mark to just past this segment's data,
 * BEFORE marking the segment itself FINALIZED in the TOC (see
 * finalize_header_write_complete() above for why this order matters). */
static void
finalize_segment_and_stop(struct app_context_t *ctx)
{
	int rc;

	ctx->vol.next_data_block = ctx->next_write_block;
	memset(ctx->vol_buf, 0, ctx->block_size);
	*(struct chrono_volume_header *)ctx->vol_buf = ctx->vol;

	rc = spdk_bdev_write(ctx->bdev_desc, ctx->bdev_io_channel, ctx->vol_buf,
			      VOLUME_HEADER_BLOCK * ctx->block_size, ctx->block_size,
			      finalize_header_write_complete, ctx);
	if (rc != 0) {
		SPDK_ERRLOG("%s finalizing volume header: %d\n", spdk_strerror(-rc), rc);
		finalize_header_write_complete(NULL, false, ctx);
	}
}

static void
write_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct write_buf *wb = cb_arg;
	struct app_context_t *ctx = &g_ctx;

	spdk_bdev_free_io(bdev_io);
	wb->in_flight = false;
	wb->used = 0;

	if (!success)
		SPDK_ERRLOG("bdev write error\n");

	ctx->pending_writes--;
	if (ctx->stopping && ctx->pending_writes == 0)
		finalize_segment_and_stop(ctx);
}

static void
retry_flush(void *arg)
{
	struct write_buf *wb = arg;
	struct app_context_t *ctx = &g_ctx;
	int rc;

	rc = spdk_bdev_write(ctx->bdev_desc, ctx->bdev_io_channel, wb->data,
			      ctx->next_write_block * ctx->block_size, ctx->buf_size,
			      write_complete, wb);
	if (rc == -ENOMEM) {
		ctx->retry_buf = wb;
		ctx->bdev_io_wait.bdev = ctx->bdev;
		ctx->bdev_io_wait.cb_fn = retry_flush;
		ctx->bdev_io_wait.cb_arg = wb;
		spdk_bdev_queue_io_wait(ctx->bdev, ctx->bdev_io_channel, &ctx->bdev_io_wait);
	} else if (rc != 0) {
		SPDK_ERRLOG("%s flushing write buffer: %d\n", spdk_strerror(-rc), rc);
		wb->in_flight = false;
		wb->used = 0;
		ctx->pending_writes--;
		if (ctx->stopping && ctx->pending_writes == 0)
			finalize_segment_and_stop(ctx);
	}
}

/* Issues the async write for buffers[idx] and advances past it - the
 * buffer stays "in_flight" (not reusable) until write_complete() clears
 * it. Caller is responsible for having already decided this buffer is
 * ready to go (full, or being flushed as part of shutdown). */
static void
flush_buffer(struct app_context_t *ctx, int idx)
{
	struct write_buf *wb = &ctx->buffers[idx];

	if (wb->used == 0)
		return;

	/* spdk_dma_zmalloc() only zeroes a buffer once, at allocation. Each
	 * of the NUM_WRITE_BUFFERS slots gets reused many times over a long
	 * capture, and a later, smaller fill would otherwise leave stale
	 * record bytes from a previous, larger fill sitting past the new
	 * `used` boundary - a reader relying on magic==0 to mean "no more
	 * records here" would misparse that leftover as real data. */
	if (wb->used < ctx->buf_size)
		memset(wb->data + wb->used, 0, ctx->buf_size - wb->used);

	wb->in_flight = true;
	ctx->pending_writes++;
	retry_flush(wb);
	ctx->next_write_block += ctx->buf_size_blocks;
}

static int
capture_poll(void *arg)
{
	struct app_context_t *ctx = arg;
	struct rte_mbuf *bufs[BURST_SIZE];
	uint16_t nb_rx;
	int did_work = SPDK_POLLER_IDLE;

	if (ctx->stopping)
		return SPDK_POLLER_IDLE;

	nb_rx = rte_eth_rx_burst(ctx->port, 0, bufs, BURST_SIZE);
	if (nb_rx == 0)
		return SPDK_POLLER_IDLE;

	uint64_t now_tsc = rte_rdtsc();

	for (uint16_t i = 0; i < nb_rx; i++) {
		did_work = SPDK_POLLER_BUSY;

		uint8_t *data = rte_pktmbuf_mtod(bufs[i], uint8_t *);
		uint32_t len = rte_pktmbuf_pkt_len(bufs[i]);

		uint16_t dst_port;
		uint64_t seq;
		const uint8_t *payload;
		uint32_t payload_len;

		bool is_ours = app_parse_packet(data, len, &dst_port, &seq,
						 &payload, &payload_len) == 0 &&
				dst_port == ctx->opts.udp_port;

		if (!is_ours) {
			rte_pktmbuf_free(bufs[i]);
			continue;
		}

		uint32_t rec_size = (uint32_t)sizeof(struct chrono_record_hdr) + payload_len;
		struct write_buf *wb = &ctx->buffers[ctx->cur_buf];

		if (wb->used + rec_size > ctx->buf_size) {
			/* Doesn't fit in what's left of this buffer - flush
			 * it (flush_buffer() pads the remainder with zeros)
			 * and move to the next buffer round-robin. */
			flush_buffer(ctx, ctx->cur_buf);
			ctx->cur_buf = (ctx->cur_buf + 1) % NUM_WRITE_BUFFERS;
			wb = &ctx->buffers[ctx->cur_buf];

			if (wb->in_flight || rec_size > ctx->buf_size) {
				/* Still busy (all buffers backed up), or a
				 * single record too large to ever fit one
				 * write chunk - drop it rather than block
				 * the RX loop. */
				ctx->dropped_count++;
				rte_pktmbuf_free(bufs[i]);
				continue;
			}
		}

		struct chrono_record_hdr *hdr = (struct chrono_record_hdr *)(wb->data + wb->used);
		hdr->magic = CHRONO_RECORD_MAGIC;
		hdr->seq = seq;
		hdr->capture_tsc = now_tsc;
		hdr->len = payload_len;
		hdr->reserved = 0;
		memcpy(wb->data + wb->used + sizeof(*hdr), payload, payload_len);
		wb->used += rec_size;

		ctx->record_count++;
		if (ctx->first_capture_tsc == 0)
			ctx->first_capture_tsc = now_tsc;
		ctx->last_capture_tsc = now_tsc;

		rte_pktmbuf_free(bufs[i]);

		if (ctx->opts.count_limit != 0 && ctx->record_count >= ctx->opts.count_limit) {
			begin_shutdown(ctx);
			break;
		}
	}

	return did_work;
}

static void
begin_shutdown(struct app_context_t *ctx)
{
	if (ctx->stopping)
		return;
	ctx->stopping = true;

	SPDK_NOTICELOG("Stopping capture, flushing pending writes...\n");
	spdk_poller_unregister(&ctx->rx_poller);

	/* Flush whatever's sitting in the currently-accumulating buffer as
	 * a final, possibly-short write. */
	flush_buffer(ctx, ctx->cur_buf);

	if (ctx->pending_writes == 0)
		finalize_segment_and_stop(ctx);
}

static void
app_shutdown_cb(void)
{
	begin_shutdown(&g_ctx);
}

static void
app_bdev_event_cb(enum spdk_bdev_event_type type, struct spdk_bdev *bdev, void *event_ctx)
{
	SPDK_NOTICELOG("Unsupported bdev event: type %d\n", type);
}

/* ---- capture: segment claim (startup) ---- */

static void
claim_header_write_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct app_context_t *ctx = cb_arg;
	int rc;

	if (bdev_io != NULL)
		spdk_bdev_free_io(bdev_io);
	if (!success) {
		SPDK_ERRLOG("failed to record segment %u's claim in the volume header\n",
			    ctx->segment_id);
		fail_started(ctx);
		return;
	}

	/* Everything below is moved verbatim from the pre-segment version of
	 * app_started()'s tail - already verified at 1,000,000-packet scale,
	 * relocated here (rather than rewritten) because it can only run
	 * once this segment's start_block is known, which now requires the
	 * async header read + claim writes above it. */
	ctx->next_write_block = ctx->segment_start_block;

	uint32_t buf_align = spdk_bdev_get_buf_align(ctx->bdev);
	for (int i = 0; i < NUM_WRITE_BUFFERS; i++) {
		ctx->buffers[i].data = spdk_dma_zmalloc(ctx->buf_size, buf_align, NULL);
		if (!ctx->buffers[i].data) {
			SPDK_ERRLOG("Failed to allocate write buffer %d\n", i);
			fail_started(ctx);
			return;
		}
	}

	SPDK_NOTICELOG("bdev block_size=%u write_unit=%u buf_size=%u (%d buffers)\n",
		       ctx->block_size, spdk_bdev_get_write_unit_size(ctx->bdev),
		       ctx->buf_size, NUM_WRITE_BUFFERS);

	if (rte_eth_dev_count_avail() != 1) {
		SPDK_ERRLOG("Expected exactly 1 available DPDK port, found %u\n",
			    rte_eth_dev_count_avail());
		fail_started(ctx);
		return;
	}
	RTE_ETH_FOREACH_DEV(ctx->port)
		break;

	ctx->mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0,
						  MBUF_DATA_SIZE, rte_socket_id());
	if (ctx->mbuf_pool == NULL) {
		SPDK_ERRLOG("Cannot create mbuf pool: %s\n", rte_strerror(rte_errno));
		fail_started(ctx);
		return;
	}

	struct rte_ether_addr mac_addr;
	rc = chrono_port_init(ctx->port, ctx->mbuf_pool, ctx->opts.mtu, ctx->opts.force_10g,
			       &mac_addr);
	if (rc != 0) {
		SPDK_ERRLOG("Failed to initialize port %u\n", ctx->port);
		fail_started(ctx);
		return;
	}

	SPDK_NOTICELOG("Recording UDP port %u to bdev %s, segment %u, port %u ready\n",
		       ctx->opts.udp_port, ctx->opts.bdev_name, ctx->segment_id, ctx->port);

	ctx->rx_poller = spdk_poller_register(capture_poll, ctx, 0);
}

static void
claim_toc_write_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct app_context_t *ctx = cb_arg;
	int rc;

	if (bdev_io != NULL)
		spdk_bdev_free_io(bdev_io);
	if (!success) {
		SPDK_ERRLOG("failed to claim a segment slot\n");
		fail_started(ctx);
		return;
	}

	/* A retried/duplicate claim of the same slot is harmless (worst case
	 * a wasted segment id), unlike finalize's header/TOC write order -
	 * see the comment on finalize_segment_and_stop() - so TOC-then-
	 * header here is fine. */
	ctx->vol.next_segment_id++;
	memset(ctx->vol_buf, 0, ctx->block_size);
	*(struct chrono_volume_header *)ctx->vol_buf = ctx->vol;

	rc = spdk_bdev_write(ctx->bdev_desc, ctx->bdev_io_channel, ctx->vol_buf,
			      VOLUME_HEADER_BLOCK * ctx->block_size, ctx->block_size,
			      claim_header_write_complete, ctx);
	if (rc != 0) {
		SPDK_ERRLOG("%s recording segment claim in volume header\n", spdk_strerror(-rc));
		fail_started(ctx);
	}
}

static void
claim_segment_start(struct app_context_t *ctx)
{
	struct chrono_segment_entry *seg;
	struct timespec ts;
	int rc;

	if (ctx->vol.next_segment_id >= ctx->vol.toc_slot_count) {
		SPDK_ERRLOG("TOC full (%u/%u segments used) - re-init the device"
			    " (--init --force) to reclaim slots; growing the TOC"
			    " in place is not supported\n",
			    ctx->vol.next_segment_id, ctx->vol.toc_slot_count);
		fail_started(ctx);
		return;
	}

	ctx->segment_id = ctx->vol.next_segment_id;
	ctx->segment_start_block = ctx->vol.next_data_block;

	clock_gettime(CLOCK_REALTIME, &ts);
	ctx->segment_wall_start_sec = (uint64_t)ts.tv_sec;
	ctx->segment_wall_start_nsec = (uint32_t)ts.tv_nsec;

	memset(ctx->io_buf, 0, ctx->block_size);
	seg = (struct chrono_segment_entry *)ctx->io_buf;
	seg->magic = CHRONO_SEGMENT_MAGIC;
	seg->segment_id = ctx->segment_id;
	seg->state = CHRONO_SEGMENT_OPEN;
	seg->start_block = ctx->segment_start_block;
	seg->wall_clock_start_sec = ctx->segment_wall_start_sec;
	seg->wall_clock_start_nsec = ctx->segment_wall_start_nsec;

	rc = spdk_bdev_write(ctx->bdev_desc, ctx->bdev_io_channel, ctx->io_buf,
			      (ctx->vol.toc_start_block + ctx->segment_id) * ctx->block_size,
			      ctx->block_size, claim_toc_write_complete, ctx);
	if (rc != 0) {
		SPDK_ERRLOG("%s claiming segment %u\n", spdk_strerror(-rc), ctx->segment_id);
		fail_started(ctx);
	}
}

/* ---- dump: per-record readback within one segment (unchanged from V1,
 * just seeded by a segment's TOC entry instead of a lone superblock) ---- */

static void
dump_read_next_chunk(struct app_context_t *ctx);

static void
dump_chunk_read_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct app_context_t *ctx = cb_arg;
	uint32_t offset = 0;

	spdk_bdev_free_io(bdev_io);
	if (!success) {
		SPDK_ERRLOG("read failed at block %" PRIu64 "\n", ctx->dump_cur_block);
		cleanup_and_stop(ctx, -1);
		return;
	}

	while (offset + sizeof(struct chrono_record_hdr) <= ctx->buf_size &&
	       ctx->dump_records_seen < ctx->dump_target_count) {
		struct chrono_record_hdr *hdr = (struct chrono_record_hdr *)(ctx->io_buf + offset);

		if (hdr->magic != CHRONO_RECORD_MAGIC)
			break;
		if (offset + sizeof(*hdr) + hdr->len > ctx->buf_size) {
			SPDK_ERRLOG("record at block %" PRIu64 " offset %u claims len %u,"
				    " overruns the write chunk - stopping\n",
				    ctx->dump_cur_block, offset, hdr->len);
			cleanup_and_stop(ctx, -1);
			return;
		}

		double rel_sec = ctx->dump_tsc_hz != 0 ?
			(double)(hdr->capture_tsc - ctx->dump_first_capture_tsc) / ctx->dump_tsc_hz : 0.0;
		printf("record %" PRIu64 ": seq=%" PRIu64 " capture_tsc=%" PRIu64
		       " (+%.6fs) len=%u\n",
		       ctx->dump_records_seen, hdr->seq, hdr->capture_tsc, rel_sec, hdr->len);

		offset += (uint32_t)sizeof(*hdr) + hdr->len;
		ctx->dump_records_seen++;
	}

	ctx->dump_cur_block += ctx->buf_size_blocks;

	if (ctx->dump_records_seen >= ctx->dump_target_count) {
		printf("Dumped %" PRIu64 " of %" PRIu64 " records from segment %u.\n",
		       ctx->dump_records_seen, ctx->dump_target_count, ctx->segment_id);
		cleanup_and_stop(ctx, 0);
		return;
	}
	if (offset == 0) {
		/* First record slot in this chunk was already padding -
		 * fewer real records on disk than the TOC entry claims. */
		SPDK_ERRLOG("expected %" PRIu64 " records, only found %" PRIu64
			    " before hitting unwritten space\n",
			    ctx->dump_target_count, ctx->dump_records_seen);
		cleanup_and_stop(ctx, -1);
		return;
	}

	dump_read_next_chunk(ctx);
}

static void
dump_read_next_chunk(struct app_context_t *ctx)
{
	int rc;

	rc = spdk_bdev_read(ctx->bdev_desc, ctx->bdev_io_channel, ctx->io_buf,
			     ctx->dump_cur_block * ctx->block_size, ctx->buf_size,
			     dump_chunk_read_complete, ctx);
	if (rc != 0) {
		SPDK_ERRLOG("%s reading block %" PRIu64 "\n", spdk_strerror(-rc), ctx->dump_cur_block);
		cleanup_and_stop(ctx, -1);
	}
}

static void
dump_segment_entry_read_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct app_context_t *ctx = cb_arg;
	struct chrono_segment_entry *seg = (struct chrono_segment_entry *)ctx->io_buf;

	spdk_bdev_free_io(bdev_io);
	if (!success) {
		SPDK_ERRLOG("failed to read segment %u's TOC entry\n", ctx->opts.dump_segment_id);
		cleanup_and_stop(ctx, -1);
		return;
	}
	if (seg->magic != CHRONO_SEGMENT_MAGIC || seg->state == CHRONO_SEGMENT_FREE) {
		SPDK_ERRLOG("segment %u does not exist\n", ctx->opts.dump_segment_id);
		cleanup_and_stop(ctx, -1);
		return;
	}
	if (seg->state != CHRONO_SEGMENT_FINALIZED) {
		printf("Segment %u: never finalized (in progress, or crashed before"
		       " finishing) - nothing to dump.\n", seg->segment_id);
		cleanup_and_stop(ctx, 0);
		return;
	}

	printf("Segment %u: record_count=%" PRIu64 " dropped_count=%" PRIu64
	       " tsc_hz=%" PRIu64 "\n", seg->segment_id, seg->record_count,
	       seg->dropped_count, seg->tsc_hz);
	if (seg->tsc_hz != 0)
		printf("Capture span: %.3fs\n",
		       (double)(seg->last_capture_tsc - seg->first_capture_tsc) / seg->tsc_hz);

	ctx->segment_id = seg->segment_id;
	ctx->dump_target_count = seg->record_count;
	ctx->dump_first_capture_tsc = seg->first_capture_tsc;
	ctx->dump_tsc_hz = seg->tsc_hz;

	if (ctx->dump_target_count == 0) {
		printf("Nothing recorded in this segment.\n");
		cleanup_and_stop(ctx, 0);
		return;
	}

	ctx->dump_cur_block = seg->start_block;
	dump_read_next_chunk(ctx);
}

/* ---- dump: list all segments ---- */

static void
list_read_next_chunk(struct app_context_t *ctx);

static void
list_chunk_read_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct app_context_t *ctx = cb_arg;
	struct chrono_segment_entry *seg = (struct chrono_segment_entry *)ctx->io_buf;

	spdk_bdev_free_io(bdev_io);
	if (!success) {
		SPDK_ERRLOG("failed to read TOC entry at block %" PRIu64 "\n", ctx->dump_cur_block);
		cleanup_and_stop(ctx, -1);
		return;
	}

	if (seg->magic == CHRONO_SEGMENT_MAGIC && seg->state != CHRONO_SEGMENT_FREE) {
		if (seg->state == CHRONO_SEGMENT_FINALIZED) {
			char start_str[32] = "n/a";
			time_t t = (time_t)seg->wall_clock_start_sec;
			struct tm tm_buf;

			if (gmtime_r(&t, &tm_buf) != NULL)
				strftime(start_str, sizeof(start_str), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);

			double duration = seg->tsc_hz != 0 ?
				(double)(seg->last_capture_tsc - seg->first_capture_tsc) /
				seg->tsc_hz : 0.0;
			printf("segment %u: FINALIZED  start=%s  duration=%.3fs"
			       "  records=%" PRIu64 "  dropped=%" PRIu64
			       "  blocks=[%" PRIu64 "+%" PRIu64 ")\n",
			       seg->segment_id, start_str, duration, seg->record_count,
			       seg->dropped_count, seg->start_block, seg->block_count);
		} else {
			printf("segment %u: OPEN (in progress, or crashed before"
			       " finishing - never finalized)\n", seg->segment_id);
		}
	}

	ctx->dump_records_seen++;
	ctx->dump_cur_block++;
	list_read_next_chunk(ctx);
}

/* Reads one TOC block (one segment entry) per I/O rather than batching
 * buf_size-sized chunks of several entries at once - simpler code, and a
 * scan of at most CHRONO_TOC_SLOT_COUNT blocks is cheap regardless. */
static void
list_read_next_chunk(struct app_context_t *ctx)
{
	int rc;

	if (ctx->dump_records_seen >= ctx->dump_target_count) {
		printf("%" PRIu64 " segment(s) listed.\n", ctx->dump_records_seen);
		cleanup_and_stop(ctx, 0);
		return;
	}

	rc = spdk_bdev_read(ctx->bdev_desc, ctx->bdev_io_channel, ctx->io_buf,
			     ctx->dump_cur_block * ctx->block_size, ctx->block_size,
			     list_chunk_read_complete, ctx);
	if (rc != 0) {
		SPDK_ERRLOG("%s reading TOC block %" PRIu64 "\n", spdk_strerror(-rc),
			    ctx->dump_cur_block);
		cleanup_and_stop(ctx, -1);
	}
}

static void
list_start(struct app_context_t *ctx)
{
	printf("Volume: %u/%u segments used, TOC at block %" PRIu64
	       ", data starts at block %" PRIu64 "\n",
	       ctx->vol.next_segment_id, ctx->vol.toc_slot_count,
	       ctx->vol.toc_start_block, ctx->vol.data_start_block);

	ctx->dump_cur_block = ctx->vol.toc_start_block;
	ctx->dump_records_seen = 0;
	ctx->dump_target_count = ctx->vol.next_segment_id;

	if (ctx->dump_target_count == 0) {
		printf("No segments recorded yet.\n");
		cleanup_and_stop(ctx, 0);
		return;
	}

	list_read_next_chunk(ctx);
}

static void
dump_start(struct app_context_t *ctx)
{
	int rc;

	if (!ctx->opts.dump_segment_given) {
		list_start(ctx);
		return;
	}

	rc = spdk_bdev_read(ctx->bdev_desc, ctx->bdev_io_channel, ctx->io_buf,
			     (ctx->vol.toc_start_block + ctx->opts.dump_segment_id) *
			     ctx->block_size, ctx->block_size,
			     dump_segment_entry_read_complete, ctx);
	if (rc != 0) {
		SPDK_ERRLOG("%s reading segment %u's TOC entry\n", spdk_strerror(-rc),
			    ctx->opts.dump_segment_id);
		cleanup_and_stop(ctx, -1);
	}
}

/* ---- shared volume-header read (capture + dump/list) ---- */

static void
volume_header_read_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct app_context_t *ctx = cb_arg;
	struct chrono_volume_header *hdr = (struct chrono_volume_header *)ctx->vol_buf;

	spdk_bdev_free_io(bdev_io);
	if (!success) {
		SPDK_ERRLOG("failed to read the volume header\n");
		fail_started(ctx);
		return;
	}
	if (!volume_header_is_valid(hdr)) {
		SPDK_ERRLOG("no valid chrontabulator volume on %s - run with --init first\n",
			    ctx->opts.bdev_name);
		fail_started(ctx);
		return;
	}

	ctx->vol = *hdr;
	if (ctx->vol.block_size != ctx->block_size) {
		SPDK_ERRLOG("volume was formatted with block_size=%u, but %s currently"
			    " reports block_size=%u - refusing to trust its offsets\n",
			    ctx->vol.block_size, ctx->opts.bdev_name, ctx->block_size);
		fail_started(ctx);
		return;
	}

	if (ctx->opts.dump_mode)
		dump_start(ctx);
	else
		claim_segment_start(ctx);
}

/* ---- --init: format a fresh volume ---- */

static void
init_write_header_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct app_context_t *ctx = cb_arg;

	spdk_bdev_free_io(bdev_io);
	if (!success) {
		SPDK_ERRLOG("failed to write the new volume header\n");
		fail_started(ctx);
		return;
	}

	printf("Initialized chrontabulator volume: %u segment slots reserved"
	       " (%.1f MB TOC), data starts at block %" PRIu64 "\n",
	       ctx->vol.toc_slot_count,
	       (double)(ctx->vol.data_start_block - ctx->vol.toc_start_block) *
	       ctx->block_size / (1024.0 * 1024.0),
	       ctx->vol.data_start_block);
	cleanup_and_stop(ctx, 0);
}

static void
init_write_header(struct app_context_t *ctx)
{
	int rc;

	memset(ctx->vol_buf, 0, ctx->block_size);
	*(struct chrono_volume_header *)ctx->vol_buf = ctx->vol;

	rc = spdk_bdev_write(ctx->bdev_desc, ctx->bdev_io_channel, ctx->vol_buf,
			      VOLUME_HEADER_BLOCK * ctx->block_size, ctx->block_size,
			      init_write_header_complete, ctx);
	if (rc != 0) {
		SPDK_ERRLOG("%s writing the new volume header\n", spdk_strerror(-rc));
		fail_started(ctx);
	}
}

static void
init_zero_toc_chunk(struct app_context_t *ctx);

/* Not queued/retried on -ENOMEM the way retry_flush() is for the
 * (much hotter, much longer-running) capture write path - --init is a
 * rare, one-time, already-explicit operation, so treating any write
 * failure here as fatal (re-run --init) is an acceptable simplification. */
static void
init_zero_toc_chunk_write_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct app_context_t *ctx = cb_arg;
	uint64_t blocks_left, chunk_blocks;

	spdk_bdev_free_io(bdev_io);
	if (!success) {
		SPDK_ERRLOG("failed zeroing the TOC region at block %" PRIu64 "\n",
			    ctx->init_cur_block);
		fail_started(ctx);
		return;
	}

	blocks_left = ctx->vol.data_start_block - ctx->init_cur_block;
	chunk_blocks = blocks_left < ctx->buf_size_blocks ? blocks_left : ctx->buf_size_blocks;
	ctx->init_cur_block += chunk_blocks;

	init_zero_toc_chunk(ctx);
}

static void
init_zero_toc_chunk(struct app_context_t *ctx)
{
	uint64_t blocks_left, chunk_blocks;
	uint32_t chunk_bytes;
	int rc;

	if (ctx->init_cur_block >= ctx->vol.data_start_block) {
		init_write_header(ctx);
		return;
	}

	blocks_left = ctx->vol.data_start_block - ctx->init_cur_block;
	chunk_blocks = blocks_left < ctx->buf_size_blocks ? blocks_left : ctx->buf_size_blocks;
	chunk_bytes = (uint32_t)(chunk_blocks * ctx->block_size);

	/* ctx->io_buf is freshly spdk_dma_zmalloc()'d and never written to
	 * before this point in the init path, so it's already all zeros -
	 * no memset needed before reusing it for every zero-fill write. */
	rc = spdk_bdev_write(ctx->bdev_desc, ctx->bdev_io_channel, ctx->io_buf,
			      ctx->init_cur_block * ctx->block_size, chunk_bytes,
			      init_zero_toc_chunk_write_complete, ctx);
	if (rc != 0) {
		SPDK_ERRLOG("%s zeroing the TOC region at block %" PRIu64 "\n",
			    spdk_strerror(-rc), ctx->init_cur_block);
		fail_started(ctx);
	}
}

static void
init_check_read_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct app_context_t *ctx = cb_arg;
	struct chrono_volume_header *hdr = (struct chrono_volume_header *)ctx->vol_buf;
	bool refuse = false;
	struct timespec ts;

	spdk_bdev_free_io(bdev_io);
	if (!success) {
		SPDK_ERRLOG("failed to read block 0\n");
		fail_started(ctx);
		return;
	}

	if (hdr->magic == CHRONO_VOLUME_MAGIC) {
		refuse = true;
		if (hdr->version == CHRONO_FORMAT_VERSION)
			SPDK_ERRLOG("device already initialized as a chrontabulator volume"
				    " with %u segment(s) recorded; pass --force to reformat"
				    " (existing segments become unreadable)\n",
				    hdr->next_segment_id);
		else
			SPDK_ERRLOG("device has a chrontabulator volume in unrecognized"
				    " format version %u (expected %u); pass --force to"
				    " reformat\n", hdr->version, CHRONO_FORMAT_VERSION);
	} else if (hdr->magic == CHRONO_SUPERBLOCK_MAGIC_V1) {
		refuse = true;
		SPDK_ERRLOG("device has a legacy (V1, pre-segment) chrontabulator capture"
			    " on it; pass --force to reformat\n");
	}

	if (refuse && !ctx->opts.force) {
		fail_started(ctx);
		return;
	}

	memset(&ctx->vol, 0, sizeof(ctx->vol));
	ctx->vol.magic = CHRONO_VOLUME_MAGIC;
	ctx->vol.version = CHRONO_FORMAT_VERSION;
	ctx->vol.block_size = ctx->block_size;
	ctx->vol.toc_slot_count = CHRONO_TOC_SLOT_COUNT;
	ctx->vol.next_segment_id = 0;
	ctx->vol.toc_start_block = VOLUME_HEADER_BLOCK + 1;
	ctx->vol.data_start_block = ctx->vol.toc_start_block + CHRONO_TOC_SLOT_COUNT;
	ctx->vol.next_data_block = ctx->vol.data_start_block;
	clock_gettime(CLOCK_REALTIME, &ts);
	ctx->vol.init_wall_clock_sec = (uint64_t)ts.tv_sec;

	ctx->init_cur_block = ctx->vol.toc_start_block;
	init_zero_toc_chunk(ctx);
}

static void
init_start(struct app_context_t *ctx)
{
	int rc;

	rc = spdk_bdev_read(ctx->bdev_desc, ctx->bdev_io_channel, ctx->vol_buf,
			     VOLUME_HEADER_BLOCK * ctx->block_size, ctx->block_size,
			     init_check_read_complete, ctx);
	if (rc != 0) {
		SPDK_ERRLOG("%s reading block 0\n", spdk_strerror(-rc));
		fail_started(ctx);
	}
}

static void
app_started(void *arg1)
{
	struct app_context_t *ctx = arg1;
	uint32_t buf_align;
	int rc;

	if (!ctx->opts.bdev_name) {
		SPDK_ERRLOG("-b <bdev> is required\n");
		spdk_app_stop(-1);
		return;
	}
	if (!ctx->opts.dump_mode && !ctx->opts.init_mode && ctx->opts.udp_port == 0) {
		SPDK_ERRLOG("-P <port> is required unless -D or --init is given\n");
		spdk_app_stop(-1);
		return;
	}
	if (ctx->opts.init_mode && ctx->opts.dump_mode) {
		SPDK_ERRLOG("--init and -D can't be used together\n");
		spdk_app_stop(-1);
		return;
	}
	if (ctx->opts.dump_segment_given && !ctx->opts.dump_mode) {
		SPDK_ERRLOG("-S requires -D\n");
		spdk_app_stop(-1);
		return;
	}

	SPDK_NOTICELOG("Opening bdev %s\n", ctx->opts.bdev_name);
	rc = spdk_bdev_open_ext(ctx->opts.bdev_name, true, app_bdev_event_cb, NULL,
				 &ctx->bdev_desc);
	if (rc) {
		SPDK_ERRLOG("Could not open bdev: %s\n", ctx->opts.bdev_name);
		spdk_app_stop(-1);
		return;
	}
	ctx->bdev = spdk_bdev_desc_get_bdev(ctx->bdev_desc);

	ctx->bdev_io_channel = spdk_bdev_get_io_channel(ctx->bdev_desc);
	if (ctx->bdev_io_channel == NULL) {
		SPDK_ERRLOG("Could not create bdev I/O channel\n");
		spdk_bdev_close(ctx->bdev_desc);
		spdk_app_stop(-1);
		return;
	}

	ctx->block_size = spdk_bdev_get_block_size(ctx->bdev);
	/* write_unit_size is the device's minimum atomic write granularity
	 * (typically 1 block), not a size to build the whole write buffer
	 * out of - a jumbo record alone can be ~9KB, which wouldn't fit in
	 * a 512-byte buffer. Round WRITE_CHUNK_TARGET up to a clean
	 * multiple of that granularity instead. */
	uint32_t write_unit_bytes = ctx->block_size * spdk_bdev_get_write_unit_size(ctx->bdev);
	ctx->buf_size = ((WRITE_CHUNK_TARGET + write_unit_bytes - 1) / write_unit_bytes) *
			write_unit_bytes;
	ctx->buf_size_blocks = ctx->buf_size / ctx->block_size;

	buf_align = spdk_bdev_get_buf_align(ctx->bdev);
	ctx->vol_buf = spdk_dma_zmalloc(ctx->block_size, buf_align, NULL);
	if (!ctx->vol_buf) {
		SPDK_ERRLOG("Failed to allocate volume header buffer\n");
		fail_started(ctx);
		return;
	}
	ctx->io_buf = spdk_dma_zmalloc(ctx->buf_size, buf_align, NULL);
	if (!ctx->io_buf) {
		SPDK_ERRLOG("Failed to allocate I/O buffer\n");
		fail_started(ctx);
		return;
	}

	if (ctx->opts.init_mode) {
		init_start(ctx);
		return;
	}

	rc = spdk_bdev_read(ctx->bdev_desc, ctx->bdev_io_channel, ctx->vol_buf,
			     VOLUME_HEADER_BLOCK * ctx->block_size, ctx->block_size,
			     volume_header_read_complete, ctx);
	if (rc != 0) {
		SPDK_ERRLOG("%s reading the volume header\n", spdk_strerror(-rc));
		fail_started(ctx);
	}
}

int
main(int argc, char **argv)
{
	struct spdk_app_opts opts = {};
	int rc;

	memset(&g_ctx, 0, sizeof(g_ctx));

	spdk_app_opts_init(&opts, sizeof(opts));
	opts.name = "chrontabulator";
	opts.shutdown_cb = app_shutdown_cb;

	rc = spdk_app_parse_args(argc, argv, &opts, "b:P:M:FC:DS:", chrono_long_opts,
				  app_parse_arg, app_usage);
	if (rc != SPDK_APP_PARSE_ARGS_SUCCESS)
		exit(rc);

	rc = spdk_app_start(&opts, app_started, &g_ctx);
	if (rc)
		SPDK_ERRLOG("ERROR starting application\n");

	spdk_app_fini();
	return rc;
}
