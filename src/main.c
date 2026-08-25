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

#include "common.h"
#include "port_init.h"
#include "record.h"

#define NUM_MBUFS        8191
#define MBUF_CACHE_SIZE  250
#define MBUF_DATA_SIZE   9216
#define BURST_SIZE       32
#define NUM_WRITE_BUFFERS 4
#define SUPERBLOCK_BLOCK 0
#define DATA_START_BLOCK 1

struct app_opts_t {
	char *bdev_name;
	uint16_t udp_port;
	uint16_t mtu;
	bool force_10g;
	uint64_t count_limit; /* 0 = unlimited */
	bool dump_mode;
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
	uint8_t *superblock_buf;

	/* --dump mode only: reads records back and prints them instead of
	 * capturing. Shares block_size/buf_size/buf_align/superblock_buf
	 * with the capture path above. */
	uint8_t *dump_buf;
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
	printf(" -P <port>                 UDP destination port to capture (required)\n");
	printf(" -M <mtu>                  set the NIC's MTU (0 = device default)\n");
	printf(" -F                        restrict advertised link speed to 10G only\n");
	printf(" -C <count>                stop after this many records (0 = unlimited)\n");
	printf(" -D                        dump records already on the bdev instead of capturing"
	       " (-P not required)\n");
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
	default:
		return -EINVAL;
	}
	return 0;
}

static void
begin_shutdown(struct app_context_t *ctx);

static void
superblock_write_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct app_context_t *ctx = cb_arg;

	if (bdev_io != NULL)
		spdk_bdev_free_io(bdev_io);
	if (!success)
		SPDK_ERRLOG("superblock write failed\n");

	SPDK_NOTICELOG("Recorded %" PRIu64 " packets (%" PRIu64 " dropped due to backpressure)\n",
		       ctx->record_count, ctx->dropped_count);

	spdk_dma_free(ctx->superblock_buf);
	if (ctx->bdev_io_channel)
		spdk_put_io_channel(ctx->bdev_io_channel);
	if (ctx->bdev_desc)
		spdk_bdev_close(ctx->bdev_desc);
	spdk_app_stop(0);
}

static void
write_superblock_and_stop(struct app_context_t *ctx)
{
	struct chrono_superblock *sb;
	int rc;

	sb = (struct chrono_superblock *)ctx->superblock_buf;
	memset(sb, 0, ctx->block_size);
	sb->magic = CHRONO_SUPERBLOCK_MAGIC;
	sb->version = CHRONO_FORMAT_VERSION;
	sb->block_size = ctx->block_size;
	sb->record_count = ctx->record_count;
	sb->dropped_count = ctx->dropped_count;
	sb->first_capture_tsc = ctx->first_capture_tsc;
	sb->last_capture_tsc = ctx->last_capture_tsc;
	sb->tsc_hz = rte_get_tsc_hz();

	rc = spdk_bdev_write(ctx->bdev_desc, ctx->bdev_io_channel, ctx->superblock_buf,
			      SUPERBLOCK_BLOCK * ctx->block_size, ctx->block_size,
			      superblock_write_complete, ctx);
	if (rc != 0) {
		SPDK_ERRLOG("%s writing superblock: %d\n", spdk_strerror(-rc), rc);
		superblock_write_complete(NULL, false, ctx);
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
		write_superblock_and_stop(ctx);
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
			write_superblock_and_stop(ctx);
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
		write_superblock_and_stop(ctx);
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

/* Releases whatever app_started() had already allocated before hitting a
 * fatal setup error, then stops the app. spdk_app_stop() alone isn't enough
 * here: SPDK's subsystem teardown waits for outstanding bdev descriptors and
 * I/O channels to close, so calling it while ctx->bdev_desc/bdev_io_channel
 * are still open leaves the reactor running indefinitely instead of exiting. */
static void
fail_started(struct app_context_t *ctx)
{
	for (int i = 0; i < NUM_WRITE_BUFFERS; i++) {
		if (ctx->buffers[i].data)
			spdk_dma_free(ctx->buffers[i].data);
	}
	if (ctx->superblock_buf)
		spdk_dma_free(ctx->superblock_buf);
	if (ctx->bdev_io_channel)
		spdk_put_io_channel(ctx->bdev_io_channel);
	if (ctx->bdev_desc)
		spdk_bdev_close(ctx->bdev_desc);
	spdk_app_stop(-1);
}

/* --dump mode: reads the superblock and every record back off the bdev
 * and prints them, to confirm the on-disk format round-trips correctly
 * before trusting a long capture run. Read-only in intent (bdev is still
 * opened for write, matching capture, since spdk_bdev_open_ext's
 * write_flag doesn't affect reads), no DPDK/NIC setup at all. */
static void
dump_stop(struct app_context_t *ctx, int rc)
{
	if (ctx->dump_buf)
		spdk_dma_free(ctx->dump_buf);
	if (ctx->superblock_buf)
		spdk_dma_free(ctx->superblock_buf);
	if (ctx->bdev_io_channel)
		spdk_put_io_channel(ctx->bdev_io_channel);
	if (ctx->bdev_desc)
		spdk_bdev_close(ctx->bdev_desc);
	spdk_app_stop(rc);
}

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
		dump_stop(ctx, -1);
		return;
	}

	while (offset + sizeof(struct chrono_record_hdr) <= ctx->buf_size &&
	       ctx->dump_records_seen < ctx->dump_target_count) {
		struct chrono_record_hdr *hdr = (struct chrono_record_hdr *)(ctx->dump_buf + offset);

		if (hdr->magic != CHRONO_RECORD_MAGIC)
			break;
		if (offset + sizeof(*hdr) + hdr->len > ctx->buf_size) {
			SPDK_ERRLOG("record at block %" PRIu64 " offset %u claims len %u,"
				    " overruns the write chunk - stopping\n",
				    ctx->dump_cur_block, offset, hdr->len);
			dump_stop(ctx, -1);
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
		printf("Dumped %" PRIu64 " of %" PRIu64 " records from the superblock.\n",
		       ctx->dump_records_seen, ctx->dump_target_count);
		dump_stop(ctx, 0);
		return;
	}
	if (offset == 0) {
		/* First record slot in this chunk was already padding -
		 * fewer real records on disk than the superblock claims. */
		SPDK_ERRLOG("expected %" PRIu64 " records, only found %" PRIu64
			    " before hitting unwritten space\n",
			    ctx->dump_target_count, ctx->dump_records_seen);
		dump_stop(ctx, -1);
		return;
	}

	dump_read_next_chunk(ctx);
}

static void
dump_read_next_chunk(struct app_context_t *ctx)
{
	int rc;

	rc = spdk_bdev_read(ctx->bdev_desc, ctx->bdev_io_channel, ctx->dump_buf,
			     ctx->dump_cur_block * ctx->block_size, ctx->buf_size,
			     dump_chunk_read_complete, ctx);
	if (rc != 0) {
		SPDK_ERRLOG("%s reading block %" PRIu64 "\n", spdk_strerror(-rc), ctx->dump_cur_block);
		dump_stop(ctx, -1);
	}
}

static void
dump_superblock_read_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct app_context_t *ctx = cb_arg;
	struct chrono_superblock *sb = (struct chrono_superblock *)ctx->superblock_buf;
	uint32_t buf_align;

	spdk_bdev_free_io(bdev_io);
	if (!success) {
		SPDK_ERRLOG("failed to read superblock\n");
		dump_stop(ctx, -1);
		return;
	}
	if (sb->magic != CHRONO_SUPERBLOCK_MAGIC) {
		SPDK_ERRLOG("no valid superblock found on %s (never recorded, or wrong bdev)\n",
			    ctx->opts.bdev_name);
		dump_stop(ctx, -1);
		return;
	}

	printf("Superblock: version=%u block_size=%u record_count=%" PRIu64
	       " dropped_count=%" PRIu64 " tsc_hz=%" PRIu64 "\n",
	       sb->version, sb->block_size, sb->record_count, sb->dropped_count, sb->tsc_hz);
	if (sb->tsc_hz != 0)
		printf("Capture span: %.3fs\n",
		       (double)(sb->last_capture_tsc - sb->first_capture_tsc) / sb->tsc_hz);

	ctx->dump_target_count = sb->record_count;
	ctx->dump_first_capture_tsc = sb->first_capture_tsc;
	ctx->dump_tsc_hz = sb->tsc_hz;

	if (ctx->dump_target_count == 0) {
		printf("Nothing recorded.\n");
		dump_stop(ctx, 0);
		return;
	}

	buf_align = spdk_bdev_get_buf_align(ctx->bdev);
	ctx->dump_buf = spdk_dma_zmalloc(ctx->buf_size, buf_align, NULL);
	if (!ctx->dump_buf) {
		SPDK_ERRLOG("Failed to allocate dump read buffer\n");
		dump_stop(ctx, -1);
		return;
	}
	ctx->dump_cur_block = DATA_START_BLOCK;

	dump_read_next_chunk(ctx);
}

static void
dump_start(struct app_context_t *ctx)
{
	uint32_t buf_align = spdk_bdev_get_buf_align(ctx->bdev);
	int rc;

	ctx->superblock_buf = spdk_dma_zmalloc(ctx->block_size, buf_align, NULL);
	if (!ctx->superblock_buf) {
		SPDK_ERRLOG("Failed to allocate superblock buffer\n");
		dump_stop(ctx, -1);
		return;
	}

	rc = spdk_bdev_read(ctx->bdev_desc, ctx->bdev_io_channel, ctx->superblock_buf,
			     SUPERBLOCK_BLOCK * ctx->block_size, ctx->block_size,
			     dump_superblock_read_complete, ctx);
	if (rc != 0) {
		SPDK_ERRLOG("%s reading superblock\n", spdk_strerror(-rc));
		dump_stop(ctx, -1);
	}
}

static void
app_started(void *arg1)
{
	struct app_context_t *ctx = arg1;
	int rc;

	if (!ctx->opts.bdev_name || (!ctx->opts.dump_mode && ctx->opts.udp_port == 0)) {
		SPDK_ERRLOG("-b <bdev> is required (-P <port> too, unless -D)\n");
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
	ctx->buf_size = ctx->block_size * spdk_bdev_get_write_unit_size(ctx->bdev);
	ctx->buf_size_blocks = ctx->buf_size / ctx->block_size;

	if (ctx->opts.dump_mode) {
		dump_start(ctx);
		return;
	}

	uint32_t buf_align = spdk_bdev_get_buf_align(ctx->bdev);
	for (int i = 0; i < NUM_WRITE_BUFFERS; i++) {
		ctx->buffers[i].data = spdk_dma_zmalloc(ctx->buf_size, buf_align, NULL);
		if (!ctx->buffers[i].data) {
			SPDK_ERRLOG("Failed to allocate write buffer %d\n", i);
			fail_started(ctx);
			return;
		}
	}
	ctx->superblock_buf = spdk_dma_zmalloc(ctx->block_size, buf_align, NULL);
	if (!ctx->superblock_buf) {
		SPDK_ERRLOG("Failed to allocate superblock buffer\n");
		fail_started(ctx);
		return;
	}
	ctx->next_write_block = DATA_START_BLOCK;

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

	SPDK_NOTICELOG("Recording UDP port %u to bdev %s, port %u ready\n",
		       ctx->opts.udp_port, ctx->opts.bdev_name, ctx->port);

	ctx->rx_poller = spdk_poller_register(capture_poll, ctx, 0);
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

	rc = spdk_app_parse_args(argc, argv, &opts, "b:P:M:FC:D", NULL, app_parse_arg, app_usage);
	if (rc != SPDK_APP_PARSE_ARGS_SUCCESS)
		exit(rc);

	rc = spdk_app_start(&opts, app_started, &g_ctx);
	if (rc)
		SPDK_ERRLOG("ERROR starting application\n");

	spdk_app_fini();
	return rc;
}
