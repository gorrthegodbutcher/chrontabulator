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
#include "chrono_ctx.h"
#include "chrono_admin.h"
#include "web_status.h"
#include "net_responder.h"

#define NUM_MBUFS        8191
#define MBUF_CACHE_SIZE  250
#define MBUF_DATA_SIZE   9216
#define BURST_SIZE       32
#define VOLUME_HEADER_BLOCK 0
/* Consecutive spdk_bdev_write() failures (submission or completion) before
 * giving up and stopping recording, rather than retrying forever at full
 * speed. Low on purpose: a real transient hiccup (the only kind worth
 * retrying through) resolves in 1-2 attempts; every case observed in
 * practice so far is a hard, permanent rejection (e.g. EINVAL) that will
 * never succeed no matter how many times it's retried, so waiting longer
 * just burns CPU that capture_poll() needs for RX - the actual cause of
 * the packet-drop cascade this is meant to prevent. */
#define CHRONO_WRITE_FAILURE_THRESHOLD 5
#define WRITE_CHUNK_TARGET (64 * 1024) /* default --write-chunk-kb, rounded
					 * up to the device's own write
					 * granularity below - not a hard
					 * size, just comfortably bigger than
					 * one jumbo (~9KB) record */
#define DEFAULT_WRITE_BUFFERS 8 /* default --write-buffers */

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
	CHRONO_OPT_SERVE,
	CHRONO_OPT_WEB_PORT,
	CHRONO_OPT_WRITE_BUFFERS,
	CHRONO_OPT_WRITE_CHUNK_KB,
	CHRONO_OPT_REPAIR_CHUNK_BYTES,
	CHRONO_OPT_NO_WIRE_SEQ,
};

static const struct option chrono_long_opts[] = {
	{"init",               no_argument,       NULL, CHRONO_OPT_INIT},
	{"force",              no_argument,       NULL, CHRONO_OPT_FORCE},
	{"serve",              no_argument,       NULL, CHRONO_OPT_SERVE},
	{"web-port",           required_argument, NULL, CHRONO_OPT_WEB_PORT},
	{"write-buffers",      required_argument, NULL, CHRONO_OPT_WRITE_BUFFERS},
	{"write-chunk-kb",     required_argument, NULL, CHRONO_OPT_WRITE_CHUNK_KB},
	{"repair-chunk-bytes", required_argument, NULL, CHRONO_OPT_REPAIR_CHUNK_BYTES},
	{"no-wire-seq",        no_argument,       NULL, CHRONO_OPT_NO_WIRE_SEQ},
	{NULL, 0, NULL, 0},
};

/* struct app_opts_t / write_buf / app_context_t now live in chrono_ctx.h,
 * shared with chrono_admin.c (the reactor-thread side of the web bridge)
 * and web_status.c (the pthread side). */

static struct app_context_t g_ctx;

static void
app_usage(void)
{
	printf(" -b <bdev>                 name of the bdev to record to (required)\n");
	printf(" -P <port>                 UDP destination port to capture (required unless -D or --init)\n");
	printf(" -M <mtu>                  set the NIC's MTU (0 = device default)\n");
	printf(" -I <ip>                   answer ARP/ping for this IP (omit = don't respond at all)\n");
	printf(" -F                        restrict advertised link speed to 10G only\n");
	printf(" -C <count>                stop after this many records (0 = unlimited)\n");
	printf(" -D                        list segments on the bdev instead of capturing\n");
	printf(" -D -S <id>                dump one segment's records instead of listing\n");
	printf(" --init                    format the bdev as a fresh, empty chrontabulator volume\n");
	printf(" --force                   with --init, reformat a bdev that already has one\n");
	printf(" --serve                   run as a persistent daemon - -P/-C become the default\n");
	printf("                           for sessions started via the web UI, not a hard\n");
	printf("                           requirement; brings up the NIC once and lets\n");
	printf("                           recording be started/stopped repeatedly\n");
	printf(" --web-port=<port>         daemon's embedded web UI port (default 8080, 0 = headless)\n");
	printf(" --write-buffers=<N>       starting number of write buffers, 1-%d (default %d) -\n",
	       MAX_WRITE_BUFFERS, DEFAULT_WRITE_BUFFERS);
	printf("                           live-tunable from the web UI while not recording\n");
	printf(" --write-chunk-kb=<N>      starting write chunk size in KB, %d-%d (default %d) -\n",
	       MIN_WRITE_CHUNK_BYTES / 1024, MAX_WRITE_CHUNK_BYTES / 1024,
	       WRITE_CHUNK_TARGET / 1024);
	printf("                           live-tunable from the web UI while not recording\n");
	printf(" -D -S <id> --repair-chunk-bytes=<N>\n");
	printf("                           patch segment <id>'s stored write chunk size instead\n");
	printf("                           of dumping it - recovery tool for a now-fixed race\n");
	printf("                           where a SET_WRITE_CHUNK/SET_WRITE_BUFFERS request\n");
	printf("                           landing between clicking Start and the claim actually\n");
	printf("                           completing changed the live write chunk size without\n");
	printf("                           updating the already-committed TOC entry\n");
	printf(" --no-wire-seq             inbound traffic on -P <port> does NOT carry dpdk-app-\n");
	printf("                           example's optional 8-byte sequence prefix (its own\n");
	printf("                           --no-seq/with_seq) - only affects where the real\n");
	printf("                           payload is found; every captured record's own seq\n");
	printf("                           field is always this capture's self-assigned, gapless\n");
	printf("                           counter regardless, never taken from the wire. Default:\n");
	printf("                           expect the prefix (matches dpdk-app-example's own\n");
	printf("                           default) - use this for real production traffic.\n");
	printf("                           Live-tunable from the web UI while not recording\n");
	printf("                           (POST /wire-has-seq?value=0|1) - this flag only sets\n");
	printf("                           the daemon's startup value.\n");
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
	case 'I':
		if (app_parse_ipv4(arg, g_ctx.opts.local_ip) != 0) {
			fprintf(stderr, "Invalid -I address: %s\n", arg);
			return -EINVAL;
		}
		g_ctx.opts.have_local_ip = true;
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
	case CHRONO_OPT_SERVE:
		g_ctx.opts.serve_mode = true;
		break;
	case CHRONO_OPT_WEB_PORT:
		g_ctx.opts.web_port = (uint16_t)strtoul(arg, NULL, 10);
		break;
	case CHRONO_OPT_WRITE_BUFFERS: {
		unsigned long n = strtoul(arg, NULL, 10);
		if (n < 1 || n > MAX_WRITE_BUFFERS) {
			fprintf(stderr, "--write-buffers must be 1-%d\n", MAX_WRITE_BUFFERS);
			return -EINVAL;
		}
		g_ctx.opts.write_buf_count = (uint32_t)n;
		break;
	}
	case CHRONO_OPT_WRITE_CHUNK_KB: {
		unsigned long kb = strtoul(arg, NULL, 10);
		if (kb * 1024 < MIN_WRITE_CHUNK_BYTES || kb * 1024 > MAX_WRITE_CHUNK_BYTES) {
			fprintf(stderr, "--write-chunk-kb must be %d-%d\n",
				MIN_WRITE_CHUNK_BYTES / 1024, MAX_WRITE_CHUNK_BYTES / 1024);
			return -EINVAL;
		}
		g_ctx.opts.write_chunk_bytes = (uint32_t)(kb * 1024);
		break;
	}
	case CHRONO_OPT_REPAIR_CHUNK_BYTES: {
		unsigned long bytes = strtoul(arg, NULL, 10);
		if (bytes == 0 || bytes > MAX_WRITE_CHUNK_BYTES) {
			fprintf(stderr, "--repair-chunk-bytes must be 1-%d\n", MAX_WRITE_CHUNK_BYTES);
			return -EINVAL;
		}
		g_ctx.opts.repair_chunk_bytes = (uint32_t)bytes;
		break;
	}
	case CHRONO_OPT_NO_WIRE_SEQ:
		g_ctx.opts.wire_has_seq = false;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static void
begin_shutdown(struct app_context_t *ctx);

static void
daemon_finalize_segment(struct app_context_t *ctx);

static bool
volume_header_is_valid(const struct chrono_volume_header *hdr)
{
	return hdr->magic == CHRONO_VOLUME_MAGIC && hdr->version == CHRONO_FORMAT_VERSION;
}

/* Shared by app_started()'s startup computation and the live
 * CHRONO_ADMIN_SET_WRITE_CHUNK handler - clamps to [MIN_WRITE_CHUNK_BYTES,
 * MAX_WRITE_CHUNK_BYTES] first (a request outside that range is rejected by
 * the caller before this ever runs, but clamping here too is cheap
 * insurance) then rounds up to a multiple of the device's write_unit_bytes,
 * same as the original WRITE_CHUNK_TARGET rounding - a jumbo record alone
 * can be ~9KB, which wouldn't fit in a single 512-byte write_unit. */
static uint32_t
chrono_round_write_chunk(struct app_context_t *ctx, uint32_t requested)
{
	if (requested < MIN_WRITE_CHUNK_BYTES)
		requested = MIN_WRITE_CHUNK_BYTES;
	if (requested > MAX_WRITE_CHUNK_BYTES)
		requested = MAX_WRITE_CHUNK_BYTES;
	return ((requested + ctx->write_unit_bytes - 1) / ctx->write_unit_bytes) *
	       ctx->write_unit_bytes;
}

/* Stops and closes the DPDK port, if chrono_port_init() ever actually
 * brought one up (guarded by ctx->nic_up - see chrono_ctx.h). Leaving the
 * port running when the process exits has been a real source of flaky
 * link renegotiation on the next run - same rationale, and the same
 * stop/close/settle sequence, as dpdk-app-example's main.c. Safe to call
 * more than once (fail_started()/cleanup_and_stop() are both reachable
 * from several points and neither is mutually exclusive with the other in
 * a way that guarantees single-call); nic_up is cleared immediately so a
 * second call is a no-op. */
static void
chrono_port_teardown(struct app_context_t *ctx)
{
	if (!ctx->nic_up)
		return;
	ctx->nic_up = false;

	int stop_ret = rte_eth_dev_stop(ctx->port);
	if (stop_ret != 0)
		SPDK_ERRLOG("rte_eth_dev_stop failed: %s\n", rte_strerror(-stop_ret));

	int close_ret = rte_eth_dev_close(ctx->port);
	if (close_ret != 0)
		SPDK_ERRLOG("rte_eth_dev_close failed: %s\n", rte_strerror(-close_ret));

	/* IEEE 802.3 autonegotiation is a physical-layer state machine with
	 * its own settling time - closing the port doesn't make that
	 * instantaneous, and rapidly cycling close-then-reopen has been
	 * observed elsewhere in this pair of projects to leave a link unable
	 * to pass traffic even though both sides report it UP. */
	rte_delay_us(3000000);
}

/* Releases whatever app_started() had already allocated before hitting a
 * fatal setup error (in any of the three modes - capture, dump/list,
 * init), then stops the app with a nonzero exit code. spdk_app_stop()
 * alone isn't enough here: SPDK's subsystem teardown waits for
 * outstanding bdev descriptors and I/O channels to close, so calling it
 * while ctx->bdev_desc/bdev_io_channel are still open leaves the reactor
 * running indefinitely instead of exiting. Safe to call at any point -
 * every field it touches is NULL/zero (or, for nic_up, false) until
 * actually allocated/set (g_ctx is memset at startup), and buffers[] is
 * only ever populated well into the capture path, never in dump/list/init. */
static void
fail_started(struct app_context_t *ctx)
{
	chrono_port_teardown(ctx);
	for (int i = 0; i < MAX_WRITE_BUFFERS; i++) {
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
	chrono_port_teardown(ctx);
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
		       atomic_load_explicit(&ctx->record_count, memory_order_relaxed),
		       atomic_load_explicit(&ctx->dropped_count, memory_order_relaxed),
		       ctx->segment_id);

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
	seg->write_chunk_bytes = ctx->buf_size; /* claim already set this, but
						  * finalize rebuilds the whole
						  * TOC entry from scratch
						  * (memset above) rather than a
						  * true read-modify-write, so it
						  * has to be repeated here or
						  * every finalized segment loses
						  * it - the bug that made every
						  * segment's data unreadable past
						  * its first chunk once a
						  * finalized read had to fall
						  * back to the READER's own
						  * (possibly different) buf_size. */
	seg->block_count = ctx->next_write_block - ctx->segment_start_block;
	seg->record_count = atomic_load_explicit(&ctx->record_count, memory_order_relaxed);
	seg->dropped_count = atomic_load_explicit(&ctx->dropped_count, memory_order_relaxed);
	seg->first_capture_tsc = atomic_load_explicit(&ctx->first_capture_tsc, memory_order_relaxed);
	seg->last_capture_tsc = atomic_load_explicit(&ctx->last_capture_tsc, memory_order_relaxed);
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

/* Shared by both CLI and daemon capture - the actual buffer-flush
 * mechanics have no mode-specific behavior except which finalize
 * function to call once a stop is fully drained, so a single dispatch
 * point here is simpler and safer than duplicating this hot-path
 * plumbing just to keep the two calls apart (unlike claim/finalize's own
 * control logic, which IS duplicated - see daemon_claim_segment_start()
 * etc. - specifically to keep this already-verified data path itself
 * untouched by that split). */
static void
finalize_current_stop(struct app_context_t *ctx)
{
	if (ctx->opts.serve_mode)
		daemon_finalize_segment(ctx);
	else
		finalize_segment_and_stop(ctx);
}

/* Called from both write_complete()'s completion-failure path and
 * retry_flush()'s submission-failure path - either one means the device
 * just refused a write. CHRONO_WRITE_FAILURE_THRESHOLD consecutive
 * failures (reset by any success - see write_complete()) stops recording
 * instead of retrying forever: observed in practice, every failure so far
 * has been a hard, permanent rejection (spdk_bdev_write() returning EINVAL
 * on every subsequent attempt, not a transient I/O error), so retrying
 * indefinitely just burns the reactor thread's time re-submitting doomed
 * writes instead of servicing RX - which is what actually produced the
 * cascade of dropped packets that made a broken write path look like a
 * capture-side problem. Safe to call when already stopping (mid-finalize-
 * flush racing the same failure) - daemon_stop_recording()/begin_shutdown()
 * both no-op if ctx->stopping is already true. */
static void
chrono_note_write_failure(struct app_context_t *ctx)
{
	ctx->consecutive_write_failures++;
	if (ctx->consecutive_write_failures < CHRONO_WRITE_FAILURE_THRESHOLD)
		return;

	SPDK_ERRLOG("%u consecutive write failures - device is not accepting writes,"
		    " stopping recording\n", ctx->consecutive_write_failures);
	atomic_store_explicit(&ctx->last_stop_reason, CHRONO_STOP_WRITE_FAILURES,
			       memory_order_relaxed);
	if (ctx->opts.serve_mode)
		daemon_stop_recording(ctx);
	else
		begin_shutdown(ctx);
}

static void
write_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct write_buf *wb = cb_arg;
	struct app_context_t *ctx = &g_ctx;

	spdk_bdev_free_io(bdev_io);
	wb->in_flight = false;
	wb->used = 0;

	if (!success) {
		SPDK_ERRLOG("bdev write error\n");
		atomic_fetch_add_explicit(&ctx->write_errors_total, 1, memory_order_relaxed);
		chrono_note_write_failure(ctx);
	} else {
		atomic_fetch_add_explicit(&ctx->bytes_written_total, ctx->buf_size,
					   memory_order_relaxed);
		atomic_fetch_add_explicit(&ctx->writes_completed_total, 1, memory_order_relaxed);
		ctx->consecutive_write_failures = 0;
	}

	ctx->pending_writes--;
	if (ctx->stopping && ctx->pending_writes == 0)
		finalize_current_stop(ctx);
}

static void
retry_flush(void *arg)
{
	struct write_buf *wb = arg;
	struct app_context_t *ctx = &g_ctx;
	int rc;

	/* wb->target_block, not ctx->next_write_block: this can run long
	 * after the buffer was originally handed off (queued via
	 * spdk_bdev_queue_io_wait() below, then re-fired later by SPDK once
	 * some unrelated I/O completes), by which point ctx->next_write_block
	 * has moved on to whatever buffer flushed after this one. Using the
	 * live value here would write this buffer to the WRONG block - and
	 * if that drifted-to position happens to be past the device end, the
	 * write fails every time it's retried with no way to ever succeed,
	 * while SPDK keeps re-queuing/re-firing it on every later completion:
	 * a permanent, silent hot loop that also drove ctx->pending_writes
	 * deeply negative (repeated failures here with no matching
	 * flush_buffer() increment), permanently blocking finalize. Checking
	 * bounds against the buffer's own fixed target, once, before ever
	 * calling spdk_bdev_write(), turns that into a single clean failure. */
	if (wb->target_block + ctx->buf_size_blocks > ctx->cached_num_blocks) {
		SPDK_ERRLOG("abandoning write buffer targeting block %" PRIu64
			    " - past device end (%" PRIu64 ")\n",
			    wb->target_block, ctx->cached_num_blocks);
		atomic_fetch_add_explicit(&ctx->write_errors_total, 1, memory_order_relaxed);
		wb->in_flight = false;
		wb->used = 0;
		ctx->pending_writes--;
		chrono_note_write_failure(ctx);
		if (ctx->stopping && ctx->pending_writes == 0)
			finalize_current_stop(ctx);
		return;
	}

	rc = spdk_bdev_write(ctx->bdev_desc, ctx->bdev_io_channel, wb->data,
			      wb->target_block * ctx->block_size, ctx->buf_size,
			      write_complete, wb);
	if (rc == -ENOMEM) {
		ctx->retry_buf = wb;
		ctx->bdev_io_wait.bdev = ctx->bdev;
		ctx->bdev_io_wait.cb_fn = retry_flush;
		ctx->bdev_io_wait.cb_arg = wb;
		spdk_bdev_queue_io_wait(ctx->bdev, ctx->bdev_io_channel, &ctx->bdev_io_wait);
	} else if (rc != 0) {
		SPDK_ERRLOG("%s flushing write buffer: %d\n", spdk_strerror(-rc), rc);
		atomic_fetch_add_explicit(&ctx->write_errors_total, 1, memory_order_relaxed);
		wb->in_flight = false;
		wb->used = 0;
		ctx->pending_writes--;
		chrono_note_write_failure(ctx);
		if (ctx->stopping && ctx->pending_writes == 0)
			finalize_current_stop(ctx);
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

	if (ctx->next_write_block + ctx->buf_size_blocks > ctx->cached_num_blocks) {
		/* Device is already full. capture_poll() checks this same
		 * condition before ever calling us for a just-filled buffer
		 * (see there for why: write_complete() has no way to tell
		 * "device full" apart from a transient error, so nothing
		 * downstream of that check would ever stop capture on its
		 * own), so the only way to land here is begin_shutdown()'s/
		 * daemon_stop_recording()'s own final flush of the
		 * currently-accumulating buffer racing the same condition.
		 * Drop it rather than issue a write that's guaranteed to
		 * fail. */
		SPDK_ERRLOG("dropping final %u-byte buffer: no room left on device"
			    " (block %" PRIu64 " + %u > %" PRIu64 ")\n",
			    wb->used, ctx->next_write_block, ctx->buf_size_blocks,
			    ctx->cached_num_blocks);
		wb->used = 0;
		return;
	}

	/* spdk_dma_zmalloc() only zeroes a buffer once, at allocation. Each
	 * of the active write_buf_count slots gets reused many times over a
	 * long capture, and a later, smaller fill would otherwise leave stale
	 * record bytes from a previous, larger fill sitting past the new
	 * `used` boundary - a reader relying on magic==0 to mean "no more
	 * records here" would misparse that leftover as real data. */
	if (wb->used < ctx->buf_size)
		memset(wb->data + wb->used, 0, ctx->buf_size - wb->used);

	wb->in_flight = true;
	wb->target_block = ctx->next_write_block;
	ctx->pending_writes++;
	retry_flush(wb);
	ctx->next_write_block += ctx->buf_size_blocks;

	/* mirror_next_data_block is normally the volume header's own
	 * committed high-water mark, updated only at finalize (see
	 * daemon_finalize_header_write_complete()/claim_segment_start()) -
	 * that's the crash-safe value, and it deliberately does NOT track an
	 * open segment's in-progress growth (an orphaned segment's space is
	 * meant to be silently reclaimed by the next run, not counted as
	 * "used" if the process dies first). But that same lag makes the web
	 * status page's data_used/data_free_bytes freeze at whatever they
	 * were when the current segment was claimed, for the entire length
	 * of a long recording - not wrong exactly, but not what "how full is
	 * the drive right now" should show a live viewer. Advancing this
	 * mirror here too (in addition to finalize) keeps the live display
	 * accurate without touching the actual on-disk/persisted value or
	 * its crash-recovery semantics at all - this is purely the in-memory
	 * atomic other threads read, never what --init/claim/finalize write
	 * to block 0. */
	atomic_store_explicit(&ctx->mirror_next_data_block, ctx->next_write_block,
			       memory_order_relaxed);
}

static int
capture_poll(void *arg)
{
	struct app_context_t *ctx = arg;
	struct rte_mbuf *bufs[BURST_SIZE];
	uint16_t nb_rx;
	int did_work = SPDK_POLLER_IDLE;

	nb_rx = rte_eth_rx_burst(ctx->port, 0, bufs, BURST_SIZE);
	if (nb_rx == 0)
		return SPDK_POLLER_IDLE;

	uint64_t now_tsc = rte_rdtsc();

	for (uint16_t i = 0; i < nb_rx; i++) {
		did_work = SPDK_POLLER_BUSY;

		if (net_responder_try_handle(ctx, bufs[i]))
			continue; /* ARP/ICMP-echo reply sent (or dropped) -
				   * mbuf ownership already given up */

		/* Daemon mode only (this poller now runs continuously - see
		 * daemon_bring_up_nic() - rather than only while a
		 * segment is claimed): nothing to record into while idle or
		 * mid-finalize, and ctx->buffers[]/ctx->cur_buf may be
		 * actively being flushed/reset by the finalize chain right
		 * now - just drop and move on. CLI mode never sets
		 * serve_mode, so this is a no-op there; its poller is
		 * unregistered synchronously before finalize begins (see
		 * begin_shutdown()), so it can never observe this state. */
		if (ctx->opts.serve_mode &&
		    (ctx->stopping || !atomic_load_explicit(&ctx->recording, memory_order_relaxed))) {
			rte_pktmbuf_free(bufs[i]);
			continue;
		}

		uint8_t *data = rte_pktmbuf_mtod(bufs[i], uint8_t *);
		uint32_t len = rte_pktmbuf_pkt_len(bufs[i]);

		uint16_t dst_port;
		uint64_t seq;
		const uint8_t *payload;
		uint32_t payload_len;

		bool is_ours = app_parse_packet(data, len, ctx->wire_has_seq, &dst_port, &seq,
						 &payload, &payload_len) == 0 &&
				dst_port == ctx->opts.udp_port;

		if (!is_ours) {
			rte_pktmbuf_free(bufs[i]);
			continue;
		}

		uint32_t rec_size = (uint32_t)sizeof(struct chrono_record_hdr) + payload_len;
		struct write_buf *wb = &ctx->buffers[ctx->cur_buf];

		if (wb->in_flight) {
			/* cur_buf's previous write hasn't completed yet (all
			 * write_buf_count buffers are backed up) - the round-
			 * robin below never got to advance past it, so every
			 * packet that lands here would otherwise fall into the
			 * "doesn't fit" branch and call flush_buffer() on this
			 * SAME still in_flight buffer again: a second, concurrent
			 * spdk_bdev_write() of the same DMA memory the first
			 * write hasn't finished reading yet, and one extra
			 * pending_writes++ per packet instead of one per genuine
			 * flush - this is what ran pending_writes up into the
			 * millions and made it look like recording could never
			 * be stopped (finalize waits for pending_writes==0, which
			 * a runaway counter like that never reaches). Just drop
			 * and wait for write_complete() to free this buffer up. */
			atomic_fetch_add_explicit(&ctx->dropped_count, 1, memory_order_relaxed);
			rte_pktmbuf_free(bufs[i]);
			continue;
		}

		if (wb->used + rec_size > ctx->buf_size) {
			/* Doesn't fit in what's left of this buffer - flush
			 * it (flush_buffer() pads the remainder with zeros)
			 * and move to the next buffer round-robin. Bail out
			 * first if that flush would run the volume off the
			 * physical end of the device: write_complete() has no
			 * way to distinguish "device full" from a transient
			 * error, so without this check nothing would ever stop
			 * capture on its own - every future write would just
			 * keep failing forever (this is what produced the
			 * "wrote for a while, then a flood of write errors"
			 * symptom before this check existed). */
			if (ctx->next_write_block + ctx->buf_size_blocks > ctx->cached_num_blocks) {
				SPDK_ERRLOG("device full at block %" PRIu64 "/%" PRIu64
					    " - stopping recording\n",
					    ctx->next_write_block, ctx->cached_num_blocks);
				atomic_store_explicit(&ctx->last_stop_reason, CHRONO_STOP_DISK_FULL,
						       memory_order_relaxed);
				atomic_fetch_add_explicit(&ctx->dropped_count, 1,
							   memory_order_relaxed);
				rte_pktmbuf_free(bufs[i]);
				if (ctx->opts.serve_mode)
					daemon_stop_recording(ctx);
				else
					begin_shutdown(ctx);
				break;
			}

			flush_buffer(ctx, ctx->cur_buf);
			ctx->cur_buf = (ctx->cur_buf + 1) % ctx->write_buf_count;
			wb = &ctx->buffers[ctx->cur_buf];

			if (wb->in_flight || rec_size > ctx->buf_size) {
				/* Still busy (all buffers backed up), or a
				 * single record too large to ever fit one
				 * write chunk - drop it rather than block
				 * the RX loop. */
				atomic_fetch_add_explicit(&ctx->dropped_count, 1, memory_order_relaxed);
				rte_pktmbuf_free(bufs[i]);
				continue;
			}
		}

		/* capture_poll only ever runs on the reactor thread, never
		 * concurrently with itself, so these are the sole writers -
		 * plain load-then-store is enough (no CAS needed); atomics
		 * here exist only so the web thread can safely read live
		 * values for /status.json without a lock. */
		uint64_t new_count = atomic_fetch_add_explicit(&ctx->record_count, 1,
								memory_order_relaxed) + 1;

		struct chrono_record_hdr *hdr = (struct chrono_record_hdr *)(wb->data + wb->used);
		hdr->magic = CHRONO_RECORD_MAGIC;
		/* Self-assigned (this segment's Nth record captured, 0-indexed),
		 * NOT the wire-parsed seq local above - decouples this format's
		 * own gapless/monotonic guarantee (verifiable purely from what
		 * chrontabulator itself wrote, independent of anything a sender
		 * did or didn't include) from whatever's actually on the wire.
		 * ctx->wire_has_seq only controls where app_parse_packet()
		 * finds the real payload, never what ends up in this field -
		 * see common.h's with_seq. A real sender-to-storage sequence
		 * validator, if ever built, is a separate, pluggable analysis
		 * pass over the raw captured payload bytes, not this field. */
		hdr->seq = new_count - 1;
		hdr->capture_tsc = now_tsc;
		hdr->len = payload_len;
		hdr->reserved = 0;
		memcpy(wb->data + wb->used + sizeof(*hdr), payload, payload_len);
		wb->used += rec_size;
		if (atomic_load_explicit(&ctx->first_capture_tsc, memory_order_relaxed) == 0)
			atomic_store_explicit(&ctx->first_capture_tsc, now_tsc, memory_order_relaxed);
		atomic_store_explicit(&ctx->last_capture_tsc, now_tsc, memory_order_relaxed);

		rte_pktmbuf_free(bufs[i]);

		if (ctx->opts.count_limit != 0 && new_count >= ctx->opts.count_limit) {
			atomic_store_explicit(&ctx->last_stop_reason, CHRONO_STOP_COUNT_LIMIT,
					       memory_order_relaxed);
			if (ctx->opts.serve_mode)
				daemon_stop_recording(ctx);
			else
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
	/* Every slot allocated at MAX_WRITE_CHUNK_BYTES up front, regardless
	 * of the active ctx->buf_size - see MAX_WRITE_BUFFERS's comment in
	 * chrono_ctx.h for why. */
	for (int i = 0; i < MAX_WRITE_BUFFERS; i++) {
		ctx->buffers[i].data = spdk_dma_zmalloc(MAX_WRITE_CHUNK_BYTES, buf_align, NULL);
		if (!ctx->buffers[i].data) {
			SPDK_ERRLOG("Failed to allocate write buffer %d\n", i);
			fail_started(ctx);
			return;
		}
	}

	SPDK_NOTICELOG("bdev block_size=%u write_unit=%u buf_size=%u (%u/%d buffers active)\n",
		       ctx->block_size, spdk_bdev_get_write_unit_size(ctx->bdev),
		       ctx->buf_size, ctx->write_buf_count, MAX_WRITE_BUFFERS);

	if (rte_eth_dev_count_avail() != 1) {
		SPDK_ERRLOG("Expected exactly 1 available DPDK port, found %u\n",
			    rte_eth_dev_count_avail());
		fail_started(ctx);
		return;
	}
	RTE_ETH_FOREACH_DEV(ctx->port)
		break;

	ctx->mbuf_socket_id = rte_socket_id();
	ctx->mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0,
						  MBUF_DATA_SIZE, ctx->mbuf_socket_id);
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
	ctx->nic_up = true;
	rte_ether_addr_copy(&mac_addr, &ctx->local_mac);

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
	seg->write_chunk_bytes = ctx->buf_size;
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

	while (offset + sizeof(struct chrono_record_hdr) <= ctx->dump_write_chunk_bytes &&
	       ctx->dump_records_seen < ctx->dump_target_count) {
		struct chrono_record_hdr *hdr = (struct chrono_record_hdr *)(ctx->io_buf + offset);

		if (hdr->magic != CHRONO_RECORD_MAGIC)
			break;
		if (offset + sizeof(*hdr) + hdr->len > ctx->dump_write_chunk_bytes) {
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

	ctx->dump_cur_block += ctx->dump_write_chunk_blocks;

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
			     ctx->dump_cur_block * ctx->block_size, ctx->dump_write_chunk_bytes,
			     dump_chunk_read_complete, ctx);
	if (rc != 0) {
		SPDK_ERRLOG("%s reading block %" PRIu64 "\n", spdk_strerror(-rc), ctx->dump_cur_block);
		cleanup_and_stop(ctx, -1);
	}
}

static void
repair_chunk_bytes_write_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct app_context_t *ctx = cb_arg;

	spdk_bdev_free_io(bdev_io);
	if (!success) {
		SPDK_ERRLOG("failed to write segment %u's repaired TOC entry\n",
			    ctx->opts.dump_segment_id);
		cleanup_and_stop(ctx, -1);
		return;
	}
	printf("Segment %u: write_chunk_bytes repaired to %u.\n", ctx->opts.dump_segment_id,
	       ctx->opts.repair_chunk_bytes);
	cleanup_and_stop(ctx, 0);
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
	enum chrono_segment_view view = chrono_segment_classify(seg);

	if (view == CHRONO_SEG_VIEW_NOT_FOUND) {
		SPDK_ERRLOG("segment %u does not exist\n", ctx->opts.dump_segment_id);
		cleanup_and_stop(ctx, -1);
		return;
	}
	if (view == CHRONO_SEG_VIEW_OPEN) {
		printf("Segment %u: never finalized (in progress, or crashed before"
		       " finishing) - nothing to dump.\n", seg->segment_id);
		cleanup_and_stop(ctx, 0);
		return;
	}
	if (view == CHRONO_SEG_VIEW_DELETED)
		printf("Segment %u: DELETED (dumping its historical contents anyway)\n",
		       seg->segment_id);

	if (ctx->opts.repair_chunk_bytes != 0) {
		int rc;

		SPDK_NOTICELOG("Segment %u: repairing write_chunk_bytes %u -> %u\n",
			       seg->segment_id, seg->write_chunk_bytes,
			       ctx->opts.repair_chunk_bytes);
		seg->write_chunk_bytes = ctx->opts.repair_chunk_bytes;
		rc = spdk_bdev_write(ctx->bdev_desc, ctx->bdev_io_channel, ctx->io_buf,
				      (ctx->vol.toc_start_block + ctx->opts.dump_segment_id) *
				      ctx->block_size, ctx->block_size,
				      repair_chunk_bytes_write_complete, ctx);
		if (rc != 0) {
			SPDK_ERRLOG("%s repairing segment %u's TOC entry\n", spdk_strerror(-rc),
				    ctx->opts.dump_segment_id);
			cleanup_and_stop(ctx, -1);
		}
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
	/* 0 means this segment predates write_chunk_bytes being recorded
	 * (an older binary) - fall back to this process's own buf_size, the
	 * old implicit assumption, rather than divide by zero below. */
	ctx->dump_write_chunk_bytes = seg->write_chunk_bytes != 0 ?
		seg->write_chunk_bytes : ctx->buf_size;
	ctx->dump_write_chunk_blocks = ctx->dump_write_chunk_bytes / ctx->block_size;

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

	enum chrono_segment_view view = chrono_segment_classify(seg);

	if (view == CHRONO_SEG_VIEW_FINALIZED || view == CHRONO_SEG_VIEW_DELETED) {
		char start_str[32] = "n/a";
		time_t t = (time_t)seg->wall_clock_start_sec;
		struct tm tm_buf;

		if (gmtime_r(&t, &tm_buf) != NULL)
			strftime(start_str, sizeof(start_str), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);

		double duration = seg->tsc_hz != 0 ?
			(double)(seg->last_capture_tsc - seg->first_capture_tsc) /
			seg->tsc_hz : 0.0;
		printf("segment %u: %s  start=%s  duration=%.3fs"
		       "  records=%" PRIu64 "  dropped=%" PRIu64
		       "  blocks=[%" PRIu64 "+%" PRIu64 ")\n",
		       seg->segment_id, view == CHRONO_SEG_VIEW_DELETED ? "DELETED" : "FINALIZED",
		       start_str, duration, seg->record_count,
		       seg->dropped_count, seg->start_block, seg->block_count);
	} else if (view == CHRONO_SEG_VIEW_OPEN) {
		printf("segment %u: OPEN (in progress, or crashed before"
		       " finishing - never finalized)\n", seg->segment_id);
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

/* ---- --serve: persistent daemon ----
 *
 * Mirrors the shape of claim_segment_start()/claim_toc_write_complete()/
 * claim_header_write_complete() and finalize_segment_and_stop()/
 * finalize_header_write_complete()/finalize_toc_write_complete() above,
 * but as separate functions rather than branching those - threading a
 * serve_mode conditional through every success/error path of the
 * already-verified (1,000,000-packet scale) CLI capture chain risks
 * subtly changing its behavior. These duplicate the shape and end
 * differently: recording=true/poller registered (claim) or
 * recording=false/admin request answered (finalize), instead of falling
 * through to process exit. */

static void
daemon_teardown_and_exit(struct app_context_t *ctx)
{
	spdk_poller_unregister(&ctx->rx_poller);
	cleanup_and_stop(ctx, 0);
}

static void
daemon_finalize_toc_write_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct app_context_t *ctx = cb_arg;

	if (bdev_io != NULL)
		spdk_bdev_free_io(bdev_io);
	if (!success)
		SPDK_ERRLOG("failed to finalize segment %u's TOC entry\n", ctx->segment_id);

	SPDK_NOTICELOG("Recorded %" PRIu64 " packets (%" PRIu64 " dropped due to backpressure)"
		       " in segment %u\n",
		       atomic_load_explicit(&ctx->record_count, memory_order_relaxed),
		       atomic_load_explicit(&ctx->dropped_count, memory_order_relaxed),
		       ctx->segment_id);

	atomic_store_explicit(&ctx->recording, false, memory_order_relaxed);
	atomic_store_explicit(&ctx->current_segment_id, CHRONO_NO_SEGMENT, memory_order_relaxed);

	/* A SIGINT mid-recording routes here via daemon_stop_recording() too
	 * (see daemon_shutdown_cb()) - if that's why we're finalizing, there
	 * is no web request waiting to be answered, so tear the whole daemon
	 * down instead of trying to fulfill one. */
	if (atomic_load_explicit(&ctx->shutting_down, memory_order_relaxed))
		daemon_teardown_and_exit(ctx);
	else
		chrono_admin_fulfill(&ctx->admin_req, success ? 0 : -EIO);
}

static void
daemon_finalize_header_write_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
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
	else
		atomic_store_explicit(&ctx->mirror_next_data_block, ctx->vol.next_data_block,
				       memory_order_relaxed);

	memset(ctx->io_buf, 0, ctx->block_size);
	seg = (struct chrono_segment_entry *)ctx->io_buf;
	seg->magic = CHRONO_SEGMENT_MAGIC;
	seg->segment_id = ctx->segment_id;
	seg->state = CHRONO_SEGMENT_FINALIZED;
	seg->start_block = ctx->segment_start_block;
	seg->write_chunk_bytes = ctx->buf_size; /* claim already set this, but
						  * finalize rebuilds the whole
						  * TOC entry from scratch
						  * (memset above) rather than a
						  * true read-modify-write, so it
						  * has to be repeated here or
						  * every finalized segment loses
						  * it - the bug that made every
						  * segment's data unreadable past
						  * its first chunk once a
						  * finalized read had to fall
						  * back to the READER's own
						  * (possibly different) buf_size. */
	seg->block_count = ctx->next_write_block - ctx->segment_start_block;
	seg->record_count = atomic_load_explicit(&ctx->record_count, memory_order_relaxed);
	seg->dropped_count = atomic_load_explicit(&ctx->dropped_count, memory_order_relaxed);
	seg->first_capture_tsc = atomic_load_explicit(&ctx->first_capture_tsc, memory_order_relaxed);
	seg->last_capture_tsc = atomic_load_explicit(&ctx->last_capture_tsc, memory_order_relaxed);
	seg->tsc_hz = rte_get_tsc_hz();
	seg->wall_clock_start_sec = ctx->segment_wall_start_sec;
	seg->wall_clock_start_nsec = ctx->segment_wall_start_nsec;
	clock_gettime(CLOCK_REALTIME, &ts);
	seg->wall_clock_end_sec = (uint64_t)ts.tv_sec;
	seg->wall_clock_end_nsec = (uint32_t)ts.tv_nsec;

	rc = spdk_bdev_write(ctx->bdev_desc, ctx->bdev_io_channel, ctx->io_buf,
			      (ctx->vol.toc_start_block + ctx->segment_id) * ctx->block_size,
			      ctx->block_size, daemon_finalize_toc_write_complete, ctx);
	if (rc != 0) {
		SPDK_ERRLOG("%s finalizing segment %u's TOC entry\n", spdk_strerror(-rc),
			    ctx->segment_id);
		daemon_finalize_toc_write_complete(NULL, false, ctx);
	}
}

static void
daemon_finalize_segment(struct app_context_t *ctx)
{
	int rc;

	ctx->vol.next_data_block = ctx->next_write_block;
	memset(ctx->vol_buf, 0, ctx->block_size);
	*(struct chrono_volume_header *)ctx->vol_buf = ctx->vol;

	rc = spdk_bdev_write(ctx->bdev_desc, ctx->bdev_io_channel, ctx->vol_buf,
			      VOLUME_HEADER_BLOCK * ctx->block_size, ctx->block_size,
			      daemon_finalize_header_write_complete, ctx);
	if (rc != 0) {
		SPDK_ERRLOG("%s finalizing volume header: %d\n", spdk_strerror(-rc), rc);
		daemon_finalize_header_write_complete(NULL, false, ctx);
	}
}

/* Called both by admin_do_recording_stop() (chrono_admin.c, a web
 * request) and by daemon_shutdown_cb() (a SIGINT mid-recording) - the
 * finalize chain above tells the two cases apart via ctx->shutting_down
 * at its terminal step. */
void
daemon_stop_recording(struct app_context_t *ctx)
{
	if (ctx->stopping)
		return;
	ctx->stopping = true;

	/* rx_poller stays registered - it keeps answering ARP/ping while
	 * idle (see daemon_bring_up_nic()); only the NVMe-write half
	 * of capture_poll() needs to stop, gated there on ctx->recording. */
	flush_buffer(ctx, ctx->cur_buf);

	if (ctx->pending_writes == 0)
		daemon_finalize_segment(ctx);
	/* else write_complete()/retry_flush() call daemon_finalize_segment()
	 * once pending_writes reaches 0, via finalize_current_stop(). */
}

static void
daemon_claim_header_write_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct app_context_t *ctx = cb_arg;

	if (bdev_io != NULL)
		spdk_bdev_free_io(bdev_io);
	if (!success) {
		SPDK_ERRLOG("failed to record segment %u's claim in the volume header\n",
			    ctx->segment_id);
		atomic_store_explicit(&ctx->claim_in_progress, false, memory_order_relaxed);
		chrono_admin_fulfill(&ctx->admin_req, -EIO);
		return;
	}

	atomic_store_explicit(&ctx->mirror_next_segment_id, ctx->vol.next_segment_id,
			       memory_order_relaxed);

	ctx->next_write_block = ctx->segment_start_block;
	ctx->cur_buf = 0;
	/* All MAX_WRITE_BUFFERS slots, not just the active write_buf_count -
	 * a slot that was active in some earlier segment (before write_buf_count
	 * was lowered) must not carry stale used/in_flight state into a much
	 * later segment where it's raised again. */
	for (int i = 0; i < MAX_WRITE_BUFFERS; i++) {
		ctx->buffers[i].used = 0;
		ctx->buffers[i].in_flight = false;
	}
	atomic_store_explicit(&ctx->record_count, 0, memory_order_relaxed);
	atomic_store_explicit(&ctx->dropped_count, 0, memory_order_relaxed);
	atomic_store_explicit(&ctx->first_capture_tsc, 0, memory_order_relaxed);
	atomic_store_explicit(&ctx->last_capture_tsc, 0, memory_order_relaxed);
	atomic_store_explicit(&ctx->last_stop_reason, CHRONO_STOP_NONE, memory_order_relaxed);
	ctx->consecutive_write_failures = 0;
	ctx->stopping = false;

	atomic_store_explicit(&ctx->current_segment_id, ctx->segment_id, memory_order_relaxed);
	/* recording=true takes over as the write-chunk/write-buffer-count
	 * busy-guard from here on - see claim_in_progress's comment
	 * (chrono_ctx.h) for why both are needed across this whole
	 * function's window, not just this one. */
	atomic_store_explicit(&ctx->claim_in_progress, false, memory_order_relaxed);
	atomic_store_explicit(&ctx->recording, true, memory_order_relaxed);

	/* rx_poller is already running (registered once at daemon startup -
	 * see daemon_bring_up_nic()); nothing to do here. */

	SPDK_NOTICELOG("Recording UDP port %u to bdev %s, segment %u\n",
		       ctx->opts.udp_port, ctx->opts.bdev_name, ctx->segment_id);

	chrono_admin_fulfill(&ctx->admin_req, 0);
}

static void
daemon_claim_toc_write_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct app_context_t *ctx = cb_arg;
	int rc;

	if (bdev_io != NULL)
		spdk_bdev_free_io(bdev_io);
	if (!success) {
		SPDK_ERRLOG("failed to claim a segment slot\n");
		atomic_store_explicit(&ctx->claim_in_progress, false, memory_order_relaxed);
		chrono_admin_fulfill(&ctx->admin_req, -EIO);
		return;
	}

	ctx->vol.next_segment_id++;
	memset(ctx->vol_buf, 0, ctx->block_size);
	*(struct chrono_volume_header *)ctx->vol_buf = ctx->vol;

	rc = spdk_bdev_write(ctx->bdev_desc, ctx->bdev_io_channel, ctx->vol_buf,
			      VOLUME_HEADER_BLOCK * ctx->block_size, ctx->block_size,
			      daemon_claim_header_write_complete, ctx);
	if (rc != 0) {
		SPDK_ERRLOG("%s recording segment claim in volume header\n", spdk_strerror(-rc));
		atomic_store_explicit(&ctx->claim_in_progress, false, memory_order_relaxed);
		chrono_admin_fulfill(&ctx->admin_req, rc);
	}
}

/* Called by admin_do_recording_start() (chrono_admin.c) once it's
 * confirmed the daemon isn't shutting down/already recording and applied
 * any per-session port/count_limit override. */
void
daemon_claim_segment_start(struct app_context_t *ctx)
{
	struct chrono_segment_entry *seg;
	struct timespec ts;
	int rc;

	if (ctx->vol.next_segment_id >= ctx->vol.toc_slot_count) {
		SPDK_ERRLOG("TOC full (%u/%u segments used) - re-init the device"
			    " (--init --force) to reclaim slots\n",
			    ctx->vol.next_segment_id, ctx->vol.toc_slot_count);
		chrono_admin_fulfill(&ctx->admin_req, -ENOSPC);
		return;
	}

	atomic_store_explicit(&ctx->claim_in_progress, true, memory_order_relaxed);

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
	seg->write_chunk_bytes = ctx->buf_size;
	seg->wall_clock_start_sec = ctx->segment_wall_start_sec;
	seg->wall_clock_start_nsec = ctx->segment_wall_start_nsec;

	rc = spdk_bdev_write(ctx->bdev_desc, ctx->bdev_io_channel, ctx->io_buf,
			      (ctx->vol.toc_start_block + ctx->segment_id) * ctx->block_size,
			      ctx->block_size, daemon_claim_toc_write_complete, ctx);
	if (rc != 0) {
		SPDK_ERRLOG("%s claiming segment %u\n", spdk_strerror(-rc), ctx->segment_id);
		atomic_store_explicit(&ctx->claim_in_progress, false, memory_order_relaxed);
		chrono_admin_fulfill(&ctx->admin_req, rc);
	}
}

/* ---- QUICK_FORMAT: web-triggered equivalent of CLI `--init --force` ----
 *
 * Mirrors init_zero_toc_chunk()/init_zero_toc_chunk_write_complete()/
 * init_write_header()/init_write_header_complete()'s shape exactly (same
 * zero-the-TOC-then-write-a-fresh-header sequence, fixed CHRONO_TOC_SLOT_COUNT
 * layout, same "a write failure here is just reported, not retried"
 * simplification - see init_zero_toc_chunk_write_complete()'s comment for
 * why that's fine for a rare, explicit, one-shot operation), but duplicated
 * rather than shared: every CLI path ends in fail_started()/
 * cleanup_and_stop(), which would tear down the whole daemon over a single
 * write hiccup. Builds the fresh header into ctx->qf_staged_vol rather
 * than ctx->vol directly, so a failure partway through never leaves the
 * live volume header (still backing reads/status while this runs) in a
 * half-formatted state - see chrono_ctx.h's comment on qf_staged_vol.
 * Idempotent on retry after a failure: it always re-derives the same fixed
 * layout from scratch. admin_do_quick_format() (chrono_admin.c) has
 * already refused this while ctx->recording is true.
 *
 * Named "quick" because it only resets the TOC/header (a fixed, small
 * amount of data - CHRONO_TOC_SLOT_COUNT blocks) - the actual segment data
 * blocks are never zeroed, just orphaned. A real full-disk zero-write is a
 * distinct, much slower operation this doesn't attempt. */

static void
daemon_quick_format_write_header_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct app_context_t *ctx = cb_arg;

	spdk_bdev_free_io(bdev_io);
	if (!success) {
		SPDK_ERRLOG("failed to write the formatted volume header\n");
		chrono_admin_fulfill(&ctx->admin_req, -EIO);
		return;
	}

	ctx->vol = ctx->qf_staged_vol;
	ctx->next_write_block = ctx->vol.data_start_block;
	atomic_store_explicit(&ctx->record_count, 0, memory_order_relaxed);
	atomic_store_explicit(&ctx->dropped_count, 0, memory_order_relaxed);
	atomic_store_explicit(&ctx->first_capture_tsc, 0, memory_order_relaxed);
	atomic_store_explicit(&ctx->last_capture_tsc, 0, memory_order_relaxed);
	atomic_store_explicit(&ctx->mirror_next_segment_id, ctx->vol.next_segment_id,
			       memory_order_relaxed);
	atomic_store_explicit(&ctx->mirror_next_data_block, ctx->vol.next_data_block,
			       memory_order_relaxed);

	SPDK_NOTICELOG("Quick-formatted chrontabulator volume on %s: %u segment slots reserved,"
		       " data starts at block %" PRIu64 "\n",
		       ctx->opts.bdev_name, ctx->vol.toc_slot_count, ctx->vol.data_start_block);
	chrono_admin_fulfill(&ctx->admin_req, 0);
}

static void
daemon_quick_format_write_header(struct app_context_t *ctx)
{
	int rc;

	memset(ctx->vol_buf, 0, ctx->block_size);
	*(struct chrono_volume_header *)ctx->vol_buf = ctx->qf_staged_vol;

	rc = spdk_bdev_write(ctx->bdev_desc, ctx->bdev_io_channel, ctx->vol_buf,
			      VOLUME_HEADER_BLOCK * ctx->block_size, ctx->block_size,
			      daemon_quick_format_write_header_complete, ctx);
	if (rc != 0) {
		SPDK_ERRLOG("%s writing the formatted volume header\n", spdk_strerror(-rc));
		chrono_admin_fulfill(&ctx->admin_req, rc);
	}
}

static void
daemon_quick_format_zero_toc_chunk(struct app_context_t *ctx);

static void
daemon_quick_format_zero_toc_chunk_write_complete(struct spdk_bdev_io *bdev_io, bool success,
						   void *cb_arg)
{
	struct app_context_t *ctx = cb_arg;
	uint64_t blocks_left, chunk_blocks;

	spdk_bdev_free_io(bdev_io);
	if (!success) {
		SPDK_ERRLOG("failed zeroing the TOC region at block %" PRIu64 "\n",
			    ctx->init_cur_block);
		chrono_admin_fulfill(&ctx->admin_req, -EIO);
		return;
	}

	blocks_left = ctx->qf_staged_vol.data_start_block - ctx->init_cur_block;
	chunk_blocks = blocks_left < ctx->buf_size_blocks ? blocks_left : ctx->buf_size_blocks;
	ctx->init_cur_block += chunk_blocks;

	daemon_quick_format_zero_toc_chunk(ctx);
}

static void
daemon_quick_format_zero_toc_chunk(struct app_context_t *ctx)
{
	uint64_t blocks_left, chunk_blocks;
	uint32_t chunk_bytes;
	int rc;

	if (ctx->init_cur_block >= ctx->qf_staged_vol.data_start_block) {
		daemon_quick_format_write_header(ctx);
		return;
	}

	blocks_left = ctx->qf_staged_vol.data_start_block - ctx->init_cur_block;
	chunk_blocks = blocks_left < ctx->buf_size_blocks ? blocks_left : ctx->buf_size_blocks;
	chunk_bytes = (uint32_t)(chunk_blocks * ctx->block_size);

	/* Unlike the CLI init path's io_buf (freshly spdk_dma_zmalloc()'d and
	 * never written to before init runs), the daemon's ctx->io_buf is
	 * shared with SEGMENTS_LIST/SEGMENT_RECORDS reads and claim/finalize's
	 * TOC entry writes - it can hold anything by the time a format runs,
	 * so it has to be zeroed explicitly before reuse as a zero-fill
	 * source. */
	memset(ctx->io_buf, 0, chunk_bytes);
	rc = spdk_bdev_write(ctx->bdev_desc, ctx->bdev_io_channel, ctx->io_buf,
			      ctx->init_cur_block * ctx->block_size, chunk_bytes,
			      daemon_quick_format_zero_toc_chunk_write_complete, ctx);
	if (rc != 0) {
		SPDK_ERRLOG("%s zeroing the TOC region at block %" PRIu64 "\n",
			    spdk_strerror(-rc), ctx->init_cur_block);
		chrono_admin_fulfill(&ctx->admin_req, rc);
	}
}

void
daemon_quick_format_start(struct app_context_t *ctx)
{
	struct timespec ts;

	SPDK_NOTICELOG("Quick-formatting chrontabulator volume on %s...\n", ctx->opts.bdev_name);

	memset(&ctx->qf_staged_vol, 0, sizeof(ctx->qf_staged_vol));
	ctx->qf_staged_vol.magic = CHRONO_VOLUME_MAGIC;
	ctx->qf_staged_vol.version = CHRONO_FORMAT_VERSION;
	ctx->qf_staged_vol.block_size = ctx->block_size;
	ctx->qf_staged_vol.toc_slot_count = CHRONO_TOC_SLOT_COUNT;
	ctx->qf_staged_vol.next_segment_id = 0;
	ctx->qf_staged_vol.toc_start_block = VOLUME_HEADER_BLOCK + 1;
	ctx->qf_staged_vol.data_start_block = ctx->qf_staged_vol.toc_start_block +
					       CHRONO_TOC_SLOT_COUNT;
	ctx->qf_staged_vol.next_data_block = ctx->qf_staged_vol.data_start_block;
	clock_gettime(CLOCK_REALTIME, &ts);
	ctx->qf_staged_vol.init_wall_clock_sec = (uint64_t)ts.tv_sec;

	ctx->init_cur_block = ctx->qf_staged_vol.toc_start_block;
	daemon_quick_format_zero_toc_chunk(ctx);
}

/* ---- SET_WRITE_BUFFERS / SET_WRITE_CHUNK: live tuning, see
 * MAX_WRITE_BUFFERS's comment in chrono_ctx.h. Both synchronous - every
 * buffer is already allocated at MAX_WRITE_CHUNK_BYTES, so there's no bdev
 * I/O or DMA (re)allocation here, just a validated field write.
 * admin_do_write_buffers()/admin_do_write_chunk() (chrono_admin.c) have
 * already refused these while ctx->recording is true. */

void
daemon_set_write_buf_count(struct app_context_t *ctx, uint32_t count)
{
	if (count < 1 || count > MAX_WRITE_BUFFERS) {
		chrono_admin_fulfill(&ctx->admin_req, -EINVAL);
		return;
	}
	ctx->write_buf_count = count;
	SPDK_NOTICELOG("write_buf_count set to %u\n", count);
	chrono_admin_fulfill(&ctx->admin_req, 0);
}

void
daemon_set_write_chunk_bytes(struct app_context_t *ctx, uint32_t bytes)
{
	if (bytes < MIN_WRITE_CHUNK_BYTES || bytes > MAX_WRITE_CHUNK_BYTES) {
		chrono_admin_fulfill(&ctx->admin_req, -EINVAL);
		return;
	}
	ctx->buf_size = chrono_round_write_chunk(ctx, bytes);
	ctx->buf_size_blocks = ctx->buf_size / ctx->block_size;
	SPDK_NOTICELOG("write chunk size set to %u bytes\n", ctx->buf_size);
	chrono_admin_fulfill(&ctx->admin_req, 0);
}

void
daemon_set_wire_has_seq(struct app_context_t *ctx, bool wire_has_seq)
{
	ctx->wire_has_seq = wire_has_seq;
	SPDK_NOTICELOG("wire_has_seq set to %s\n", wire_has_seq ? "true" : "false");
	chrono_admin_fulfill(&ctx->admin_req, 0);
}

void
daemon_set_local_ip(struct app_context_t *ctx, const uint8_t ip[4], bool have_ip)
{
	if (have_ip) {
		memcpy(ctx->opts.local_ip, ip, 4);
		ctx->opts.have_local_ip = true;
		SPDK_NOTICELOG("local_ip set to %u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);
	} else {
		ctx->opts.have_local_ip = false;
		SPDK_NOTICELOG("local_ip cleared - no longer answering ARP/ICMP-echo\n");
	}
	chrono_admin_fulfill(&ctx->admin_req, 0);
}

/* Sets shutting_down (and, transitively via the web thread's own poll of
 * it, the web server's quit flag) as the very first action, before any
 * bdev/segment teardown - see the shutdown-safety design in the
 * project's plan for why this ordering matters. */
static void
daemon_shutdown_cb(void)
{
	struct app_context_t *ctx = &g_ctx;

	atomic_store_explicit(&ctx->shutting_down, true, memory_order_relaxed);

	if (atomic_load_explicit(&ctx->recording, memory_order_relaxed))
		daemon_stop_recording(ctx);
	else
		daemon_teardown_and_exit(ctx);
}

/* Returns 0 on success, -1 on failure (fail_started() already called and
 * the whole process already tearing down - caller must not proceed). */
static int
daemon_bring_up_nic(struct app_context_t *ctx)
{
	if (rte_eth_dev_count_avail() != 1) {
		SPDK_ERRLOG("Expected exactly 1 available DPDK port, found %u\n",
			    rte_eth_dev_count_avail());
		fail_started(ctx);
		return -1;
	}
	RTE_ETH_FOREACH_DEV(ctx->port)
		break;

	ctx->mbuf_socket_id = rte_socket_id();
	ctx->mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0,
						  MBUF_DATA_SIZE, ctx->mbuf_socket_id);
	if (ctx->mbuf_pool == NULL) {
		SPDK_ERRLOG("Cannot create mbuf pool: %s\n", rte_strerror(rte_errno));
		fail_started(ctx);
		return -1;
	}

	struct rte_ether_addr mac_addr;
	int rc = chrono_port_init(ctx->port, ctx->mbuf_pool, ctx->opts.mtu, ctx->opts.force_10g,
				   &mac_addr);
	if (rc != 0) {
		SPDK_ERRLOG("Failed to initialize port %u\n", ctx->port);
		fail_started(ctx);
		return -1;
	}
	ctx->nic_up = true;
	rte_ether_addr_copy(&mac_addr, &ctx->local_mac);

	/* Registered once, here, and left running for the daemon's whole
	 * life (never unregistered on recording stop/start - only at actual
	 * daemon teardown) - net_responder_try_handle() needs this poller
	 * alive to answer ARP/ping even while idle, not just mid-recording.
	 * capture_poll() itself gates the NVMe-write half of its work behind
	 * ctx->recording; the responder half always runs. */
	ctx->rx_poller = spdk_poller_register(capture_poll, ctx, 0);
	return 0;
}

/* Everything here (unlike daemon_bring_up_nic() above) genuinely needs
 * ctx->vol already populated - the mirror atomics and the log line read
 * it directly, and web_status_start() hands ctx to a new pthread that
 * reads ctx->vol.data_start_block/toc_slot_count without any lock
 * ("write-before-thread-creation" - see chrono_ctx.h's start_time comment).
 * That safety property only holds if every plain-field write to ctx->vol
 * happens before this call - so this must stay sequenced after the volume
 * header read completes, even though NIC bring-up itself no longer is. */
static void
daemon_finish_startup(struct app_context_t *ctx)
{
	uint32_t buf_align = spdk_bdev_get_buf_align(ctx->bdev);
	/* Every slot allocated at MAX_WRITE_CHUNK_BYTES up front, regardless
	 * of the active ctx->buf_size - see MAX_WRITE_BUFFERS's comment in
	 * chrono_ctx.h for why. */
	for (int i = 0; i < MAX_WRITE_BUFFERS; i++) {
		ctx->buffers[i].data = spdk_dma_zmalloc(MAX_WRITE_CHUNK_BYTES, buf_align, NULL);
		if (!ctx->buffers[i].data) {
			SPDK_ERRLOG("Failed to allocate write buffer %d\n", i);
			fail_started(ctx);
			return;
		}
	}

	if (chrono_admin_init(ctx) != 0) {
		SPDK_ERRLOG("Failed to initialize the admin bridge\n");
		fail_started(ctx);
		return;
	}
	ctx->app_thread = spdk_get_thread();
	ctx->start_time = time(NULL);
	atomic_store_explicit(&ctx->current_segment_id, CHRONO_NO_SEGMENT, memory_order_relaxed);
	atomic_store_explicit(&ctx->mirror_next_segment_id, ctx->vol.next_segment_id,
			       memory_order_relaxed);
	atomic_store_explicit(&ctx->mirror_next_data_block, ctx->vol.next_data_block,
			       memory_order_relaxed);
	ctx->cached_num_blocks = spdk_bdev_get_num_blocks(ctx->bdev);

	/* Everything above this point must be written before the web
	 * thread is created below - pthread_create() is itself a
	 * synchronization point, so no atomics are needed for the plain
	 * fields it just set (app_thread, start_time, cached_num_blocks,
	 * ctx->vol.*) to be safely visible on that thread from here on. */
	if (ctx->opts.web_port != 0) {
		if (web_status_start(ctx->opts.web_port, ctx) != 0) {
			SPDK_ERRLOG("Failed to start the web server on port %u\n",
				    ctx->opts.web_port);
			fail_started(ctx);
			return;
		}
		SPDK_NOTICELOG("Web UI listening on port %u\n", ctx->opts.web_port);
	}

	SPDK_NOTICELOG("Daemon ready: bdev %s, port %u, %u/%u segments already recorded\n",
		       ctx->opts.bdev_name, ctx->port, ctx->vol.next_segment_id,
		       ctx->vol.toc_slot_count);
}

static void
daemon_volume_header_read_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
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

	daemon_finish_startup(ctx);
}

static void
daemon_start(struct app_context_t *ctx)
{
	int rc;

	/* NIC bring-up runs first, directly here - not chained behind the
	 * volume header read's completion callback below. Two reasons: (1)
	 * it has no actual dependency on the volume header's contents, so
	 * ARP/ping/the web UI shouldn't be held hostage by an unrelated disk
	 * read (or fail outright if that read fails - see daemon_finish_startup()'s
	 * comment for what DOES still need to wait); (2) it rules out any
	 * possibility that calling rte_eth_dev_start() et al. from inside an
	 * SPDK bdev-completion callback, rather than a plain top-level call,
	 * matters for this PMD's own interrupt-thread setup - unlikely, since
	 * both run on the same reactor OS thread either way, but this PMD has
	 * shown real interrupt-thread fragility elsewhere this project (see
	 * the atlantic segfault findings in project memory), so it costs
	 * nothing to remove the variable rather than argue it away. */
	if (daemon_bring_up_nic(ctx) != 0)
		return;

	rc = spdk_bdev_read(ctx->bdev_desc, ctx->bdev_io_channel, ctx->vol_buf,
			     VOLUME_HEADER_BLOCK * ctx->block_size, ctx->block_size,
			     daemon_volume_header_read_complete, ctx);
	if (rc != 0) {
		SPDK_ERRLOG("%s reading the volume header\n", spdk_strerror(-rc));
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
	if (!ctx->opts.dump_mode && !ctx->opts.init_mode && !ctx->opts.serve_mode &&
	    ctx->opts.udp_port == 0) {
		SPDK_ERRLOG("-P <port> is required unless -D, --init, or --serve is given\n");
		spdk_app_stop(-1);
		return;
	}
	if ((ctx->opts.init_mode && ctx->opts.dump_mode) ||
	    (ctx->opts.init_mode && ctx->opts.serve_mode) ||
	    (ctx->opts.dump_mode && ctx->opts.serve_mode)) {
		SPDK_ERRLOG("--init, -D, and --serve can't be used together\n");
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
	ctx->write_unit_bytes = ctx->block_size * spdk_bdev_get_write_unit_size(ctx->bdev);
	ctx->write_buf_count = ctx->opts.write_buf_count;
	ctx->buf_size = chrono_round_write_chunk(ctx, ctx->opts.write_chunk_bytes);
	ctx->buf_size_blocks = ctx->buf_size / ctx->block_size;
	ctx->wire_has_seq = ctx->opts.wire_has_seq;

	buf_align = spdk_bdev_get_buf_align(ctx->bdev);
	ctx->vol_buf = spdk_dma_zmalloc(ctx->block_size, buf_align, NULL);
	if (!ctx->vol_buf) {
		SPDK_ERRLOG("Failed to allocate volume header buffer\n");
		fail_started(ctx);
		return;
	}
	/* MAX_WRITE_CHUNK_BYTES, not ctx->buf_size: io_buf is shared by every
	 * read/write that uses "the current chunk size" as its length -
	 * quick-format's zero-fill, and (via the segment's own stored
	 * write_chunk_bytes - see chrono_segment_entry) dump/list's per-
	 * segment record reads. buf_size can grow at runtime (live tuning,
	 * gated to !recording - see MAX_WRITE_BUFFERS's comment in
	 * chrono_ctx.h), and io_buf is allocated once here, before any of
	 * that can happen - sizing it to ctx->buf_size's startup value would
	 * leave every later, larger read/write past that point writing off
	 * the end of this allocation. */
	ctx->io_buf = spdk_dma_zmalloc(MAX_WRITE_CHUNK_BYTES, buf_align, NULL);
	if (!ctx->io_buf) {
		SPDK_ERRLOG("Failed to allocate I/O buffer\n");
		fail_started(ctx);
		return;
	}

	if (ctx->opts.init_mode) {
		init_start(ctx);
		return;
	}
	if (ctx->opts.serve_mode) {
		daemon_start(ctx);
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
	g_ctx.opts.web_port = 8080; /* --web-port=0 (explicitly passed) is what
				     * means headless - see app_parse_arg(). */
	g_ctx.opts.write_buf_count = DEFAULT_WRITE_BUFFERS;
	g_ctx.opts.write_chunk_bytes = WRITE_CHUNK_TARGET;
	g_ctx.opts.wire_has_seq = true;

	spdk_app_opts_init(&opts, sizeof(opts));
	opts.name = "chrontabulator";

	rc = spdk_app_parse_args(argc, argv, &opts, "b:P:M:I:FC:DS:", chrono_long_opts,
				  app_parse_arg, app_usage);
	if (rc != SPDK_APP_PARSE_ARGS_SUCCESS)
		exit(rc);

	opts.shutdown_cb = g_ctx.opts.serve_mode ? daemon_shutdown_cb : app_shutdown_cb;

	rc = spdk_app_start(&opts, app_started, &g_ctx);
	if (rc)
		SPDK_ERRLOG("ERROR starting application\n");

	/* Must run after spdk_app_start() returns (the reactor OS thread is
	 * done by then) and before spdk_app_fini() - never from inside a
	 * reactor callback, since the web thread's accept loop may be
	 * blocked in a bridged admin call that only the reactor thread can
	 * complete. See web_status.h. */
	if (g_ctx.opts.serve_mode)
		web_status_stop();

	spdk_app_fini();
	return rc;
}
