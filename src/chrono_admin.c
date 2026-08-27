#include "chrono_ctx.h"
#include "chrono_admin.h"

#include "spdk/bdev.h"
#include "spdk/thread.h"
#include "spdk/log.h"
#include "spdk/string.h"

#include <errno.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <inttypes.h>

#define CHRONO_ADMIN_RESP_BUF_CAP (1024 * 1024)
#define CHRONO_RECORDS_LIMIT_MAX 2000
#define CHRONO_RECORDS_LIMIT_DEFAULT 500

enum chrono_segment_view
chrono_segment_classify(const struct chrono_segment_entry *seg)
{
	if (seg->magic != CHRONO_SEGMENT_MAGIC || seg->state == CHRONO_SEGMENT_FREE)
		return CHRONO_SEG_VIEW_NOT_FOUND;
	switch (seg->state) {
	case CHRONO_SEGMENT_FINALIZED:
		return CHRONO_SEG_VIEW_FINALIZED;
	case CHRONO_SEGMENT_DELETED:
		return CHRONO_SEG_VIEW_DELETED;
	case CHRONO_SEGMENT_OPEN:
	default:
		return CHRONO_SEG_VIEW_OPEN;
	}
}

static void
format_iso8601(uint64_t wall_clock_sec, char *out, size_t out_size)
{
	time_t t = (time_t)wall_clock_sec;
	struct tm tm_buf;

	out[0] = '\0';
	if (gmtime_r(&t, &tm_buf) != NULL)
		strftime(out, out_size, "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
}

static void
admin_buf_appendf(struct chrono_admin_request *req, const char *fmt, ...)
{
	va_list ap;
	int n;
	size_t remaining;

	if (req->resp_len >= req->resp_buf_cap)
		return;
	remaining = req->resp_buf_cap - req->resp_len;
	va_start(ap, fmt);
	n = vsnprintf(req->resp_buf + req->resp_len, remaining, fmt, ap);
	va_end(ap);
	if (n > 0)
		req->resp_len += (size_t)n < remaining ? (size_t)n : remaining;
}

/* Hex-encodes raw bytes directly into resp_buf - admin_buf_appendf()'s
 * printf-based approach can't safely carry arbitrary binary (not
 * null-terminated, may contain embedded NULs). Truncates rather than
 * overflowing resp_buf if there's not enough room, same fail-safe
 * philosophy as admin_buf_appendf() silently no-op'ing once resp_buf_cap
 * is reached. */
static void
admin_buf_append_hex(struct chrono_admin_request *req, const uint8_t *data, uint32_t len)
{
	static const char hexdigits[] = "0123456789abcdef";

	if (req->resp_len >= req->resp_buf_cap)
		return;
	size_t remaining = req->resp_buf_cap - req->resp_len;
	if ((size_t)len * 2 > remaining)
		len = (uint32_t)(remaining / 2);

	char *out = req->resp_buf + req->resp_len;
	for (uint32_t i = 0; i < len; i++) {
		out[i * 2] = hexdigits[data[i] >> 4];
		out[i * 2 + 1] = hexdigits[data[i] & 0xF];
	}
	req->resp_len += (size_t)len * 2;
}

int
chrono_admin_init(struct app_context_t *ctx)
{
	struct chrono_admin_request *req = &ctx->admin_req;

	memset(req, 0, sizeof(*req));
	if (pthread_mutex_init(&req->lock, NULL) != 0)
		return -1;
	if (pthread_cond_init(&req->cond, NULL) != 0) {
		pthread_mutex_destroy(&req->lock);
		return -1;
	}
	req->resp_buf_cap = CHRONO_ADMIN_RESP_BUF_CAP;
	req->resp_buf = malloc(req->resp_buf_cap);
	if (!req->resp_buf) {
		pthread_mutex_destroy(&req->lock);
		pthread_cond_destroy(&req->cond);
		return -1;
	}
	return 0;
}

void
chrono_admin_fulfill(struct chrono_admin_request *req, int rc)
{
	pthread_mutex_lock(&req->lock);
	req->rc = rc;
	if (req->abandoned) {
		/* Nobody's waiting anymore - just free up the slot for the
		 * next call. resp_buf may already be mid-reuse by then, so
		 * don't touch resp_len/resp_buf here. */
		req->busy = false;
		pthread_mutex_unlock(&req->lock);
		return;
	}
	req->done = true;
	pthread_cond_signal(&req->cond);
	pthread_mutex_unlock(&req->lock);
}

int
chrono_admin_call(struct app_context_t *ctx, struct chrono_admin_request *req, int timeout_sec)
{
	struct timespec deadline;
	int wait_rc = 0;

	pthread_mutex_lock(&req->lock);
	if (req->busy) {
		/* Shouldn't happen given the server's serial accept loop,
		 * but refuse cleanly rather than corrupt the in-flight
		 * request's state if it ever does. */
		pthread_mutex_unlock(&req->lock);
		return -EBUSY;
	}
	req->busy = true;
	req->done = false;
	req->abandoned = false;
	req->resp_len = 0;
	pthread_mutex_unlock(&req->lock);

	spdk_thread_send_msg(ctx->app_thread, chrono_admin_dispatch, ctx);

	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += timeout_sec;

	pthread_mutex_lock(&req->lock);
	while (!req->done && wait_rc == 0)
		wait_rc = pthread_cond_timedwait(&req->cond, &req->lock, &deadline);
	if (!req->done) {
		req->abandoned = true;
		pthread_mutex_unlock(&req->lock);
		return -ETIMEDOUT;
	}
	req->busy = false;
	pthread_mutex_unlock(&req->lock);
	return 0;
}

/* ---- SEGMENTS_LIST: scan the TOC one block at a time, JSON per entry ---- */

static void
admin_list_read_next_chunk(struct app_context_t *ctx);

static void
admin_list_chunk_read_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct app_context_t *ctx = cb_arg;
	struct chrono_admin_request *req = &ctx->admin_req;
	struct chrono_segment_entry *seg = (struct chrono_segment_entry *)ctx->io_buf;
	enum chrono_segment_view view;

	spdk_bdev_free_io(bdev_io);
	if (!success) {
		chrono_admin_fulfill(req, -EIO);
		return;
	}

	view = chrono_segment_classify(seg);
	if (view != CHRONO_SEG_VIEW_NOT_FOUND &&
	    (view != CHRONO_SEG_VIEW_DELETED || req->req_include_deleted)) {
		bool first = req->resp_len > 0 &&
			req->resp_buf[req->resp_len - 1] == '[';

		if (view == CHRONO_SEG_VIEW_FINALIZED || view == CHRONO_SEG_VIEW_DELETED) {
			char start_str[32], end_str[32];
			double duration = seg->tsc_hz != 0 ?
				(double)(seg->last_capture_tsc - seg->first_capture_tsc) /
				seg->tsc_hz : 0.0;

			format_iso8601(seg->wall_clock_start_sec, start_str, sizeof(start_str));
			format_iso8601(seg->wall_clock_end_sec, end_str, sizeof(end_str));
			admin_buf_appendf(req,
				"%s{\"segment_id\":%u,\"state\":\"%s\",\"start_block\":%"
				PRIu64 ",\"block_count\":%" PRIu64 ",\"record_count\":%"
				PRIu64 ",\"dropped_count\":%" PRIu64
				",\"wall_clock_start\":\"%s\",\"wall_clock_end\":\"%s\""
				",\"duration_sec\":%.3f}",
				first ? "" : ",", seg->segment_id,
				view == CHRONO_SEG_VIEW_DELETED ? "deleted" : "finalized",
				seg->start_block, seg->block_count, seg->record_count,
				seg->dropped_count, start_str, end_str, duration);
		} else {
			admin_buf_appendf(req,
				"%s{\"segment_id\":%u,\"state\":\"open\",\"start_block\":%"
				PRIu64 "}", first ? "" : ",", seg->segment_id, seg->start_block);
		}
		/* Reused for "entries actually included" here, same as its
		 * SEGMENT_RECORDS use - the two never run concurrently
		 * (single admin_req slot). Must count only what's actually
		 * appended: dump_target_count is the total TOC slots ever
		 * claimed, which overcounts once a deleted entry gets
		 * filtered out of the response. */
		req->scan_collected++;
	}

	ctx->dump_records_seen++;
	ctx->dump_cur_block++;
	admin_list_read_next_chunk(ctx);
}

static void
admin_list_read_next_chunk(struct app_context_t *ctx)
{
	struct chrono_admin_request *req = &ctx->admin_req;
	int rc;

	if (ctx->dump_records_seen >= ctx->dump_target_count) {
		admin_buf_appendf(req, "],\"count\":%" PRIu64 "}", req->scan_collected);
		chrono_admin_fulfill(req, 0);
		return;
	}

	rc = spdk_bdev_read(ctx->bdev_desc, ctx->bdev_io_channel, ctx->io_buf,
			     ctx->dump_cur_block * ctx->block_size, ctx->block_size,
			     admin_list_chunk_read_complete, ctx);
	if (rc != 0)
		chrono_admin_fulfill(req, rc);
}

static void
admin_do_segments_list(struct app_context_t *ctx, struct chrono_admin_request *req)
{
	admin_buf_appendf(req, "{\"segments\":[");
	ctx->dump_cur_block = ctx->vol.toc_start_block;
	ctx->dump_records_seen = 0;
	ctx->dump_target_count = ctx->vol.next_segment_id;
	req->scan_collected = 0;

	if (ctx->dump_target_count == 0) {
		admin_buf_appendf(req, "],\"count\":0}");
		chrono_admin_fulfill(req, 0);
		return;
	}
	admin_list_read_next_chunk(ctx);
}

/* ---- SEGMENT_RECORDS: one segment's TOC entry, then a paginated walk of
 * its record data ---- */

static void
admin_records_read_next_chunk(struct app_context_t *ctx);

static void
admin_records_chunk_read_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct app_context_t *ctx = cb_arg;
	struct chrono_admin_request *req = &ctx->admin_req;
	uint32_t off = 0;

	spdk_bdev_free_io(bdev_io);
	if (!success) {
		SPDK_ERRLOG("segment %u records read failed at block %" PRIu64 "\n",
			    ctx->segment_id, ctx->dump_cur_block);
		chrono_admin_fulfill(req, -EIO);
		return;
	}

	while (off + sizeof(struct chrono_record_hdr) <= ctx->dump_write_chunk_bytes &&
	       ctx->dump_records_seen < ctx->dump_target_count &&
	       req->scan_collected < req->req_limit) {
		struct chrono_record_hdr *hdr = (struct chrono_record_hdr *)(ctx->io_buf + off);

		if (hdr->magic != CHRONO_RECORD_MAGIC) {
			/* Padding at the tail of THIS chunk - same as the
			 * CLI's dump_chunk_read_complete() - just stop
			 * parsing it and let admin_records_read_next_chunk()
			 * below decide whether to advance to the next one.
			 * NOT the end of the whole segment: every chunk
			 * boundary looks like this whenever the write chunk
			 * size isn't an exact multiple of the record size,
			 * not just the segment's actual last chunk - this
			 * used to unconditionally treat any padding as "done"
			 * (ctx->dump_records_seen = ctx->dump_target_count),
			 * which silently returned empty/incomplete results
			 * for any offset past the first chunk's worth of
			 * records - never noticed until payloads large enough
			 * to fit only a few dozen records per chunk made it
			 * trivial to hit on offset 40+. */
			break;
		}
		if (off + sizeof(*hdr) + hdr->len > ctx->dump_write_chunk_bytes) {
			SPDK_ERRLOG("segment %u: record at chunk block %" PRIu64 " off %u claims"
				    " len %u, overruns chunk_bytes=%u (dump_records_seen=%"
				    PRIu64 ")\n",
				    ctx->segment_id, ctx->dump_cur_block, off, hdr->len,
				    ctx->dump_write_chunk_bytes, ctx->dump_records_seen);
			chrono_admin_fulfill(req, -EIO);
			return;
		}

		if (ctx->dump_records_seen >= req->req_offset) {
			bool first = req->scan_collected == 0;
			double rel_sec = ctx->dump_tsc_hz != 0 ?
				(double)(hdr->capture_tsc - ctx->dump_first_capture_tsc) /
				ctx->dump_tsc_hz : 0.0;

			admin_buf_appendf(req,
				"%s{\"seq\":%" PRIu64 ",\"capture_tsc\":%" PRIu64
				",\"rel_sec\":%.6f,\"len\":%u",
				first ? "" : ",", hdr->seq, hdr->capture_tsc, rel_sec, hdr->len);
			/* Only for a single-record fetch (req_limit == 1) - a
			 * bulk listing hex-encoding every record's payload
			 * could easily exceed resp_buf_cap (1MB) well before
			 * CHRONO_RECORDS_LIMIT_MAX records are collected. */
			if (req->req_limit == 1) {
				admin_buf_appendf(req, ",\"payload_hex\":\"");
				admin_buf_append_hex(req, (const uint8_t *)hdr + sizeof(*hdr),
						      hdr->len);
				admin_buf_appendf(req, "\"");
			}
			admin_buf_appendf(req, "}");
			req->scan_collected++;
		}

		off += (uint32_t)sizeof(*hdr) + hdr->len;
		ctx->dump_records_seen++;
	}

	/* Mirrors the CLI's dump_chunk_read_complete() offset==0 check: hit
	 * padding immediately, at the very start of a fresh chunk, before
	 * the TOC entry's own record count was satisfied - genuinely out of
	 * real data on disk, not just this chunk's own tail padding. */
	if (off == 0 && ctx->dump_records_seen < ctx->dump_target_count &&
	    req->scan_collected < req->req_limit) {
		SPDK_ERRLOG("segment %u: expected %" PRIu64 " records, only found %" PRIu64
			    " before hitting unwritten space\n",
			    ctx->segment_id, ctx->dump_target_count, ctx->dump_records_seen);
		chrono_admin_fulfill(req, -EIO);
		return;
	}

	admin_records_read_next_chunk(ctx);
}

static void
admin_records_read_next_chunk(struct app_context_t *ctx)
{
	struct chrono_admin_request *req = &ctx->admin_req;
	int rc;
	bool has_more;

	if (ctx->dump_records_seen >= ctx->dump_target_count || req->scan_collected >= req->req_limit) {
		has_more = ctx->dump_records_seen < ctx->dump_target_count;
		admin_buf_appendf(req,
			"],\"total_records\":%" PRIu64 ",\"offset\":%" PRIu64
			",\"limit\":%u,\"returned\":%" PRIu64 ",\"has_more\":%s}",
			ctx->dump_target_count, req->req_offset, req->req_limit,
			req->scan_collected, has_more ? "true" : "false");
		chrono_admin_fulfill(req, 0);
		return;
	}

	rc = spdk_bdev_read(ctx->bdev_desc, ctx->bdev_io_channel, ctx->io_buf,
			     ctx->dump_cur_block * ctx->block_size, ctx->dump_write_chunk_bytes,
			     admin_records_chunk_read_complete, ctx);
	if (rc != 0) {
		SPDK_ERRLOG("segment %u: %s reading block %" PRIu64 " (chunk_bytes=%u,"
			    " dump_records_seen=%" PRIu64 ")\n",
			    ctx->segment_id, spdk_strerror(-rc), ctx->dump_cur_block,
			    ctx->dump_write_chunk_bytes, ctx->dump_records_seen);
		chrono_admin_fulfill(req, rc);
		return;
	}
	ctx->dump_cur_block += ctx->dump_write_chunk_blocks;
}

static void
admin_records_entry_read_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct app_context_t *ctx = cb_arg;
	struct chrono_admin_request *req = &ctx->admin_req;
	struct chrono_segment_entry *seg = (struct chrono_segment_entry *)ctx->io_buf;
	enum chrono_segment_view view;

	spdk_bdev_free_io(bdev_io);
	if (!success) {
		chrono_admin_fulfill(req, -EIO);
		return;
	}

	view = chrono_segment_classify(seg);
	if (view == CHRONO_SEG_VIEW_NOT_FOUND) {
		chrono_admin_fulfill(req, -ENOENT);
		return;
	}
	if (view == CHRONO_SEG_VIEW_OPEN) {
		chrono_admin_fulfill(req, -EAGAIN); /* "never finalized, nothing to dump" */
		return;
	}

	if (req->req_limit == 0 || req->req_limit > CHRONO_RECORDS_LIMIT_MAX)
		req->req_limit = CHRONO_RECORDS_LIMIT_DEFAULT;

	admin_buf_appendf(req, "{\"segment_id\":%u,\"records\":[", seg->segment_id);
	ctx->dump_target_count = seg->record_count;
	ctx->dump_first_capture_tsc = seg->first_capture_tsc;
	ctx->dump_tsc_hz = seg->tsc_hz;
	ctx->dump_cur_block = seg->start_block;
	ctx->dump_records_seen = 0;
	req->scan_collected = 0;
	/* 0 means this segment predates write_chunk_bytes being recorded -
	 * fall back to this process's own buf_size, the old implicit
	 * assumption. See record.h's chrono_segment_entry.write_chunk_bytes
	 * and main.c's dump_segment_entry_read_complete() for why a reader
	 * can't just use its own current ctx->buf_size here. */
	ctx->dump_write_chunk_bytes = seg->write_chunk_bytes != 0 ?
		seg->write_chunk_bytes : ctx->buf_size;
	ctx->dump_write_chunk_blocks = ctx->dump_write_chunk_bytes / ctx->block_size;

	if (ctx->dump_target_count == 0 || req->req_offset >= ctx->dump_target_count) {
		admin_buf_appendf(req,
			"],\"total_records\":%" PRIu64 ",\"offset\":%" PRIu64
			",\"limit\":%u,\"returned\":0,\"has_more\":false}",
			ctx->dump_target_count, req->req_offset, req->req_limit);
		chrono_admin_fulfill(req, 0);
		return;
	}

	admin_records_read_next_chunk(ctx);
}

static void
admin_do_segment_records(struct app_context_t *ctx, struct chrono_admin_request *req)
{
	int rc;

	rc = spdk_bdev_read(ctx->bdev_desc, ctx->bdev_io_channel, ctx->io_buf,
			     (ctx->vol.toc_start_block + req->req_segment_id) * ctx->block_size,
			     ctx->block_size, admin_records_entry_read_complete, ctx);
	if (rc != 0)
		chrono_admin_fulfill(req, rc);
}

/* ---- SEGMENT_DELETE: read-modify-write the one TOC entry ---- */

static void
admin_delete_write_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct app_context_t *ctx = cb_arg;
	struct chrono_admin_request *req = &ctx->admin_req;

	spdk_bdev_free_io(bdev_io);
	chrono_admin_fulfill(req, success ? 0 : -EIO);
}

static void
admin_delete_read_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct app_context_t *ctx = cb_arg;
	struct chrono_admin_request *req = &ctx->admin_req;
	struct chrono_segment_entry *seg = (struct chrono_segment_entry *)ctx->io_buf;
	enum chrono_segment_view view;
	int rc;

	spdk_bdev_free_io(bdev_io);
	if (!success) {
		chrono_admin_fulfill(req, -EIO);
		return;
	}

	view = chrono_segment_classify(seg);
	if (view == CHRONO_SEG_VIEW_NOT_FOUND) {
		chrono_admin_fulfill(req, -ENOENT);
		return;
	}
	if (view == CHRONO_SEG_VIEW_DELETED) {
		chrono_admin_fulfill(req, 0); /* idempotent */
		return;
	}

	seg->state = CHRONO_SEGMENT_DELETED;
	rc = spdk_bdev_write(ctx->bdev_desc, ctx->bdev_io_channel, ctx->io_buf,
			      (ctx->vol.toc_start_block + req->req_segment_id) * ctx->block_size,
			      ctx->block_size, admin_delete_write_complete, ctx);
	if (rc != 0)
		chrono_admin_fulfill(req, rc);
}

static void
admin_do_segment_delete(struct app_context_t *ctx, struct chrono_admin_request *req)
{
	int rc;

	if (atomic_load(&ctx->recording) &&
	    req->req_segment_id == atomic_load(&ctx->current_segment_id)) {
		chrono_admin_fulfill(req, -EBUSY);
		return;
	}

	rc = spdk_bdev_read(ctx->bdev_desc, ctx->bdev_io_channel, ctx->io_buf,
			     (ctx->vol.toc_start_block + req->req_segment_id) * ctx->block_size,
			     ctx->block_size, admin_delete_read_complete, ctx);
	if (rc != 0)
		chrono_admin_fulfill(req, rc);
}

/* ---- RECORDING_START / RECORDING_STOP: delegate to main.c's daemon
 * claim/finalize chains, which call chrono_admin_fulfill() themselves at
 * their terminal step. ---- */

static void
admin_do_recording_start(struct app_context_t *ctx, struct chrono_admin_request *req)
{
	if (atomic_load(&ctx->shutting_down)) {
		chrono_admin_fulfill(req, -ESHUTDOWN);
		return;
	}
	if (atomic_load(&ctx->recording)) {
		chrono_admin_fulfill(req, -EALREADY);
		return;
	}
	if (req->req_port != 0)
		ctx->opts.udp_port = req->req_port;
	/* Explicit 0 (from the web UI's "Unlimited" mode) must override a
	 * nonzero daemon-startup default to actually mean unlimited - only
	 * an omitted param keeps that default as-is. */
	if (req->req_count_limit_given)
		ctx->opts.count_limit = req->req_count_limit;
	if (ctx->opts.udp_port == 0) {
		chrono_admin_fulfill(req, -EINVAL);
		return;
	}
	daemon_claim_segment_start(ctx);
}

static void
admin_do_recording_stop(struct app_context_t *ctx, struct chrono_admin_request *req)
{
	if (!atomic_load(&ctx->recording)) {
		chrono_admin_fulfill(req, -EALREADY);
		return;
	}
	atomic_store_explicit(&ctx->last_stop_reason, CHRONO_STOP_USER, memory_order_relaxed);
	daemon_stop_recording(ctx);
}

/* ---- QUICK_FORMAT: delegate to main.c's daemon_quick_format_start(),
 * which mirrors --init --force's own TOC-zero-then-header-write chain and
 * calls chrono_admin_fulfill() itself at its terminal step, same as
 * RECORDING_START/STOP above. ---- */

static void
admin_do_quick_format(struct app_context_t *ctx, struct chrono_admin_request *req)
{
	if (atomic_load(&ctx->recording)) {
		chrono_admin_fulfill(req, -EBUSY);
		return;
	}
	daemon_quick_format_start(ctx);
}

/* ---- SET_WRITE_BUFFERS / SET_WRITE_CHUNK: both synchronous, delegate
 * straight to main.c's setters, which call chrono_admin_fulfill()
 * themselves - see chrono_admin.h. Refused while recording (same as
 * QUICK_FORMAT above) since every buffer must be guaranteed idle for either
 * change to be safe - see MAX_WRITE_BUFFERS's comment in chrono_ctx.h. ---- */

static void
admin_do_write_buffers(struct app_context_t *ctx, struct chrono_admin_request *req)
{
	/* claim_in_progress too, not just recording - see its comment
	 * (chrono_ctx.h) for the race this closes: a claim snapshots
	 * ctx->buf_size/write_buf_count into the TOC several async bdev
	 * writes before ctx->recording actually flips true. */
	if (atomic_load(&ctx->recording) || atomic_load(&ctx->claim_in_progress)) {
		chrono_admin_fulfill(req, -EBUSY);
		return;
	}
	daemon_set_write_buf_count(ctx, req->req_write_buf_count);
}

static void
admin_do_write_chunk(struct app_context_t *ctx, struct chrono_admin_request *req)
{
	/* claim_in_progress too, not just recording - see its comment
	 * (chrono_ctx.h) for the race this closes: a claim snapshots
	 * ctx->buf_size/write_buf_count into the TOC several async bdev
	 * writes before ctx->recording actually flips true. */
	if (atomic_load(&ctx->recording) || atomic_load(&ctx->claim_in_progress)) {
		chrono_admin_fulfill(req, -EBUSY);
		return;
	}
	daemon_set_write_chunk_bytes(ctx, req->req_write_chunk_bytes);
}

/* ---- SET_WIRE_HAS_SEQ: same synchronous shape and same recording/claim
 * guard as the two above - see daemon_set_wire_has_seq()'s comment
 * (chrono_admin.h) for why this can't change mid-segment. ---- */

static void
admin_do_wire_has_seq(struct app_context_t *ctx, struct chrono_admin_request *req)
{
	if (atomic_load(&ctx->recording) || atomic_load(&ctx->claim_in_progress)) {
		chrono_admin_fulfill(req, -EBUSY);
		return;
	}
	daemon_set_wire_has_seq(ctx, req->req_wire_has_seq);
}

/* ---- SET_LOCAL_IP: same synchronous shape, no guard - see
 * daemon_set_local_ip()'s comment (chrono_admin.h) for why. ---- */

static void
admin_do_set_local_ip(struct app_context_t *ctx, struct chrono_admin_request *req)
{
	daemon_set_local_ip(ctx, req->req_local_ip, req->req_have_local_ip);
}

void
chrono_admin_dispatch(void *arg)
{
	struct app_context_t *ctx = arg;
	struct chrono_admin_request *req = &ctx->admin_req;

	if (atomic_load(&ctx->shutting_down) && req->op != CHRONO_ADMIN_RECORDING_STOP) {
		chrono_admin_fulfill(req, -ESHUTDOWN);
		return;
	}

	switch (req->op) {
	case CHRONO_ADMIN_RECORDING_START:
		admin_do_recording_start(ctx, req);
		break;
	case CHRONO_ADMIN_RECORDING_STOP:
		admin_do_recording_stop(ctx, req);
		break;
	case CHRONO_ADMIN_SEGMENTS_LIST:
		admin_do_segments_list(ctx, req);
		break;
	case CHRONO_ADMIN_SEGMENT_RECORDS:
		admin_do_segment_records(ctx, req);
		break;
	case CHRONO_ADMIN_SEGMENT_DELETE:
		admin_do_segment_delete(ctx, req);
		break;
	case CHRONO_ADMIN_QUICK_FORMAT:
		admin_do_quick_format(ctx, req);
		break;
	case CHRONO_ADMIN_SET_WRITE_BUFFERS:
		admin_do_write_buffers(ctx, req);
		break;
	case CHRONO_ADMIN_SET_WRITE_CHUNK:
		admin_do_write_chunk(ctx, req);
		break;
	case CHRONO_ADMIN_SET_WIRE_HAS_SEQ:
		admin_do_wire_has_seq(ctx, req);
		break;
	case CHRONO_ADMIN_SET_LOCAL_IP:
		admin_do_set_local_ip(ctx, req);
		break;
	default:
		chrono_admin_fulfill(req, -EINVAL);
		break;
	}
}
