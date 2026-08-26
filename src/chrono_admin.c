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
		chrono_admin_fulfill(req, -EIO);
		return;
	}

	while (off + sizeof(struct chrono_record_hdr) <= ctx->buf_size &&
	       ctx->dump_records_seen < ctx->dump_target_count &&
	       req->scan_collected < req->req_limit) {
		struct chrono_record_hdr *hdr = (struct chrono_record_hdr *)(ctx->io_buf + off);

		if (hdr->magic != CHRONO_RECORD_MAGIC) {
			/* Padding reached before the TOC entry's own record
			 * count was satisfied - treat what we've already
			 * collected as the true end. */
			ctx->dump_records_seen = ctx->dump_target_count;
			break;
		}
		if (off + sizeof(*hdr) + hdr->len > ctx->buf_size) {
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
				",\"rel_sec\":%.6f,\"len\":%u}",
				first ? "" : ",", hdr->seq, hdr->capture_tsc, rel_sec, hdr->len);
			req->scan_collected++;
		}

		off += (uint32_t)sizeof(*hdr) + hdr->len;
		ctx->dump_records_seen++;
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
			     ctx->dump_cur_block * ctx->block_size, ctx->buf_size,
			     admin_records_chunk_read_complete, ctx);
	if (rc != 0) {
		chrono_admin_fulfill(req, rc);
		return;
	}
	ctx->dump_cur_block += ctx->buf_size_blocks;
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
	daemon_stop_recording(ctx);
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
	default:
		chrono_admin_fulfill(req, -EINVAL);
		break;
	}
}
