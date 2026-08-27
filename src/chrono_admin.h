#ifndef CHRONO_ADMIN_H
#define CHRONO_ADMIN_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>

struct app_context_t;
struct chrono_segment_entry;

/* How a TOC slot should be treated by any reader (CLI list/dump, or the
 * web bridge's JSON equivalents) - shared so both agree on what
 * "deleted" and "never claimed" mean instead of each re-deriving it from
 * the raw magic/state fields. */
enum chrono_segment_view {
	CHRONO_SEG_VIEW_NOT_FOUND,
	CHRONO_SEG_VIEW_OPEN,
	CHRONO_SEG_VIEW_FINALIZED,
	CHRONO_SEG_VIEW_DELETED,
};

enum chrono_segment_view chrono_segment_classify(const struct chrono_segment_entry *seg);

/* Bridges the web server's pthread into the SPDK reactor thread, which is
 * the only thread allowed to touch bdev/thread APIs. The web thread fills
 * a request, hands it to the reactor via spdk_thread_send_msg(), and
 * blocks (bounded) on a condvar until the reactor-side handler is done.
 * Only one admin request is ever in flight - the web server's own
 * accept()-handle-close() loop is fully serial - so one static slot
 * (embedded in app_context_t, not allocated here) is enough; no queue. */

enum chrono_admin_op {
	CHRONO_ADMIN_RECORDING_START,
	CHRONO_ADMIN_RECORDING_STOP,
	CHRONO_ADMIN_SEGMENTS_LIST,
	CHRONO_ADMIN_SEGMENT_RECORDS,
	CHRONO_ADMIN_SEGMENT_DELETE,
	CHRONO_ADMIN_QUICK_FORMAT,
	CHRONO_ADMIN_SET_WRITE_BUFFERS,
	CHRONO_ADMIN_SET_WRITE_CHUNK,
	CHRONO_ADMIN_SET_WIRE_HAS_SEQ,
	CHRONO_ADMIN_SET_LOCAL_IP,
};

struct chrono_admin_request {
	pthread_mutex_t lock;
	pthread_cond_t cond;
	bool busy;      /* web thread: request in flight */
	bool done;      /* reactor thread: response ready, safe to read */
	bool abandoned; /* web thread timed out - reactor should just clear
			 * busy on completion, nobody's waiting to read it */
	enum chrono_admin_op op;

	/* request parameters - flat rather than a union, for clarity over
	 * the handful of bytes it costs */
	uint16_t req_port;              /* RECORDING_START, 0 = use ctx default */
	uint64_t req_count_limit;       /* RECORDING_START - meaningful only if
					  * req_count_limit_given; 0 explicitly
					  * means unlimited, distinct from "not
					  * given, keep the daemon's startup
					  * default" */
	bool req_count_limit_given;     /* RECORDING_START */
	uint32_t req_segment_id;       /* SEGMENT_RECORDS, SEGMENT_DELETE */
	uint64_t req_offset;           /* SEGMENT_RECORDS */
	uint32_t req_limit;            /* SEGMENT_RECORDS, clamped server-side */
	bool req_include_deleted;      /* SEGMENTS_LIST */
	uint32_t req_write_buf_count;  /* SET_WRITE_BUFFERS */
	uint32_t req_write_chunk_bytes; /* SET_WRITE_CHUNK */
	bool req_wire_has_seq;          /* SET_WIRE_HAS_SEQ */
	uint8_t req_local_ip[4];        /* SET_LOCAL_IP, meaningful only if
					  * req_have_local_ip */
	bool req_have_local_ip;         /* SET_LOCAL_IP - false means "stop
					  * answering ARP/ICMP-echo entirely",
					  * same as never passing -I at all */

	/* response */
	int rc; /* 0 = success, negative errno-style on failure */
	char *resp_buf;
	size_t resp_buf_cap;
	size_t resp_len;

	/* Internal scan state for SEGMENT_RECORDS's paginated chunk walk -
	 * not a caller-supplied parameter, just needs somewhere to live
	 * across the async chunk-read chain. */
	uint64_t scan_collected;
};

/* Allocates admin_req.resp_buf and initializes the mutex/condvar. Called
 * once from the reactor thread during daemon_start(), before the web
 * server (which is the only other user of this struct) is started. */
int chrono_admin_init(struct app_context_t *ctx);

/* Web thread side: fills req->op/req_* (caller's responsibility, done
 * under no lock since nothing else touches these fields until the mutex
 * is taken inside this call), dispatches to the reactor, and blocks up to
 * timeout_sec for completion. Returns 0 and leaves rc/resp_buf/resp_len
 * populated on completion, or -ETIMEDOUT if the reactor didn't respond in
 * time (caller should treat this as a 503 - the request may still
 * complete later, harmlessly, since it's marked abandoned). */
int chrono_admin_call(struct app_context_t *ctx, struct chrono_admin_request *req,
		       int timeout_sec);

/* Reactor thread side: the spdk_thread_send_msg() target. Dispatches on
 * req->op to the matching handler. */
void chrono_admin_dispatch(void *arg);

/* Implemented in main.c - own the actual daemon capture state machine
 * (claiming a segment and registering the capture poller, or
 * unregistering/flushing/finalizing). Called by chrono_admin.c's
 * RECORDING_START/STOP handlers; each chain's terminal step calls
 * chrono_admin_fulfill() on ctx->admin_req once done (success or
 * failure) - no separate cb_arg threading needed since only one admin
 * request is ever in flight. */
void daemon_claim_segment_start(struct app_context_t *ctx);
void daemon_stop_recording(struct app_context_t *ctx);

/* Same "called by chrono_admin.c, fulfills ctx->admin_req itself at its
 * terminal step" shape as the two above. Wipes the TOC and writes a fresh
 * volume header - the web-triggered equivalent of CLI `--init --force`.
 * Named "quick format" (not "erase") because it only resets metadata: the
 * actual segment data blocks are never zeroed, just orphaned - a real
 * full-disk zero-write is a distinct, much slower operation, not this one.
 * Caller (admin_do_quick_format() in chrono_admin.c) is responsible for
 * refusing this while ctx->recording is true; this function assumes that's
 * already been checked. */
void daemon_quick_format_start(struct app_context_t *ctx);

/* Synchronous setters (no bdev I/O, so no async chain like the ops above -
 * each just validates, sets the field, and calls chrono_admin_fulfill()
 * itself before returning) for the two live-tunable write-path knobs - see
 * MAX_WRITE_BUFFERS's comment in chrono_ctx.h. Both return their result via
 * ctx->admin_req.rc, same as every other op; -EBUSY if ctx->recording (set
 * by admin_do_write_buffers()/admin_do_write_chunk() in chrono_admin.c),
 * -EINVAL if the requested value is out of range. */
void daemon_set_write_buf_count(struct app_context_t *ctx, uint32_t count);
void daemon_set_write_chunk_bytes(struct app_context_t *ctx, uint32_t bytes);

/* Same synchronous shape as the two setters above (no bdev I/O, validates
 * then calls chrono_admin_fulfill() itself) - a plain bool, so no range to
 * validate. -EBUSY if ctx->recording/claim_in_progress, same reasoning as
 * the write-path knobs: capture_poll() reads ctx->wire_has_seq once per
 * packet, so it must stay fixed for a whole segment's duration or a single
 * recording could end up parsed two different ways. This is a testing/
 * diagnostic knob, not a wire-format negotiation - real production traffic
 * never carries dpdk-app-example's synthetic 8-byte sequence prefix, so a
 * real deployment just leaves this on --no-wire-seq (or its web equivalent)
 * permanently. */
void daemon_set_wire_has_seq(struct app_context_t *ctx, bool wire_has_seq);

/* Same synchronous shape as the setters above, but with no -EBUSY guard at
 * all - unlike wire_has_seq/the write-path knobs, net_responder.c reads
 * ctx->opts.local_ip/have_local_ip fresh on every packet with no per-
 * segment consistency requirement (ARP/ICMP-echo replies are independent
 * of whatever's being recorded, if anything), so this is safe to change
 * at any time, recording or not - same shape as dpdk-app-example's
 * interactive sender's own freely-live-tunable fields. Always succeeds. */
void daemon_set_local_ip(struct app_context_t *ctx, const uint8_t ip[4], bool have_ip);

/* Called by whichever handler (in chrono_admin.c or main.c) finished
 * req's work, successfully or not. Locks, records rc, marks done, and
 * signals the web thread's condvar - unless req->abandoned (the web
 * thread already gave up waiting), in which case it just clears busy
 * silently, since nobody is listening and resp_buf may already be
 * reused for a later call by then. */
void chrono_admin_fulfill(struct chrono_admin_request *req, int rc);

#endif
