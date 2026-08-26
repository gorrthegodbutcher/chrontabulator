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
	uint16_t req_port;             /* RECORDING_START, 0 = use ctx default */
	uint64_t req_count_limit;      /* RECORDING_START, 0 = use ctx default */
	uint32_t req_segment_id;       /* SEGMENT_RECORDS, SEGMENT_DELETE */
	uint64_t req_offset;           /* SEGMENT_RECORDS */
	uint32_t req_limit;            /* SEGMENT_RECORDS, clamped server-side */
	bool req_include_deleted;      /* SEGMENTS_LIST */

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

/* Called by whichever handler (in chrono_admin.c or main.c) finished
 * req's work, successfully or not. Locks, records rc, marks done, and
 * signals the web thread's condvar - unless req->abandoned (the web
 * thread already gave up waiting), in which case it just clears busy
 * silently, since nobody is listening and resp_buf may already be
 * reused for a later call by then. */
void chrono_admin_fulfill(struct chrono_admin_request *req, int rc);

#endif
