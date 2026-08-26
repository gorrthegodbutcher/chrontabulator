#ifndef WEB_STATUS_H
#define WEB_STATUS_H

#include <stdint.h>

struct app_context_t;

/* Starts the web dashboard on a dedicated pthread (not the SPDK reactor -
 * see chrono_admin.h for why). Serves GET / (static dashboard),
 * GET /status.json (live, lock-free "hot" status), and, bridged through
 * chrono_admin.c onto the reactor thread, GET /segments.json,
 * GET /segments/<id>/records.json, POST /recording/start,
 * POST /recording/stop, POST /segments/<id>/delete. Returns 0 on success,
 * -1 on failure (port already in use, etc - logged, not fatal to the
 * caller by design, though daemon_start() currently treats it as fatal
 * setup failure like everything else there).
 *
 * ctx->shutting_down doubles as this server's quit flag - the accept
 * loop polls it directly rather than taking a separate parameter,
 * since main.c always sets it as the very first step of daemon
 * shutdown anyway (see the shutdown-safety design in the project's
 * plan). */
int web_status_start(uint16_t web_port, struct app_context_t *ctx);

/* Blocks until the server thread has exited. Must be called from main(),
 * after spdk_app_start() has returned (i.e. after the reactor OS thread
 * is done) and before spdk_app_fini() - never from inside a reactor
 * callback, since the accept loop may be blocked in a bridged admin call
 * that only the reactor thread can complete. */
void web_status_stop(void);

#endif
