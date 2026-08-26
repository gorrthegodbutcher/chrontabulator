#include "chrono_ctx.h"
#include "web_status.h"
#include "chrono_admin.h"
#include "chrono_web_html.h"

#include <rte_ethdev.h>
#include <rte_cycles.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#define REQUEST_BUF_SIZE 512
#define ACCEPT_POLL_TIMEOUT_MS 1000
#define ADMIN_TIMEOUT_SEC 3

struct web_server_ctx {
	int listen_fd;
	struct app_context_t *ctx;
};

static pthread_t g_server_thread;
static bool g_server_running;
static struct web_server_ctx g_wctx;

/* Reads and discards a request up to (and including) the blank line that
 * ends the headers, keeping only the request line - same bounded,
 * not-a-general-HTTP-parser approach as dpdk-app-example's web_status.c,
 * just with a bigger buffer to fit this project's longer paths
 * (/segments/<id>/records.json?offset=...&limit=...). */
static void
read_request_line(int fd, char *line_out, size_t line_out_size)
{
	char buf[REQUEST_BUF_SIZE * 2];
	size_t total = 0;
	bool have_line = false;

	line_out[0] = '\0';

	while (total < sizeof(buf) - 1) {
		ssize_t n = recv(fd, buf + total, sizeof(buf) - 1 - total, 0);
		if (n <= 0)
			break;
		total += (size_t)n;
		buf[total] = '\0';

		if (!have_line) {
			char *eol = strstr(buf, "\r\n");
			if (eol != NULL) {
				size_t len = (size_t)(eol - buf);
				if (len >= line_out_size)
					len = line_out_size - 1;
				memcpy(line_out, buf, len);
				line_out[len] = '\0';
				have_line = true;
			}
		}

		if (strstr(buf, "\r\n\r\n") != NULL)
			break;
	}
}

static void
send_response(int fd, const char *status_line, const char *content_type, const char *body)
{
	char header[512];
	int header_len = snprintf(header, sizeof(header),
		"HTTP/1.1 %s\r\n"
		"Content-Type: %s; charset=utf-8\r\n"
		"Content-Length: %zu\r\n"
		"Connection: close\r\n"
		"\r\n",
		status_line, content_type, strlen(body));

	if (header_len < 0)
		return;

	(void)send(fd, header, (size_t)header_len, MSG_NOSIGNAL);
	(void)send(fd, body, strlen(body), MSG_NOSIGNAL);
}

/* Matches request_line against a fixed method+path prefix (e.g.
 * "GET /segments/"), parses the decimal digits immediately following as
 * *id_out, and returns a pointer to whatever comes right after those
 * digits (e.g. "/records.json?offset=10 HTTP/1.1"). False (no match) if
 * the prefix doesn't match or isn't immediately followed by a digit. */
static bool
parse_segment_path(const char *request_line, const char *method_prefix,
		    uint32_t *id_out, const char **rest_out)
{
	size_t prefix_len = strlen(method_prefix);
	const char *p;
	char *endptr;
	unsigned long id;

	if (strncmp(request_line, method_prefix, prefix_len) != 0)
		return false;
	p = request_line + prefix_len;
	if (!isdigit((unsigned char)*p))
		return false;
	id = strtoul(p, &endptr, 10);
	*id_out = (uint32_t)id;
	*rest_out = endptr;
	return true;
}

/* Tiny key=value&key=value... reader, scoped to this project's actual
 * needs: every query value used here is a small non-negative integer, so
 * no urlencoding support is needed - same "not a general-purpose parser"
 * philosophy as read_request_line(). Returns false if the query string or
 * key isn't present. */
static bool
query_get_uint(const char *rest, const char *key, uint64_t *out)
{
	const char *q = strchr(rest, '?');
	size_t key_len = strlen(key);

	if (!q)
		return false;
	q++;
	while (*q && *q != ' ') {
		if (strncmp(q, key, key_len) == 0 && q[key_len] == '=') {
			char *endptr;
			unsigned long long val = strtoull(q + key_len + 1, &endptr, 10);
			if (endptr != q + key_len + 1) {
				*out = val;
				return true;
			}
		}
		const char *amp = strchr(q, '&');
		if (!amp)
			break;
		q = amp + 1;
	}
	return false;
}

/* Tier 1: served directly, no bridge - every field here is either a
 * lock-free atomic, a DPDK call already proven safe from any thread
 * (port_init.c), or a value set once before this thread was created (see
 * the comment on app_context_t's start_time field in chrono_ctx.h). */
static void
render_status_json(struct app_context_t *ctx, char *out, size_t out_size)
{
	bool recording = atomic_load_explicit(&ctx->recording, memory_order_relaxed);
	uint32_t seg_id = atomic_load_explicit(&ctx->current_segment_id, memory_order_relaxed);
	uint64_t rec_count = atomic_load_explicit(&ctx->record_count, memory_order_relaxed);
	uint64_t drop_count = atomic_load_explicit(&ctx->dropped_count, memory_order_relaxed);
	uint64_t first_tsc = atomic_load_explicit(&ctx->first_capture_tsc, memory_order_relaxed);
	uint64_t last_tsc = atomic_load_explicit(&ctx->last_capture_tsc, memory_order_relaxed);
	uint32_t next_seg = atomic_load_explicit(&ctx->mirror_next_segment_id, memory_order_relaxed);
	uint64_t next_data_block = atomic_load_explicit(&ctx->mirror_next_data_block,
							  memory_order_relaxed);
	uint64_t bytes_written = atomic_load_explicit(&ctx->bytes_written_total,
							memory_order_relaxed);
	uint64_t writes_completed = atomic_load_explicit(&ctx->writes_completed_total,
							    memory_order_relaxed);
	uint64_t write_errors = atomic_load_explicit(&ctx->write_errors_total,
						       memory_order_relaxed);

	struct rte_eth_stats hw;
	struct rte_eth_link link;
	bool have_hw = rte_eth_stats_get(ctx->port, &hw) == 0;
	bool have_link = rte_eth_link_get_nowait(ctx->port, &link) == 0;
	uint64_t tsc_hz = rte_get_tsc_hz();

	double elapsed_sec = (recording && tsc_hz != 0) ?
		(double)(last_tsc - first_tsc) / tsc_hz : 0.0;

	uint64_t data_blocks = ctx->vol.data_start_block <= ctx->cached_num_blocks ?
		ctx->cached_num_blocks - ctx->vol.data_start_block : 0;
	uint64_t data_used_blocks = next_data_block > ctx->vol.data_start_block ?
		next_data_block - ctx->vol.data_start_block : 0;
	uint64_t total_bytes = ctx->cached_num_blocks * (uint64_t)ctx->block_size;
	uint64_t data_used_bytes = data_used_blocks * (uint64_t)ctx->block_size;
	uint64_t data_free_bytes = data_blocks > data_used_blocks ?
		(data_blocks - data_used_blocks) * (uint64_t)ctx->block_size : 0;
	double toc_pct = ctx->vol.toc_slot_count != 0 ?
		(100.0 * next_seg) / ctx->vol.toc_slot_count : 0.0;

	char seg_id_json[16];
	if (seg_id == CHRONO_NO_SEGMENT)
		snprintf(seg_id_json, sizeof(seg_id_json), "null");
	else
		snprintf(seg_id_json, sizeof(seg_id_json), "%u", seg_id);

	snprintf(out, out_size,
		"{\n"
		"  \"mode\": \"chrontabulator\",\n"
		"  \"uptime_sec\": %ld,\n"
		"  \"recording\": %s,\n"
		"  \"current_segment_id\": %s,\n"
		"  \"current_segment_record_count\": %" PRIu64 ",\n"
		"  \"current_segment_dropped_count\": %" PRIu64 ",\n"
		"  \"current_segment_elapsed_sec\": %.3f,\n"
		"  \"udp_port\": %u,\n"
		"  \"link_up\": %s,\n"
		"  \"link_speed_mbps\": %u,\n"
		"  \"have_hw_stats\": %s,\n"
		"  \"hw_ipackets\": %" PRIu64 ",\n"
		"  \"hw_ibytes\": %" PRIu64 ",\n"
		"  \"hw_imissed\": %" PRIu64 ",\n"
		"  \"hw_ierrors\": %" PRIu64 ",\n"
		"  \"bdev_name\": \"%s\",\n"
		"  \"block_size\": %u,\n"
		"  \"total_bytes\": %" PRIu64 ",\n"
		"  \"toc_slot_count\": %u,\n"
		"  \"segments_used\": %u,\n"
		"  \"toc_capacity_pct\": %.2f,\n"
		"  \"data_used_bytes\": %" PRIu64 ",\n"
		"  \"data_free_bytes\": %" PRIu64 ",\n"
		"  \"bytes_written_total\": %" PRIu64 ",\n"
		"  \"writes_completed_total\": %" PRIu64 ",\n"
		"  \"write_errors_total\": %" PRIu64 "\n"
		"}\n",
		(long)(time(NULL) - ctx->start_time),
		recording ? "true" : "false", seg_id_json,
		rec_count, drop_count, elapsed_sec,
		ctx->opts.udp_port,
		(have_link && link.link_status) ? "true" : "false",
		have_link ? link.link_speed : 0,
		have_hw ? "true" : "false",
		have_hw ? hw.ipackets : 0, have_hw ? hw.ibytes : 0,
		have_hw ? hw.imissed : 0, have_hw ? hw.ierrors : 0,
		ctx->opts.bdev_name ? ctx->opts.bdev_name : "",
		ctx->block_size, total_bytes,
		ctx->vol.toc_slot_count, next_seg, toc_pct,
		data_used_bytes, data_free_bytes,
		bytes_written, writes_completed, write_errors);
}

static void
send_admin_result(int fd, int rc, struct chrono_admin_request *req)
{
	if (rc == -ETIMEDOUT) {
		send_response(fd, "503 Service Unavailable", "text/plain",
			      "request timed out\n");
		return;
	}
	if (rc != 0) {
		char body[128];
		snprintf(body, sizeof(body), "{\"error\":\"%s\"}\n", strerror(-rc));
		send_response(fd, "400 Bad Request", "application/json", body);
		return;
	}
	if (req->resp_len > 0)
		send_response(fd, "200 OK", "application/json", req->resp_buf);
	else
		send_response(fd, "200 OK", "application/json", "{}\n");
}

/* "GET /" serves CHRONO_WEB_HTML (chrono_web_html.h) as-is - all dynamic
 * content is client-side, polling /status.json and (on demand)
 * /segments.json. */
static void
handle_connection(int fd, struct app_context_t *ctx)
{
	char request_line[REQUEST_BUF_SIZE];
	struct chrono_admin_request *req = &ctx->admin_req;
	uint32_t seg_id;
	const char *rest;
	uint64_t v;
	int rc;

	read_request_line(fd, request_line, sizeof(request_line));

	if (strncmp(request_line, "GET /status.json ", strlen("GET /status.json ")) == 0) {
		char json[2048];
		render_status_json(ctx, json, sizeof(json));
		send_response(fd, "200 OK", "application/json", json);
	} else if (strncmp(request_line, "GET / ", strlen("GET / ")) == 0) {
		send_response(fd, "200 OK", "text/html", CHRONO_WEB_HTML);
	} else if (strncmp(request_line, "GET /segments.json", strlen("GET /segments.json")) == 0) {
		req->op = CHRONO_ADMIN_SEGMENTS_LIST;
		req->req_include_deleted = query_get_uint(request_line, "include_deleted", &v) &&
			v != 0;
		rc = chrono_admin_call(ctx, req, ADMIN_TIMEOUT_SEC);
		send_admin_result(fd, rc == 0 ? req->rc : rc, req);
	} else if (parse_segment_path(request_line, "GET /segments/", &seg_id, &rest) &&
		   strncmp(rest, "/records.json", strlen("/records.json")) == 0) {
		req->op = CHRONO_ADMIN_SEGMENT_RECORDS;
		req->req_segment_id = seg_id;
		req->req_offset = query_get_uint(rest, "offset", &v) ? v : 0;
		req->req_limit = query_get_uint(rest, "limit", &v) ? (uint32_t)v : 0;
		rc = chrono_admin_call(ctx, req, ADMIN_TIMEOUT_SEC);
		send_admin_result(fd, rc == 0 ? req->rc : rc, req);
	} else if (strncmp(request_line, "POST /recording/start", strlen("POST /recording/start")) == 0) {
		req->op = CHRONO_ADMIN_RECORDING_START;
		req->req_port = query_get_uint(request_line, "port", &v) ? (uint16_t)v : 0;
		req->req_count_limit = query_get_uint(request_line, "count_limit", &v) ? v : 0;
		rc = chrono_admin_call(ctx, req, ADMIN_TIMEOUT_SEC);
		send_admin_result(fd, rc == 0 ? req->rc : rc, req);
	} else if (strncmp(request_line, "POST /recording/stop", strlen("POST /recording/stop")) == 0) {
		req->op = CHRONO_ADMIN_RECORDING_STOP;
		rc = chrono_admin_call(ctx, req, ADMIN_TIMEOUT_SEC);
		send_admin_result(fd, rc == 0 ? req->rc : rc, req);
	} else if (parse_segment_path(request_line, "POST /segments/", &seg_id, &rest) &&
		   strncmp(rest, "/delete", strlen("/delete")) == 0) {
		req->op = CHRONO_ADMIN_SEGMENT_DELETE;
		req->req_segment_id = seg_id;
		rc = chrono_admin_call(ctx, req, ADMIN_TIMEOUT_SEC);
		send_admin_result(fd, rc == 0 ? req->rc : rc, req);
	} else {
		send_response(fd, "404 Not Found", "text/plain", "not found\n");
	}
}

static void *
server_thread_main(void *arg)
{
	struct web_server_ctx *wctx = arg;

	while (!atomic_load_explicit(&wctx->ctx->shutting_down, memory_order_relaxed)) {
		struct pollfd pfd = { .fd = wctx->listen_fd, .events = POLLIN };
		int ret = poll(&pfd, 1, ACCEPT_POLL_TIMEOUT_MS);

		if (ret <= 0)
			continue;

		int conn_fd = accept(wctx->listen_fd, NULL, NULL);
		if (conn_fd < 0)
			continue;

		handle_connection(conn_fd, wctx->ctx);
		close(conn_fd);
	}

	return NULL;
}

int
web_status_start(uint16_t web_port, struct app_context_t *ctx)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		fprintf(stderr, "web_status: socket() failed: %s\n", strerror(errno));
		return -1;
	}

	int one = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = INADDR_ANY,
		.sin_port = htons(web_port),
	};

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		fprintf(stderr, "web_status: bind() to port %u failed: %s\n",
			web_port, strerror(errno));
		close(fd);
		return -1;
	}

	if (listen(fd, 8) != 0) {
		fprintf(stderr, "web_status: listen() failed: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	g_wctx.listen_fd = fd;
	g_wctx.ctx = ctx;

	int ret = pthread_create(&g_server_thread, NULL, server_thread_main, &g_wctx);
	if (ret != 0) {
		fprintf(stderr, "web_status: pthread_create failed: %s\n", strerror(ret));
		close(fd);
		return -1;
	}

	g_server_running = true;
	return 0;
}

void
web_status_stop(void)
{
	if (!g_server_running)
		return;

	pthread_join(g_server_thread, NULL);
	close(g_wctx.listen_fd);
	g_server_running = false;
}
