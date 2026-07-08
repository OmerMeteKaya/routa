#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "lb/upstream.h"
#include "util/logger.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "net/socket.h"
#include "net/poller.h"

/* ── upstream_conn acquire/release ─────────────────────────────────────────*/

/* Bug fix / cleanup: node_connect() and upstream_conn_acquire() (the old
 * blocking, synchronous connect-and-acquire path) were dead code -- no
 * caller anywhere in the codebase used them. The real request-forwarding
 * path (proxy.c / lb.c's begin_forward_on_node()) has always gone through
 * upstream_conn_connect_async() + this same upstream_conn_release()
 * instead. Removed rather than left to bit-rot silently; if a genuinely
 * synchronous acquire is ever needed again, upstream_conn_connect_async()
 * plus a short select()/poll() at the call site is the pattern to reach
 * for (matching how hc_probe_start() in the health-check rewrite above
 * does it), not reviving a static-linkage blocking helper. */

void upstream_conn_release(upstream_conn_t *conn, int healthy) {
    upstream_node_t *node = conn->node;

    __atomic_fetch_sub(&node->inflight, 1u, __ATOMIC_RELAXED);

    if (!healthy) {
        close(conn->fd);
        free(conn);
        pthread_mutex_lock(&node->pool_lock);
        node->active_count--;
        pthread_mutex_unlock(&node->pool_lock);
        return;
    }

    conn->state     = UPSTREAM_CONN_IDLE;
    conn->last_used = time(NULL);
    conn->requests++;

    pthread_mutex_lock(&node->pool_lock);
    conn->next       = node->idle_conns;
    node->idle_conns = conn;
    node->idle_count++;
    node->active_count--;
    pthread_mutex_unlock(&node->pool_lock);
}

void upstream_node_drain_idle(upstream_node_t *node) {
    pthread_mutex_lock(&node->pool_lock);
    upstream_conn_t *c = node->idle_conns;
    node->idle_conns = NULL;
    node->idle_count = 0;
    pthread_mutex_unlock(&node->pool_lock);

    while (c) {
        upstream_conn_t *next = c->next;
        close(c->fd);
        free(c);
        c = next;
    }
}

void upstream_node_reap_idle(upstream_node_t *node, time_t max_age_s) {
    time_t threshold = time(NULL) - max_age_s;
    upstream_conn_t *keep  = NULL;
    upstream_conn_t *drain = NULL;

    pthread_mutex_lock(&node->pool_lock);
    upstream_conn_t *c = node->idle_conns;
    while (c) {
        upstream_conn_t *next = c->next;
        if (c->last_used < threshold) {
            c->next = drain;
            drain   = c;
            node->idle_count--;
        } else {
            c->next = keep;
            keep    = c;
        }
        c = next;
    }
    node->idle_conns = keep;
    pthread_mutex_unlock(&node->pool_lock);

    while (drain) {
        upstream_conn_t *next = drain->next;
        close(drain->fd);
        free(drain);
        drain = next;
    }
}

/* ── Async connect ──────────────────────────────────────────────────────────*/

/* Resolves node->host into node->addr (IPv4 or IPv6, cached after the
 * first call) and returns 0 on success, -1 if the host string is neither
 * a valid IPv4 nor IPv6 literal. Bug fix / feature: previously hardcoded
 * AF_INET + inet_pton(AF_INET, ...), silently rejecting (with a generic
 * "cannot parse IP" error) any IPv6 upstream -- routa's config parser
 * already accepts "[::1]:3000"-style upstream lines (see config.c), but
 * they'd fail here at connect time. Tries IPv4 first (the common case),
 * falls back to IPv6 only if that fails, so ordinary dotted-decimal
 * addresses don't pay for a wasted IPv6 parse attempt. */
static int resolve_node_addr(upstream_node_t *node) {
    pthread_spin_lock(&node->state_lock);
    if (node->addr_resolved) {
        pthread_spin_unlock(&node->state_lock);
        return 0;
    }

    memset(&node->addr, 0, sizeof(node->addr));

    struct sockaddr_in *a4 = (struct sockaddr_in *)&node->addr;
    if (inet_pton(AF_INET, node->host, &a4->sin_addr) == 1) {
        a4->sin_family = AF_INET;
        a4->sin_port   = htons(node->port);
        node->addr_family = AF_INET;
        node->addr_len     = sizeof(struct sockaddr_in);
        node->addr_resolved = 1;
        pthread_spin_unlock(&node->state_lock);
        return 0;
    }

    struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&node->addr;
    memset(a6, 0, sizeof(*a6));
    if (inet_pton(AF_INET6, node->host, &a6->sin6_addr) == 1) {
        a6->sin6_family = AF_INET6;
        a6->sin6_port   = htons(node->port);
        node->addr_family = AF_INET6;
        node->addr_len     = sizeof(struct sockaddr_in6);
        node->addr_resolved = 1;
        pthread_spin_unlock(&node->state_lock);
        return 0;
    }

    /* Not an IP literal -- try it as a hostname (e.g. "api.internal").
     * getaddrinfo() is a blocking syscall, so this DNS lookup happens
     * synchronously on whichever worker thread first tries to connect to
     * this node -- but only ONCE per node, ever: node->addr_resolved
     * caches the result (this whole function returns immediately at the
     * top if already resolved), same as the IP-literal fast paths above.
     * This means a hostname upstream's resolved address is fixed for the
     * process's lifetime (no re-resolution on DNS/TTL changes) -- a
     * simple, deliberate tradeoff for a first hostname-support pass;
     * revisit with periodic re-resolution if DNS-based failover across
     * the resolved IP itself (as opposed to routa's own health checking
     * across configured nodes) becomes a real requirement. */
    {
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", node->port);

        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_family   = AF_UNSPEC; /* accept whichever family DNS returns */

        struct addrinfo *res = NULL;
        int gai_rc = getaddrinfo(node->host, port_str, &hints, &res);
        if (gai_rc != 0 || !res) {
            pthread_spin_unlock(&node->state_lock);
            LOG_ERROR("upstream: cannot resolve hostname '%s': %s",
                      node->host, gai_strerror(gai_rc));
            if (res) freeaddrinfo(res);
            return -1;
        }

        /* Use the first result -- getaddrinfo() with AF_UNSPEC typically
         * orders results per RFC 6724 (e.g. preferring IPv6 if the host
         * has working IPv6 connectivity), which is a reasonable default
         * without adding our own preference logic. */
        memcpy(&node->addr, res->ai_addr, res->ai_addrlen);
        node->addr_family   = res->ai_family;
        node->addr_len      = (socklen_t)res->ai_addrlen;
        node->addr_resolved = 1;
        freeaddrinfo(res);

        pthread_spin_unlock(&node->state_lock);
        LOG_INFO("upstream: resolved hostname '%s' to an address (family=%d)",
                 node->host, node->addr_family);
        return 0;
    }
}

int upstream_conn_connect_async(upstream_node_t *node) {
    if (resolve_node_addr(node) < 0) return -1;

    int fd = socket(node->addr_family, SOCK_STREAM, 0);
    if (fd >= 0) {
        net_set_nonblocking(fd);
        fcntl(fd, F_SETFD, FD_CLOEXEC);
    }
    if (fd < 0) return -1;

    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    int ret = connect(fd, (struct sockaddr *)&node->addr, node->addr_len);
    if (ret < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    return fd;
}

int upstream_conn_check_connected(int fd) {
    int err = 0;
    socklen_t len = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0)
        return -1;
    return 0;
}

/* ── Passive health tracking ────────────────────────────────────────────────*/

void upstream_node_set_state(upstream_node_t *node, node_state_t state) {
    pthread_spin_lock(&node->state_lock);
    node_state_t old = node->state;
    node->state = state;
    if (state == NODE_DOWN && old != NODE_DOWN) {
        /* Freshly DOWN: start the half-open clock and clear any stale
         * in-flight guard from a previous half-open cycle. */
        node->down_since = time(NULL);
        node->half_open_probe_in_flight = 0;
    }
    pthread_spin_unlock(&node->state_lock);

    if (old != state) {
        const char *s = state == NODE_UP ? "UP" :
                        state == NODE_DOWN ? "DOWN" :
                        state == NODE_HALF_OPEN ? "HALF_OPEN" : "DRAINING";
        LOG_INFO("upstream %s:%d → %s", node->host, node->port, s);
    }

    if (state == NODE_DOWN)
        upstream_node_drain_idle(node);
}

/* See doc comment in upstream.h. Only meaningful for nodes with hc.type ==
 * HC_NONE -- nodes with an active health check never sit in a bare
 * NODE_DOWN-with-no-recovery-path state, so they don't need this. */
int upstream_node_is_selectable(upstream_node_t *node, upstream_pool_t *pool) {
    pthread_spin_lock(&node->state_lock);
    node_state_t st = node->state;
    pthread_spin_unlock(&node->state_lock);

    if (st == NODE_UP) return 1;
    if (st == NODE_DRAINING || st == NODE_HALF_OPEN) return 0;

    /* st == NODE_DOWN */
    if (node->hc.type != HC_NONE) return 0;      /* hc thread owns recovery */
    if (pool->half_open_retry_after_ms <= 0) return 0; /* half-open disabled */

    time_t now = time(NULL);
    long elapsed_ms = (long)difftime(now, node->down_since) * 1000L;
    if (elapsed_ms < pool->half_open_retry_after_ms) return 0;

    /* Try to win the trial slot -- only one caller may proceed. */
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&node->half_open_probe_in_flight,
                                     &expected, 1u, 0,
                                     __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
        return 0; /* someone else already has the trial in flight */
    }

    upstream_node_set_state(node, NODE_HALF_OPEN);
    return 1;
}

void upstream_node_half_open_release(upstream_node_t *node) {
    __atomic_store_n(&node->half_open_probe_in_flight, 0u, __ATOMIC_SEQ_CST);
}

void upstream_node_record_success(upstream_node_t *node,
                                   upstream_pool_t *pool) {
    pthread_spin_lock(&node->state_lock);
    node->success_count++;
    node->fail_count = 0;
    node->total_requests++;
    node_state_t st = node->state;
    pthread_spin_unlock(&node->state_lock);

    if ((st == NODE_DOWN || st == NODE_HALF_OPEN) &&
        node->success_count >= (uint32_t)pool->passive_recover_threshold) {
        upstream_node_set_state(node, NODE_UP);
        /* reset under lock */
        pthread_spin_lock(&node->state_lock);
        node->success_count = 0;
        pthread_spin_unlock(&node->state_lock);
        }
    if (st == NODE_HALF_OPEN)
        upstream_node_half_open_release(node);
}

void upstream_node_record_failure(upstream_node_t *node,
                                   upstream_pool_t *pool) {
    pthread_spin_lock(&node->state_lock);
    node->fail_count++;
    node->success_count = 0;
    node->total_errors++;
    node->last_fail_time = time(NULL);
    uint32_t fail = node->fail_count;
    node_state_t st = node->state;
    pthread_spin_unlock(&node->state_lock);

    if (st == NODE_HALF_OPEN) {
        /* Trial failed: back to DOWN (resets down_since, restarting the
         * half-open clock for the next attempt) and release the guard. */
        upstream_node_set_state(node, NODE_DOWN);
        upstream_node_half_open_release(node);
        return;
    }

    if (fail >= (uint32_t)pool->passive_fail_threshold) {
        upstream_node_set_state(node, NODE_DOWN);
    }
}

/* ── Active health check ────────────────────────────────────────────────────*/

/* Bounded strstr -- strstr() itself requires a NUL-terminated haystack;
 * this works directly on a [start,end) byte range, since HC probe
 * response buffers aren't always NUL-terminated at the exact point
 * that matters here. */
static const char *strstr_bounded(const char *start, const char *end, const char *needle) {
    size_t nlen = strlen(needle);
    if (nlen == 0 || (size_t)(end - start) < nlen) return NULL;
    for (const char *p = start; p + nlen <= end; p++) {
        if (memcmp(p, needle, nlen) == 0) return p;
    }
    return NULL;
}

/* Minimal, dependency-free JSON scan for HC_CUSTOM: looks for a
 * top-level "status" key (skipping whitespace-tolerant JSON) whose
 * string value is exactly "ok" or "OK" -- NOT a full JSON parser (no
 * nesting, no escapes, no other types), but a real key/value match
 * instead of the previous naive strstr(body, "\"ok\"") anywhere-in-body
 * search, which would false-positive on {"status":"not_ok"} (contains
 * the substring "ok"), {"other_field":"ok"} (right value, wrong key),
 * or {"message":"looks ok to me"} (neither field nor exact value).
 * Returns 1 if a "status" key with value "ok"/"OK" is found, 0 otherwise
 * (including on malformed input -- fails closed, matching the old
 * function's behavior of treating "couldn't confirm ok" as a failure). */
static int hc_json_status_ok(const char *body, size_t len) {
    if (!body || len == 0) return 0;
    const char *end = body + len;
    const char *p = body;
    while (p < end) {
        const char *key = strstr_bounded(p, end, "\"status\"");
        if (!key) return 0;
        const char *q = key + 8; /* past "status" */
        while (q < end && (*q == ' ' || *q == '\t')) q++;
        if (q >= end || *q != ':') { p = key + 1; continue; }
        q++;
        while (q < end && (*q == ' ' || *q == '\t')) q++;
        if (q + 1 >= end || *q != '"') { p = key + 1; continue; }
        q++;
        if (q + 1 < end &&
            (q[0] == 'o' || q[0] == 'O') &&
            (q[1] == 'k' || q[1] == 'K') &&
            q + 2 < end && q[2] == '"') {
            return 1;
        }
        p = key + 1; /* keep scanning in case of multiple "status" occurrences */
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Non-blocking, parallel health-check probes
 *
 * Bug fix / redesign: the previous implementation called blocking
 * probe_node() on each node IN SEQUENCE inside a single loop. With N
 * nodes and a per-probe timeout of T, a single slow or unresponsive node
 * could stall the ENTIRE health-check pass for up to T ms before moving
 * on to the next node -- with several slow nodes, or a large N, this
 * could make the effective check interval for later nodes in the list
 * far larger than their configured interval_ms, or even make the whole
 * pool's health checking fall permanently behind. It also only used a
 * single pool-wide interval (pool->nodes[0]->hc.interval_ms), ignoring
 * whatever interval_ms other individual nodes had configured.
 *
 * This version runs all in-flight probes concurrently via a dedicated
 * poller_t (independent of any worker's epoll instance -- this thread
 * has its own event loop), advancing each probe's own connect/TLS-
 * handshake/write/read state machine as its fd becomes ready, and
 * honors each node's own interval_ms/timeout_ms independently. A slow
 * node's probe no longer blocks any other node's probe from starting,
 * progressing, or completing on schedule.
 * ═══════════════════════════════════════════════════════════════════════════*/

typedef enum {
    HC_PHASE_CONNECTING = 0,
    HC_PHASE_TLS_HANDSHAKE,
    HC_PHASE_WRITING,
    HC_PHASE_READING,
} hc_phase_t;

typedef struct {
    upstream_node_t *node;
    int              fd;          /* -1 when this slot has no probe in flight */
    hc_phase_t       phase;
    SSL             *ssl;
    time_t           deadline;    /* absolute wall-clock deadline for this probe */

    char             req[512];
    int              req_len;
    int              req_sent;    /* bytes of req already written (non-TLS path) */

    char             resp[256];
    int              resp_len;    /* bytes of resp already read */
} hc_probe_t;

/* Called when a probe finishes (successfully or not) to update the
 * node's consecutive ok/fail counters and, if a threshold is crossed,
 * its state -- same logic the old blocking loop used inline. */
static void hc_record_probe_result(upstream_node_t *node, int ok) {
    if (ok) {
        node->hc_consec_ok++;
        node->hc_consec_fail = 0;
        if (node->hc_consec_ok >= node->hc.threshold_up) {
            pthread_spin_lock(&node->state_lock);
            node_state_t st = node->state;
            pthread_spin_unlock(&node->state_lock);
            if (st == NODE_DOWN)
                upstream_node_set_state(node, NODE_UP);
        }
    } else {
        node->hc_consec_fail++;
        node->hc_consec_ok = 0;
        if (node->hc_consec_fail >= node->hc.threshold_down)
            upstream_node_set_state(node, NODE_DOWN);
    }
}

/* Tears down a probe's fd/SSL and marks the slot free, without touching
 * hc_consec_ok/hc_consec_fail (caller decides via hc_record_probe_result,
 * or skips it entirely for a probe that never really started). */
static void hc_probe_reset(hc_probe_t *p, poller_t *poller) {
    if (p->fd >= 0) {
        poller_del(poller, p->fd);
        close(p->fd);
    }
    if (p->ssl) {
        SSL_free(p->ssl);
        p->ssl = NULL;
    }
    p->fd    = -1;
    p->node  = NULL;
}

/* Starts a new probe for node in the given slot. Returns 0 on success
 * (slot now has an in-flight probe registered with poller), -1 if the
 * probe couldn't even be started (e.g. connect() failed immediately) --
 * caller should treat -1 as an immediate probe failure. */
static int hc_probe_start(hc_probe_t *p, upstream_node_t *node, poller_t *poller) {
    int timeout_ms = node->hc.timeout_ms > 0 ? node->hc.timeout_ms : 2000;

    int fd = upstream_conn_connect_async(node);
    if (fd < 0) return -1;

    p->node     = node;
    p->fd       = fd;
    p->phase    = HC_PHASE_CONNECTING;
    p->ssl      = NULL;
    p->deadline = time(NULL) + (timeout_ms / 1000 + 1);
    p->req_len  = 0;
    p->req_sent = 0;
    p->resp_len = 0;

    if (poller_add(poller, fd, POLLER_WRITE | POLLER_ET, p) < 0) {
        close(fd);
        p->fd   = -1;
        p->node = NULL;
        return -1;
    }
    return 0;
}

/* Builds the HC_HTTP/HC_CUSTOM request line into p->req. Called once
 * connect (and TLS handshake, if any) has completed. */
static void hc_build_request(hc_probe_t *p) {
    const char *path = p->node->hc.path[0] ? p->node->hc.path : "/health";
    p->req_len = snprintf(p->req, sizeof(p->req),
        "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
        path, p->node->host);
}

/* Validates a completed HC_HTTP/HC_CUSTOM response. Returns 1 (ok) or 0. */
static int hc_validate_response(hc_probe_t *p) {
    if (p->resp_len <= 0) return 0;
    p->resp[p->resp_len] = '\0';
    if (strncmp(p->resp, "HTTP/1.", 7) != 0) return 0;
    int status = (int)strtol(p->resp + 9, NULL, 10);
    if (status < 200 || status >= 300) return 0;
    if (p->node->hc.type == HC_CUSTOM) {
        /* See hc_json_status_ok() below -- a real (tiny, single-field)
         * JSON scan instead of a bare substring search, which used to
         * accept any response containing the bytes "ok" ANYWHERE (e.g.
         * in an unrelated field, or even inside "not_ok"). */
        const char *body = strstr(p->resp, "\r\n\r\n");
        if (!body) return 0;
        body += 4;
        return hc_json_status_ok(body, (size_t)(p->resp_len - (body - p->resp)));
    }
    return 1;
}

/* Advances one probe's state machine by one step, in response to its fd
 * becoming ready per revents (POLLER_READ/WRITE/HUP/ERR). Returns:
 *   1  probe finished, *out_ok reflects the result
 *   0  probe still in progress, nothing to report yet
 *  -1  probe failed outright (fatal I/O error) -- *out_ok is always 0 in
 *      this case too, but distinguished for clarity at the call site
 */
static int hc_probe_advance(hc_probe_t *p, uint32_t revents, int *out_ok) {
    *out_ok = 0;

    if (revents & (POLLER_HUP | POLLER_ERR)) return -1;

    switch (p->phase) {
    case HC_PHASE_CONNECTING: {
        if (upstream_conn_check_connected(p->fd) < 0) return -1;

        if (p->node->use_tls) {
            SSL_CTX *sctx = SSL_CTX_new(TLS_client_method());
            if (!sctx) return -1;
            SSL_CTX_set_verify(sctx, SSL_VERIFY_NONE, NULL);
            SSL_CTX_set_mode(sctx, SSL_MODE_ENABLE_PARTIAL_WRITE |
                                   SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
            p->ssl = SSL_new(sctx);
            SSL_CTX_free(sctx);
            if (!p->ssl) return -1;
            SSL_set_fd(p->ssl, p->fd);
            SSL_set_connect_state(p->ssl);
            SSL_set_tlsext_host_name(p->ssl, p->node->host);
            p->phase = HC_PHASE_TLS_HANDSHAKE;
            return 0; /* re-enter on next readiness event */
        }

        if (p->node->hc.type == HC_TCP) { *out_ok = 1; return 1; }
        hc_build_request(p);
        p->phase = HC_PHASE_WRITING;
        return 0;
    }

    case HC_PHASE_TLS_HANDSHAKE: {
        int hret = SSL_do_handshake(p->ssl);
        if (hret == 1) {
            if (p->node->hc.type == HC_TCP) { *out_ok = 1; return 1; }
            hc_build_request(p);
            p->phase = HC_PHASE_WRITING;
            return 0;
        }
        int err = SSL_get_error(p->ssl, hret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            return 0; /* still handshaking, wait for the next event */
        return -1;
    }

    case HC_PHASE_WRITING: {
        int w;
        if (p->ssl) w = SSL_write(p->ssl, p->req + p->req_sent, p->req_len - p->req_sent);
        else        w = (int)write(p->fd, p->req + p->req_sent, (size_t)(p->req_len - p->req_sent));
        if (w <= 0) {
            if (!p->ssl && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
            if (p->ssl) {
                int err = SSL_get_error(p->ssl, w);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return 0;
            }
            return -1;
        }
        p->req_sent += w;
        if (p->req_sent < p->req_len) return 0; /* partial write, wait for more */
        p->phase = HC_PHASE_READING;
        return 0;
    }

    case HC_PHASE_READING: {
        int r;
        if (p->ssl) r = SSL_read(p->ssl, p->resp + p->resp_len,
                                 (int)(sizeof(p->resp) - 1 - (size_t)p->resp_len));
        else        r = (int)read(p->fd, p->resp + p->resp_len,
                                  sizeof(p->resp) - 1 - (size_t)p->resp_len);
        if (r < 0) {
            if (!p->ssl && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
            if (p->ssl) {
                int err = SSL_get_error(p->ssl, r);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return 0;
            }
            return -1;
        }
        if (r == 0) {
            /* EOF -- validate whatever we've accumulated so far */
            *out_ok = hc_validate_response(p);
            return 1;
        }
        p->resp_len += r;
        if ((size_t)p->resp_len >= sizeof(p->resp) - 1) {
            *out_ok = hc_validate_response(p);
            return 1;
        }
        return 0; /* keep reading */
    }
    }
    return -1;
}

static void *hc_thread_fn(void *arg) {
    upstream_pool_t *pool = (upstream_pool_t *)arg;
    if (pool->node_count == 0) return NULL;

    poller_t *poller = poller_new();
    if (!poller) {
        LOG_ERROR("hc: failed to create poller, health checks disabled for this pool");
        return NULL;
    }

    hc_probe_t *probes = calloc((size_t)pool->node_count, sizeof(hc_probe_t));
    if (!probes) { poller_free(poller); return NULL; }
    for (int i = 0; i < pool->node_count; i++) probes[i].fd = -1;

    /* last_probe_start[i]: wall-clock time the last probe for node i was
     * kicked off (0 = never), used to honor each node's own interval_ms
     * independently instead of a single pool-wide interval. */
    time_t *last_probe_start = calloc((size_t)pool->node_count, sizeof(time_t));
    if (!last_probe_start) { free(probes); poller_free(poller); return NULL; }

    poller_event_t events[64];

    while (!pool->hc_stop) {
        time_t now = time(NULL);

        /* Start any due, not-currently-in-flight probes. */
        for (int i = 0; i < pool->node_count; i++) {
            upstream_node_t *node = pool->nodes[i];
            if (node->hc.type == HC_NONE) continue;
            if (probes[i].fd >= 0) continue; /* already in flight */

            int interval_ms = node->hc.interval_ms > 0 ? node->hc.interval_ms : 5000;
            if (last_probe_start[i] != 0 &&
                (long)(now - last_probe_start[i]) * 1000L < interval_ms)
                continue;

            last_probe_start[i] = now;
            if (hc_probe_start(&probes[i], node, poller) < 0) {
                hc_record_probe_result(node, 0);
            }
        }

        /* Wait briefly for progress on any in-flight probe -- a short,
         * fixed poll timeout (rather than computing the exact next-due
         * time across all nodes) keeps this loop simple and is cheap
         * enough given health checks run at most a few times a second. */
        int nfds = poller_wait(poller, events, 64, 200);
        for (int e = 0; e < nfds; e++) {
            hc_probe_t *p = (hc_probe_t *)events[e].ptr;
            if (!p || p->fd < 0) continue;

            int ok = 0;
            int rc = hc_probe_advance(p, events[e].events, &ok);
            if (rc != 0) {
                upstream_node_t *node = p->node;
                hc_probe_reset(p, poller);
                hc_record_probe_result(node, ok);
            }
            /* rc == 0: still in progress, leave it registered. */
        }

        /* Reap any probe that's been running past its own deadline --
         * poller_wait() alone won't catch this (a connect() that never
         * completes produces no event at all, for instance). */
        now = time(NULL);
        for (int i = 0; i < pool->node_count; i++) {
            if (probes[i].fd < 0) continue;
            if (now < probes[i].deadline) continue;
            upstream_node_t *node = probes[i].node;
            hc_probe_reset(&probes[i], poller);
            hc_record_probe_result(node, 0);
        }
    }

    for (int i = 0; i < pool->node_count; i++) {
        if (probes[i].fd >= 0) hc_probe_reset(&probes[i], poller);
    }
    free(last_probe_start);
    free(probes);
    poller_free(poller);
    return NULL;
}

int upstream_pool_hc_start(upstream_pool_t *pool) {
    pool->hc_stop    = 0;
    pool->hc_running = 1;
    return pthread_create(&pool->hc_thread, NULL, hc_thread_fn, pool);
}

void upstream_pool_hc_stop(upstream_pool_t *pool) {
    pool->hc_stop = 1;
    if (pool->hc_running) {
        pthread_join(pool->hc_thread, NULL);
        pool->hc_running = 0;
    }
}

/* ── Pool lifecycle ─────────────────────────────────────────────────────────*/

upstream_pool_t *upstream_pool_new(void) {
    upstream_pool_t *p = calloc(1, sizeof(upstream_pool_t));
    if (!p) return NULL;
    p->passive_fail_threshold    = 3;
    p->passive_recover_threshold = 2;
    return p;
}

void upstream_pool_free(upstream_pool_t *pool) {
    if (!pool) return;
    upstream_pool_hc_stop(pool);
    for (int i = 0; i < pool->node_count; i++) {
        upstream_node_t *n = pool->nodes[i];
        upstream_node_drain_idle(n);
        pthread_mutex_destroy(&n->pool_lock);
        pthread_spin_destroy(&n->state_lock);
        free(n);
    }
    free((void *)pool->nodes);
    free((void *)pool->hash_ring);
    free(pool);
}

int upstream_pool_add_node(upstream_pool_t *pool, upstream_node_t *node) {
    upstream_node_t **tmp = (upstream_node_t **)realloc((void *)pool->nodes,
        (size_t)(pool->node_count + 1) * sizeof(upstream_node_t *));
    if (!tmp) return -1;
    pool->nodes = tmp;
    pool->nodes[pool->node_count++] = node;
    return 0;
}
