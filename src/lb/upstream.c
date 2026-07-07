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
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "net/socket.h"

/* ── Internal: open a new TCP connection to node ───────────────────────────*/
static int node_connect(upstream_node_t *node, int timeout_ms) {
    pthread_spin_lock(&node->state_lock);
    if (!node->addr_resolved) {
        memset(&node->addr, 0, sizeof(node->addr));
        node->addr.sin_family = AF_INET;
        node->addr.sin_port   = htons(node->port);
        if (inet_pton(AF_INET, node->host, &node->addr.sin_addr) != 1) {
            pthread_spin_unlock(&node->state_lock);
            LOG_ERROR("upstream: cannot parse IP '%s'", node->host);
            return -1;
        }
        node->addr_resolved = 1;
    }
    pthread_spin_unlock(&node->state_lock);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd >= 0) {
        net_set_nonblocking(fd);
        fcntl(fd, F_SETFD, FD_CLOEXEC);
    }
    if (fd < 0) return -1;

    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    int ret = connect(fd, (struct sockaddr *)&node->addr, sizeof(node->addr));
    if (ret < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }

    if (ret == 0) return fd;   /* immediate connect (loopback) */

    /* Wait for connect to complete */
    struct timeval tv = {
        .tv_sec  =  timeout_ms / 1000,
        .tv_usec = (long)((timeout_ms % 1000) * 1000),
    };
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);

    ret = select(fd + 1, NULL, &wfds, NULL, &tv);
    if (ret <= 0) {
        close(fd);
        return -1;
    }

    int err = 0;
    socklen_t len = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
    if (err) { close(fd); return -1; }

    return fd;
}

/* ── upstream_conn acquire/release ─────────────────────────────────────────*/

upstream_conn_t *upstream_conn_acquire(upstream_node_t *node, int timeout_ms) {
    pthread_spin_lock(&node->state_lock);
    node_state_t st = node->state;
    pthread_spin_unlock(&node->state_lock);

    if (st == NODE_DOWN) return NULL;

    pthread_mutex_lock(&node->pool_lock);

    /* Pop from idle freelist */
    upstream_conn_t *c = node->idle_conns;
    if (c) {
        node->idle_conns = c->next;
        node->idle_count--;
        c->next  = NULL;
        c->state = UPSTREAM_CONN_IN_USE;
        node->active_count++;
        pthread_mutex_unlock(&node->pool_lock);
        __atomic_fetch_add(&node->inflight, 1u, __ATOMIC_RELAXED);
        return c;
    }

    /* Pool full? */
    if (node->active_count >= node->pool_max) {
        pthread_mutex_unlock(&node->pool_lock);
        LOG_WARN("upstream %s:%d pool exhausted", node->host, node->port);
        return NULL;
    }

    node->active_count++;
    pthread_mutex_unlock(&node->pool_lock);

    /* Open new connection outside the lock */
    int fd = node_connect(node, timeout_ms > 0 ? timeout_ms : 2000);
    if (fd < 0) {
        pthread_mutex_lock(&node->pool_lock);
        node->active_count--;
        pthread_mutex_unlock(&node->pool_lock);
        return NULL;
    }

    c = calloc(1, sizeof(upstream_conn_t));
    if (!c) { close(fd); return NULL; }

    c->fd         = fd;
    c->state      = UPSTREAM_CONN_IN_USE;
    c->node       = node;
    c->created_at = time(NULL);
    c->last_used  = c->created_at;
    c->max_streams = 0;   /* HTTP/1.1 — HTTP/2 will set this after ALPN     */

    __atomic_fetch_add(&node->inflight, 1u, __ATOMIC_RELAXED);
    return c;
}

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

int upstream_conn_connect_async(upstream_node_t *node) {
    pthread_spin_lock(&node->state_lock);
    if (!node->addr_resolved) {
        memset(&node->addr, 0, sizeof(node->addr));
        node->addr.sin_family = AF_INET;
        node->addr.sin_port   = htons(node->port);
        if (inet_pton(AF_INET, node->host, &node->addr.sin_addr) != 1) {
            pthread_spin_unlock(&node->state_lock);
            LOG_ERROR("upstream: cannot parse IP '%s'", node->host);
            return -1;
        }
        node->addr_resolved = 1;
    }
    pthread_spin_unlock(&node->state_lock);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd >= 0) {
        net_set_nonblocking(fd);
        fcntl(fd, F_SETFD, FD_CLOEXEC);
    }
    if (fd < 0) return -1;

    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    int ret = connect(fd, (struct sockaddr *)&node->addr, sizeof(node->addr));
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

/* Returns 1 if probe succeeded, 0 if failed */
/* Blocking TLS handshake on an already-connected fd, for TLS upstream
 * health probes. Verification is intentionally disabled (SSL_VERIFY_NONE)
 * -- the same trust model routa's proxy path already uses for upstream
 * connections (see h2_client.c), since upstreams are configured by the
 * operator, not arbitrary internet hosts. Returns a live SSL* on success
 * (caller must SSL_free it), or NULL on failure (fd is left open either
 * way -- caller is responsible for closing it in both cases). */
static SSL *probe_tls_handshake(int fd, const char *hostname, int timeout_ms) {
    SSL_CTX *sctx = SSL_CTX_new(TLS_client_method());
    if (!sctx) return NULL;
    SSL_CTX_set_verify(sctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_mode(sctx, SSL_MODE_ENABLE_PARTIAL_WRITE |
                           SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    SSL *ssl = SSL_new(sctx);
    SSL_CTX_free(sctx); /* SSL* keeps its own reference */
    if (!ssl) return NULL;

    SSL_set_fd(ssl, fd);
    SSL_set_connect_state(ssl);
    SSL_set_tlsext_host_name(ssl, hostname); /* SNI */

    time_t deadline = time(NULL) + (timeout_ms > 0 ? (timeout_ms / 1000 + 1) : 3);
    for (;;) {
        int hret = SSL_do_handshake(ssl);
        if (hret == 1) return ssl;

        int err = SSL_get_error(ssl, hret);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            SSL_free(ssl);
            return NULL;
        }
        if (time(NULL) >= deadline) { SSL_free(ssl); return NULL; }

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int sel = (err == SSL_ERROR_WANT_WRITE)
            ? select(fd + 1, NULL, &fds, NULL, &tv)
            : select(fd + 1, &fds, NULL, NULL, &tv);
        if (sel < 0) { SSL_free(ssl); return NULL; }
        /* sel == 0 (timeout this iteration) just loops back and retries
         * SSL_do_handshake, bounded by the deadline check above. */
    }
}

static int probe_node(upstream_node_t *node) {
    health_check_config_t *hc = &node->hc;

    if (hc->type == HC_NONE) return 1;

    int timeout_ms = hc->timeout_ms > 0 ? hc->timeout_ms : 2000;
    int fd = node_connect(node, timeout_ms);
    if (fd < 0) return 0;

    /* TLS upstream: probes must speak TLS too, or a plaintext GET against
     * a TLS-only port either hangs until timeout or gets a garbage/empty
     * response, both of which look like -- and previously were
     * mis-recorded as -- a failed health check even when the backend is
     * perfectly healthy. */
    SSL *ssl = NULL;
    if (node->use_tls) {
        ssl = probe_tls_handshake(fd, node->host, timeout_ms);
        if (!ssl) { close(fd); return 0; }
    }

    if (hc->type == HC_TCP) {
        /* For a TLS node, reaching here means the handshake above already
         * completed -- that's a stronger, more meaningful liveness signal
         * than a bare TCP connect would be, so no extra check is needed. */
        if (ssl) SSL_free(ssl);
        close(fd);
        return 1;
    }

    /* HC_HTTP or HC_CUSTOM: send GET request */
    const char *path = hc->path[0] ? hc->path : "/health";
    char req[512];
    int  req_len = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
        path, node->host);

    char resp[256];
    memset(resp, 0, sizeof(resp));
    ssize_t n;

    if (ssl) {
        /* Blocking TLS write/read -- the fd itself is still blocking
         * (node_connect only uses non-blocking mode for the initial
         * connect/select), so SSL_write/SSL_read here behave like their
         * plaintext write()/read() counterparts below. */
        int w = SSL_write(ssl, req, req_len);
        if (w != req_len) { SSL_free(ssl); close(fd); return 0; }
        n = SSL_read(ssl, resp, sizeof(resp) - 1);
        SSL_free(ssl);
    } else {
        /* Blocking write — fd is open, timeout handled by select in connect */
        ssize_t w = write(fd, req, (size_t)req_len);
        if (w != req_len) { close(fd); return 0; }

        /* Read response — we only need the status line */
        struct timeval tv = {
            .tv_sec  = timeout_ms / 1000,
            .tv_usec = 0
        };
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        if (select(fd + 1, &rfds, NULL, NULL, &tv) <= 0) {
            close(fd); return 0;
        }
        n = read(fd, resp, sizeof(resp) - 1);
    }
    close(fd);
    if (n <= 0) return 0;

    /* Expect "HTTP/1.x 2xx" */
    if (strncmp(resp, "HTTP/1.", 7) != 0) return 0;
    int status = (int)strtol(resp + 9, NULL, 10);
    if (status < 200 || status >= 300) return 0;

    if (hc->type == HC_CUSTOM) {
        /* Look for {"status":"ok"} anywhere in the body */
        if (!strstr(resp, "\"ok\"") && !strstr(resp, "\"OK\"")) return 0;
    }

    return 1;
}

static void *hc_thread_fn(void *arg) {
    upstream_pool_t *pool = (upstream_pool_t *)arg;

    while (!pool->hc_stop) {
        for (int i = 0; i < pool->node_count; i++) {
            upstream_node_t *node = pool->nodes[i];
            if (node->hc.type == HC_NONE) continue;

            int ok = probe_node(node);

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

        /* Sleep until next probe interval.
         * Use the first node's interval or 5 s default.                    */
        int interval_ms = 5000;
        if (pool->node_count > 0 && pool->nodes[0]->hc.interval_ms > 0)
            interval_ms = pool->nodes[0]->hc.interval_ms;

        struct timespec ts = {
            .tv_sec  = interval_ms / 1000,
            .tv_nsec = (long)(interval_ms % 1000) * 1000000L
        };
        nanosleep(&ts, NULL);
    }
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
