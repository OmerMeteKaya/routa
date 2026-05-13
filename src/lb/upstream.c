#define _GNU_SOURCE
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

/* ── Internal: open a new TCP connection to node ───────────────────────────*/
static int node_connect(upstream_node_t *node, int timeout_ms) {
    /* Resolve once, cache result */
    if (!node->addr_resolved) {
        memset(&node->addr, 0, sizeof(node->addr));
        node->addr.sin_family = AF_INET;
        node->addr.sin_port   = htons(node->port);
        if (inet_pton(AF_INET, node->host, &node->addr.sin_addr) != 1) {
            LOG_ERROR("upstream: cannot parse IP '%s'", node->host);
            return -1;
        }
        node->addr_resolved = 1;
    }

    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
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
        .tv_usec = (timeout_ms % 1000) * 1000,
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

/* ── Passive health tracking ────────────────────────────────────────────────*/

void upstream_node_set_state(upstream_node_t *node, node_state_t state) {
    pthread_spin_lock(&node->state_lock);
    node_state_t old = node->state;
    node->state = state;
    pthread_spin_unlock(&node->state_lock);

    if (old != state) {
        const char *s = state == NODE_UP ? "UP" :
                        state == NODE_DOWN ? "DOWN" : "DRAINING";
        LOG_INFO("upstream %s:%d → %s", node->host, node->port, s);
    }

    if (state == NODE_DOWN)
        upstream_node_drain_idle(node);
}

void upstream_node_record_success(upstream_node_t *node,
                                   upstream_pool_t *pool) {
    node->success_count++;
    node->fail_count = 0;
    node->total_requests++;

    pthread_spin_lock(&node->state_lock);
    node_state_t st = node->state;
    pthread_spin_unlock(&node->state_lock);

    if (st == NODE_DOWN &&
        node->success_count >= (uint32_t)pool->passive_recover_threshold) {
        upstream_node_set_state(node, NODE_UP);
        node->success_count = 0;
    }
}

void upstream_node_record_failure(upstream_node_t *node,
                                   upstream_pool_t *pool) {
    node->fail_count++;
    node->success_count = 0;
    node->total_errors++;
    node->last_fail_time = time(NULL);

    if (node->fail_count >= (uint32_t)pool->passive_fail_threshold) {
        upstream_node_set_state(node, NODE_DOWN);
    }
}

/* ── Active health check ────────────────────────────────────────────────────*/

/* Returns 1 if probe succeeded, 0 if failed */
static int probe_node(upstream_node_t *node) {
    health_check_config_t *hc = &node->hc;

    if (hc->type == HC_NONE) return 1;

    int fd = node_connect(node, hc->timeout_ms > 0 ? hc->timeout_ms : 2000);
    if (fd < 0) return 0;

    if (hc->type == HC_TCP) {
        close(fd);
        return 1;
    }

    /* HC_HTTP or HC_CUSTOM: send GET request */
    const char *path = hc->path[0] ? hc->path : "/health";
    char req[512];
    int  req_len = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
        path, node->host);

    /* Blocking write — fd is open, timeout handled by select in connect */
    ssize_t w = write(fd, req, (size_t)req_len);
    if (w != req_len) { close(fd); return 0; }

    /* Read response — we only need the status line */
    char resp[256];
    memset(resp, 0, sizeof(resp));

    struct timeval tv = {
        .tv_sec  = (hc->timeout_ms > 0 ? hc->timeout_ms : 2000) / 1000,
        .tv_usec = 0
    };
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    if (select(fd + 1, &rfds, NULL, NULL, &tv) <= 0) {
        close(fd); return 0;
    }

    ssize_t n = read(fd, resp, sizeof(resp) - 1);
    close(fd);
    if (n <= 0) return 0;

    /* Expect "HTTP/1.x 2xx" */
    if (strncmp(resp, "HTTP/1.", 7) != 0) return 0;
    int status = 0;
    sscanf(resp + 9, "%d", &status);
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
    free(pool->nodes);
    free(pool->hash_ring);
    free(pool);
}

int upstream_pool_add_node(upstream_pool_t *pool, upstream_node_t *node) {
    upstream_node_t **tmp = realloc(pool->nodes,
        (size_t)(pool->node_count + 1) * sizeof(upstream_node_t *));
    if (!tmp) return -1;
    pool->nodes = tmp;
    pool->nodes[pool->node_count++] = node;
    return 0;
}