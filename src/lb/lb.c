#define _GNU_SOURCE
#include "lb/lb.h"
#include "lb/upstream.h"
#include "util/logger.h"
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>
#include <time.h>

/* ── Consistent hash ring ───────────────────────────────────────────────────*/
#define VNODE_MAX (1024 * 8)   /* max total virtual nodes in ring            */

typedef struct {
    uint32_t        hash;
    upstream_node_t *node;
} vnode_t;

typedef struct {
    vnode_t *vnodes;
    int      count;
} hash_ring_t;

/* FNV-1a 32-bit */
static uint32_t fnv1a(const char *s, size_t len) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        h ^= (unsigned char)s[i];
        h *= 16777619u;
    }
    return h;
}

static int vnode_cmp(const void *a, const void *b) {
    uint32_t ha = ((const vnode_t *)a)->hash;
    uint32_t hb = ((const vnode_t *)b)->hash;
    return (ha > hb) - (ha < hb);
}

static hash_ring_t *ring_build(upstream_node_t **nodes, int n, int vnodes_per) {
    hash_ring_t *ring = calloc(1, sizeof(hash_ring_t));
    if (!ring) return NULL;

    int total = n * vnodes_per;
    if (total > VNODE_MAX) total = VNODE_MAX;

    ring->vnodes = malloc((size_t)total * sizeof(vnode_t));
    if (!ring->vnodes) { free(ring); return NULL; }

    int idx = 0;
    for (int i = 0; i < n && idx < total; i++) {
        int per = vnodes_per * nodes[i]->weight;
        if (per < 1) per = 1;
        for (int v = 0; v < per && idx < total; v++, idx++) {
            char key[128];
            int  klen = snprintf(key, sizeof(key), "%s:%d#%d",
                                 nodes[i]->host, nodes[i]->port, v);
            ring->vnodes[idx].hash = fnv1a(key, (size_t)klen);
            ring->vnodes[idx].node = nodes[i];
        }
    }
    ring->count = idx;
    qsort(ring->vnodes, (size_t)ring->count, sizeof(vnode_t), vnode_cmp);
    return ring;
}

static upstream_node_t *ring_lookup(hash_ring_t *ring, uint32_t hash) {
    if (!ring || ring->count == 0) return NULL;
    int lo = 0, hi = ring->count - 1;
    while (lo < hi) {
        int mid = (lo + hi) / 2;
        if (ring->vnodes[mid].hash < hash) lo = mid + 1;
        else                               hi = mid;
    }
    /* Walk forward to find first UP node */
    for (int i = 0; i < ring->count; i++) {
        int idx = (lo + i) % ring->count;
        upstream_node_t *n = ring->vnodes[idx].node;
        pthread_spin_lock(&n->state_lock);
        node_state_t st = n->state;
        pthread_spin_unlock(&n->state_lock);
        if (st == NODE_UP) return n;
    }
    return NULL;
}

/* ── lb_t ───────────────────────────────────────────────────────────────────*/
struct lb {
    lb_config_t      cfg;
    upstream_pool_t *pool;
    hash_ring_t     *ring;    /* non-NULL when algo == LB_CONSISTENT_HASH   */

    /* Weighted RR state */
    pthread_mutex_t  wrr_lock;
    int              wrr_current;
    int              wrr_cw;      /* current weight */

    volatile uint64_t stat_requests;
    volatile uint64_t stat_failed;
    volatile uint64_t stat_retries;
};

/* ── Node selection ─────────────────────────────────────────────────────────*/

static upstream_node_t *pick_up_node(upstream_pool_t *pool) {
    for (int i = 0; i < pool->node_count; i++) {
        upstream_node_t *n = pool->nodes[i];
        pthread_spin_lock(&n->state_lock);
        node_state_t st = n->state;
        pthread_spin_unlock(&n->state_lock);
        if (st == NODE_UP) return n;
    }
    return NULL;
}

/* Smooth Weighted Round Robin (Nginx-style) */
static upstream_node_t *pick_wrr(lb_t *lb) {
    upstream_pool_t *pool = lb->pool;
    if (pool->node_count == 0) return NULL;

    pthread_mutex_lock(&lb->wrr_lock);

    /* Find max weight among UP nodes */
    int max_w = 0;
    for (int i = 0; i < pool->node_count; i++) {
        upstream_node_t *n = pool->nodes[i];
        pthread_spin_lock(&n->state_lock);
        node_state_t st = n->state;
        pthread_spin_unlock(&n->state_lock);
        if (st == NODE_UP && n->weight > max_w) max_w = n->weight;
    }

    upstream_node_t *best = NULL;
    if (max_w == 0) goto done;

    /* Smooth WRR: pick node with highest (effective_weight - current_weight) */
    int total_w = 0;
    for (int i = 0; i < pool->node_count; i++) {
        upstream_node_t *n = pool->nodes[i];
        pthread_spin_lock(&n->state_lock);
        node_state_t st = n->state;
        pthread_spin_unlock(&n->state_lock);
        if (st != NODE_UP) continue;
        total_w += n->weight;
        /* reuse inflight as running current_weight — harmless for WRR */
    }
    /* Simple WRR fallback when weights equal */
    if (total_w == 0) goto done;

    uint32_t rr = __atomic_fetch_add(&pool->rr_counter, 1u, __ATOMIC_RELAXED);
    int target = (int)(rr % (uint32_t)total_w);
    int acc = 0;
    for (int i = 0; i < pool->node_count; i++) {
        upstream_node_t *n = pool->nodes[i];
        pthread_spin_lock(&n->state_lock);
        node_state_t st = n->state;
        pthread_spin_unlock(&n->state_lock);
        if (st != NODE_UP) continue;
        acc += n->weight;
        if (target < acc) { best = n; break; }
    }

done:
    pthread_mutex_unlock(&lb->wrr_lock);
    return best;
}

/* Power of Two Choices */
static upstream_node_t *pick_p2c(lb_t *lb) {
    upstream_pool_t *pool = lb->pool;
    if (pool->node_count == 0) return NULL;
    if (pool->node_count == 1) return pick_up_node(pool);

    /* Collect UP nodes */
    upstream_node_t **up = alloca((size_t)pool->node_count *
                                   sizeof(upstream_node_t *));
    int up_cnt = 0;
    for (int i = 0; i < pool->node_count; i++) {
        upstream_node_t *n = pool->nodes[i];
        pthread_spin_lock(&n->state_lock);
        node_state_t st = n->state;
        pthread_spin_unlock(&n->state_lock);
        if (st == NODE_UP) up[up_cnt++] = n;
    }
    if (up_cnt == 0) return NULL;
    if (up_cnt == 1) return up[0];

    /* Pick two distinct random candidates */
    int a = (int)((uint32_t)rand() % (uint32_t)up_cnt);
    int b;
    do { b = (int)((uint32_t)rand() % (uint32_t)up_cnt); } while (b == a);

    uint32_t inf_a = __atomic_load_n(&up[a]->inflight, __ATOMIC_RELAXED);
    uint32_t inf_b = __atomic_load_n(&up[b]->inflight, __ATOMIC_RELAXED);
    return inf_a <= inf_b ? up[a] : up[b];
}

upstream_node_t *lb_pick_node(lb_t *lb, const char *client_ip) {
    upstream_pool_t *pool = lb->pool;

    switch (lb->cfg.algo) {
    case LB_ROUND_ROBIN: {
        uint32_t rr = __atomic_fetch_add(&pool->rr_counter, 1u, __ATOMIC_RELAXED);
        int n = pool->node_count;
        if (n == 0) return NULL;
        for (int i = 0; i < n; i++) {
            upstream_node_t *node = pool->nodes[(rr + (uint32_t)i) % (uint32_t)n];
            pthread_spin_lock(&node->state_lock);
            node_state_t st = node->state;
            pthread_spin_unlock(&node->state_lock);
            if (st == NODE_UP) return node;
        }
        return NULL;
    }
    case LB_WEIGHTED_RR:
        return pick_wrr(lb);

    case LB_LEAST_CONN: {
        upstream_node_t *best = NULL;
        uint32_t min_inf = UINT32_MAX;
        for (int i = 0; i < pool->node_count; i++) {
            upstream_node_t *n = pool->nodes[i];
            pthread_spin_lock(&n->state_lock);
            node_state_t st = n->state;
            pthread_spin_unlock(&n->state_lock);
            if (st != NODE_UP) continue;
            uint32_t inf = __atomic_load_n(&n->inflight, __ATOMIC_RELAXED);
            if (inf < min_inf) { min_inf = inf; best = n; }
        }
        return best;
    }
    case LB_IP_HASH: {
        if (!client_ip) return pick_up_node(pool);
        uint32_t h = fnv1a(client_ip, strlen(client_ip));
        int n = pool->node_count;
        if (n == 0) return NULL;
        for (int i = 0; i < n; i++) {
            upstream_node_t *node = pool->nodes[(h + (uint32_t)i) % (uint32_t)n];
            pthread_spin_lock(&node->state_lock);
            node_state_t st = node->state;
            pthread_spin_unlock(&node->state_lock);
            if (st == NODE_UP) return node;
        }
        return NULL;
    }
    case LB_RANDOM: {
        /* Fisher-Yates sample */
        int n = pool->node_count;
        if (n == 0) return NULL;
        int start = (int)((uint32_t)rand() % (uint32_t)n);
        for (int i = 0; i < n; i++) {
            upstream_node_t *node = pool->nodes[(start + i) % n];
            pthread_spin_lock(&node->state_lock);
            node_state_t st = node->state;
            pthread_spin_unlock(&node->state_lock);
            if (st == NODE_UP) return node;
        }
        return NULL;
    }
    case LB_P2C:
        return pick_p2c(lb);

    case LB_CONSISTENT_HASH: {
        if (!lb->ring) return pick_up_node(pool);
        const char *key = client_ip ? client_ip : "default";
        uint32_t h = fnv1a(key, strlen(key));
        return ring_lookup(lb->ring, h);
    }
    default:
        return pick_up_node(pool);
    }
}

/* ── Request forwarding ─────────────────────────────────────────────────────
 *
 * Minimal HTTP/1.1 forward:
 *   1. Serialize incoming request
 *   2. Send to upstream over pooled conn
 *   3. Read status line + headers into resp
 *   4. Read body
 *
 * This is synchronous/blocking on the upstream fd.  When io_uring or async
 * upstream is added later, replace the read/write calls here — lb_forward's
 * interface stays the same.
 * -------------------------------------------------------------------------*/

/* Build a forwarded request buffer */
static int build_forward_request(const http_request_t *req,
                                  char *buf, size_t bufsz) {
    static const char *method_str[] = {
        "GET","POST","PUT","DELETE","HEAD",
        "PATCH","OPTIONS","TRACE","CONNECT","UNKNOWN"
    };
    int m = (req->method >= 0 && req->method < 10) ? req->method : 9;

    int n = snprintf(buf, bufsz, "%s %s HTTP/1.1\r\n",
                     method_str[m], req->path);

    /* Forward original headers, skip Connection and Host (rewritten below) */
    for (int i = 0; i < req->header_count && n < (int)bufsz - 4; i++) {
        if (!req->headers[i].key) continue;
        if (strcasecmp(req->headers[i].key, "connection") == 0) continue;
        if (strcasecmp(req->headers[i].key, "host") == 0)       continue;
        n += snprintf(buf + n, bufsz - (size_t)n,
                      "%s: %s\r\n",
                      req->headers[i].key,
                      req->headers[i].value ? req->headers[i].value : "");
    }

    n += snprintf(buf + n, bufsz - (size_t)n, "Connection: close\r\n");
    n += snprintf(buf + n, bufsz - (size_t)n, "\r\n");

    /* Append body if any */
    if (req->body && req->body_len > 0 &&
        (size_t)n + req->body_len < bufsz) {
        memcpy(buf + n, req->body, req->body_len);
        n += (int)req->body_len;
    }
    return n;
}

/* Read full HTTP response from upstream fd into resp */
static int read_upstream_response(int fd, http_response_t *resp) {
    char raw[65536];
    size_t total = 0;

    /* Read until we see end of headers or buffer full */
    while (total < sizeof(raw) - 1) {
        ssize_t n = read(fd, raw + total, sizeof(raw) - 1 - total);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return -1;
        }
        if (n == 0) break;
        total += (size_t)n;
        /* Stop after headers for now */
        if (memmem(raw, total, "\r\n\r\n", 4)) break;
    }
    raw[total] = '\0';

    /* Parse status line */
    if (strncmp(raw, "HTTP/1.", 7) != 0) return -1;
    int status = 0;
    char reason[64] = {0};
    sscanf(raw + 9, "%d %63[^\r]", &status, reason);
    http_response_set_status(resp, status, reason);

    /* Parse headers */
    char *hdr_start = strchr(raw, '\n');
    if (!hdr_start) return -1;
    hdr_start++;

    char *body_start = strstr(raw, "\r\n\r\n");
    size_t body_so_far = 0;
    if (body_start) {
        body_start += 4;
        body_so_far = total - (size_t)(body_start - raw);
    }

    char *line = hdr_start;
    while (line && line < (body_start ? body_start : raw + total)) {
        char *end = strstr(line, "\r\n");
        if (!end || end == line) break;
        *end = '\0';

        char *colon = strchr(line, ':');
        if (colon) {
            *colon = '\0';
            char *val = colon + 1;
            while (*val == ' ') val++;
            http_response_set_header(resp, line, val);

            /* Content-Length → read body */
            if (strcasecmp(line, "content-length") == 0) {
                size_t clen = (size_t)atoll(val);
                char  *body = malloc(clen + 1);
                if (body) {
                    if (body_so_far > 0)
                        memcpy(body, body_start, body_so_far);

                    size_t rem = clen - body_so_far;
                    size_t got = body_so_far;
                    while (rem > 0) {
                        ssize_t n = read(fd, body + got, rem);
                        if (n <= 0) break;
                        got += (size_t)n;
                        rem -= (size_t)n;
                    }
                    body[got] = '\0';
                    http_response_set_body(resp, body, got);
                    free(body);
                }
            }
        }
        *end = '\r';
        line = end + 2;
    }
    return 0;
}

int lb_forward(lb_t *lb,
               const http_request_t *req,
               http_response_t      *resp,
               const char           *client_ip)
{
    __atomic_fetch_add(&lb->stat_requests, 1u, __ATOMIC_RELAXED);

    int max_tries = 1 + (lb->cfg.max_retries > 0 ? lb->cfg.max_retries : 0);

    for (int attempt = 0; attempt < max_tries; attempt++) {
        if (attempt > 0) __atomic_fetch_add(&lb->stat_retries, 1u, __ATOMIC_RELAXED);

        upstream_node_t *node = lb_pick_node(lb, client_ip);
        if (!node) {
            LOG_WARN("lb: no upstream available");
            break;
        }

        upstream_conn_t *conn = upstream_conn_acquire(
            node, lb->cfg.pool_connect_timeout_ms);
        if (!conn) {
            upstream_node_record_failure(node, lb->pool);
            continue;
        }

        /* Build and send request */
        char req_buf[65536];
        int  req_len = build_forward_request(req, req_buf, sizeof(req_buf));
        if (req_len <= 0) {
            upstream_conn_release(conn, 0);
            continue;
        }

        ssize_t w = write(conn->fd, req_buf, (size_t)req_len);
        if (w != req_len) {
            upstream_conn_release(conn, 0);
            upstream_node_record_failure(node, lb->pool);
            continue;
        }

        int ret = read_upstream_response(conn->fd, resp);
        if (ret < 0) {
            upstream_conn_release(conn, 0);
            upstream_node_record_failure(node, lb->pool);
            continue;
        }

        /* Success */
        int is_5xx = (resp->status >= 500);
        int conn_ok = !is_5xx || !lb->cfg.retry_on_5xx;
        upstream_conn_release(conn, conn_ok);

        if (is_5xx && lb->cfg.retry_on_5xx && attempt < max_tries - 1) {
            http_response_destroy(resp);
            http_response_init(resp);
            continue;
        }

        upstream_node_record_success(node, lb->pool);
        return 0;
    }

    __atomic_fetch_add(&lb->stat_failed, 1u, __ATOMIC_RELAXED);
    http_response_set_status(resp, 502, "Bad Gateway");
    http_response_set_body(resp, "Bad Gateway\n", 12);
    return -1;
}

/* ── Lifecycle ───────────────────────────────────────────────────────────────*/

void lb_config_init(lb_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->algo                    = LB_ROUND_ROBIN;
    cfg->pool_max_per_node       = 64;
    cfg->pool_connect_timeout_ms = 2000;
    cfg->pool_idle_timeout_s     = 60;
    cfg->passive_fail_threshold  = 3;
    cfg->passive_recover_threshold = 2;
    cfg->max_retries             = 1;
    cfg->retry_on_connect_fail   = 1;
    cfg->retry_on_5xx            = 0;
    cfg->consistent_hash_vnodes  = 150;
    cfg->hc.type                 = HC_NONE;
    cfg->hc.path[0]              = '\0';
    cfg->hc.interval_ms          = 5000;
    cfg->hc.timeout_ms           = 2000;
    cfg->hc.threshold_up         = 2;
    cfg->hc.threshold_down       = 3;
}

lb_t *lb_new(const lb_config_t *cfg) {
    lb_t *lb = calloc(1, sizeof(lb_t));
    if (!lb) return NULL;

    lb->cfg  = *cfg;
    lb->pool = upstream_pool_new();
    if (!lb->pool) { free(lb); return NULL; }

    lb->pool->passive_fail_threshold    = cfg->passive_fail_threshold;
    lb->pool->passive_recover_threshold = cfg->passive_recover_threshold;

    pthread_mutex_init(&lb->wrr_lock, NULL);
    srand((unsigned)time(NULL));
    return lb;
}

int lb_add_upstream(lb_t *lb, const char *host, uint16_t port, int weight) {
    upstream_node_t *n = calloc(1, sizeof(upstream_node_t));
    if (!n) return -1;

    strncpy(n->host, host, sizeof(n->host) - 1);
    n->port     = port;
    n->weight   = weight > 0 ? weight : 1;
    n->state    = NODE_UP;
    n->pool_max = lb->cfg.pool_max_per_node;
    n->hc       = lb->cfg.hc;   /* inherit global hc config */

    pthread_mutex_init(&n->pool_lock, NULL);
    pthread_spin_init(&n->state_lock, PTHREAD_PROCESS_PRIVATE);

    if (upstream_pool_add_node(lb->pool, n) < 0) {
        pthread_mutex_destroy(&n->pool_lock);
        pthread_spin_destroy(&n->state_lock);
        free(n);
        return -1;
    }

    LOG_INFO("lb: added upstream %s:%d weight=%d", host, port, n->weight);
    return 0;
}

int lb_start(lb_t *lb) {
    /* Build consistent hash ring if needed */
    if (lb->cfg.algo == LB_CONSISTENT_HASH) {
        lb->ring = ring_build(lb->pool->nodes, lb->pool->node_count,
                              lb->cfg.consistent_hash_vnodes);
        if (!lb->ring) {
            LOG_ERROR("lb: failed to build hash ring");
            return -1;
        }
    }

    /* Start health check thread only if active HC configured */
    int need_hc = 0;
    for (int i = 0; i < lb->pool->node_count; i++)
        if (lb->pool->nodes[i]->hc.type != HC_NONE) { need_hc = 1; break; }

    if (need_hc) {
        if (upstream_pool_hc_start(lb->pool) != 0) {
            LOG_ERROR("lb: failed to start health check thread");
            return -1;
        }
        LOG_INFO("lb: health check thread started");
    }

    LOG_INFO("lb: started, algo=%d, nodes=%d",
             lb->cfg.algo, lb->pool->node_count);
    return 0;
}

void lb_stop(lb_t *lb) {
    upstream_pool_hc_stop(lb->pool);
}

void lb_free(lb_t *lb) {
    if (!lb) return;
    lb_stop(lb);
    upstream_pool_free(lb->pool);
    if (lb->ring) {
        hash_ring_t *r = lb->ring;
        free(r->vnodes);
        free(r);
    }
    pthread_mutex_destroy(&lb->wrr_lock);
    free(lb);
}

/* ── Async forwarding ───────────────────────────────────────────────────────*/

int lb_begin_forward(lb_t *lb,
                     const http_request_t *req,
                     const char           *client_ip,
                     buf_t                *req_buf,
                     upstream_node_t     **out_node,
                     upstream_conn_t     **out_uconn)
{
    upstream_node_t *node = lb_pick_node(lb, client_ip);
    if (!node) { LOG_WARN("lb_begin_forward: no upstream"); return -1; }

    /* Try idle pooled connection first */
    upstream_conn_t *uconn = NULL;
    pthread_mutex_lock(&node->pool_lock);
    if (node->idle_conns) {
        uconn            = node->idle_conns;
        node->idle_conns = uconn->next;
        node->idle_count--;
        node->active_count++;
        uconn->next  = NULL;
        uconn->state = UPSTREAM_CONN_IN_USE;
    }
    pthread_mutex_unlock(&node->pool_lock);

    int fd;
    if (uconn) {
        fd = uconn->fd;
        __atomic_fetch_add(&node->inflight, 1u, __ATOMIC_RELAXED);
    } else {
        pthread_mutex_lock(&node->pool_lock);
        if (node->active_count >= node->pool_max) {
            pthread_mutex_unlock(&node->pool_lock);
            LOG_WARN("lb_begin_forward: pool exhausted %s:%d", node->host, node->port);
            return -1;
        }
        node->active_count++;
        pthread_mutex_unlock(&node->pool_lock);

        fd = upstream_conn_connect_async(node);
        if (fd < 0) {
            pthread_mutex_lock(&node->pool_lock);
            node->active_count--;
            pthread_mutex_unlock(&node->pool_lock);
            upstream_node_record_failure(node, lb->pool);
            return -1;
        }

        uconn = calloc(1, sizeof(upstream_conn_t));
        if (!uconn) { close(fd); return -1; }
        uconn->fd         = fd;
        uconn->state      = UPSTREAM_CONN_IN_USE;
        uconn->node       = node;
        uconn->created_at = time(NULL);
        uconn->last_used  = uconn->created_at;
        __atomic_fetch_add(&node->inflight, 1u, __ATOMIC_RELAXED);
    }

    /* Serialize request */
    char tmp[65536];
    int  len = build_forward_request(req, tmp, sizeof(tmp));
    if (len <= 0) { upstream_conn_release(uconn, 0); return -1; }
    buf_reset(req_buf);
    if (buf_append(req_buf, tmp, (size_t)len) < 0) {
        upstream_conn_release(uconn, 0); return -1;
    }

    *out_node  = node;
    *out_uconn = uconn;
    return fd;
}

int lb_finish_forward(lb_t            *lb,
                      buf_t           *resp_buf,
                      http_response_t *resp,
                      upstream_node_t *node,
                      upstream_conn_t *uconn,
                      int              healthy)
{
    int ret = 0;
    if (resp_buf->len == 0) { ret = -1; goto done; }

    {
        char *raw = malloc(resp_buf->len + 1);
        if (!raw) { ret = -1; goto done; }
        memcpy(raw, resp_buf->data, resp_buf->len);
        raw[resp_buf->len] = '\0';

        if (strncmp(raw, "HTTP/1.", 7) != 0) { free(raw); ret = -1; goto done; }

        int status = 0; char reason[64] = {0};
        sscanf(raw + 9, "%d %63[^\r]", &status, reason);
        http_response_set_status(resp, status, reason);

        char *body_start = strstr(raw, "\r\n\r\n");
        if (body_start) {
            char *line = strchr(raw, '\n');
            if (line) line++;
            body_start += 4;

            while (line && line < body_start) {
                char *end = strstr(line, "\r\n");
                if (!end || end == line) break;
                *end = '\0';
                char *colon = strchr(line, ':');
                if (colon) {
                    *colon = '\0';
                    char *val = colon + 1;
                    while (*val == ' ') val++;
                    http_response_set_header(resp, line, val);
                    if (strcasecmp(line, "content-length") == 0) {
                        size_t clen = (size_t)atoll(val);
                        size_t blen = resp_buf->len - (size_t)(body_start - raw);
                        size_t use  = clen < blen ? clen : blen;
                        if (use > 0)
                            http_response_set_body(resp, body_start, use);
                    }
                }
                *end = '\r';
                line = end + 2;
            }
        }
        free(raw);
    }

done:
    upstream_conn_release(uconn, healthy && ret == 0);
    if (ret == 0) upstream_node_record_success(node, lb->pool);
    else          upstream_node_record_failure(node, lb->pool);
    (void)lb;
    return ret;
}

lb_stats_t lb_get_stats(const lb_t *lb) {
    const volatile uint64_t *req = &lb->stat_requests;
    const volatile uint64_t *fail = &lb->stat_failed;
    const volatile uint64_t *ret  = &lb->stat_retries;
    lb_stats_t s = {
        .requests_total  = __atomic_load_n(req,  __ATOMIC_RELAXED),
        .requests_failed = __atomic_load_n(fail, __ATOMIC_RELAXED),
        .retries         = __atomic_load_n(ret,  __ATOMIC_RELAXED),
    };
    return s;
}