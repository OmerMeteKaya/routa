#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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
#include <ctype.h>

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

/* Thread-safe fast PRNG — xorshift32, no locks needed */
static uint32_t lb_rand(void) {
    static _Atomic uint32_t state = 0x9e3779b9u;
    uint32_t x = atomic_load_explicit(&state, memory_order_relaxed);
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    atomic_store_explicit(&state, x, memory_order_relaxed);
    return x;
}

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

static upstream_node_t *ring_lookup(hash_ring_t *ring, upstream_pool_t *pool, uint32_t hash) {
    if (!ring || ring->count == 0) return NULL;
    int lo = 0, hi = ring->count - 1;
    while (lo < hi) {
        int mid = (lo + hi) / 2;
        if (ring->vnodes[mid].hash < hash) lo = mid + 1;
        else                               hi = mid;
    }
    /* Walk forward to find first selectable node (UP, or a DOWN node
     * winning its half-open trial slot) */
    for (int i = 0; i < ring->count; i++) {
        int idx = (lo + i) % ring->count;
        upstream_node_t *n = ring->vnodes[idx].node;
        if (upstream_node_is_selectable(n, pool)) return n;
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

    int has_tls_upstreams;    /* >0 when any node has use_tls=1             */
};
upstream_pool_t *lb_get_pool(lb_t *lb) {
    return lb ? lb->pool : NULL;
}

int lb_sticky_enabled(const lb_t *lb) {
    return lb ? lb->cfg.sticky_session_enabled : 0;
}

const char *lb_sticky_cookie_name(const lb_t *lb) {
    return (lb && lb->cfg.sticky_cookie_name[0]) ? lb->cfg.sticky_cookie_name : "routa_sticky";
}

void lb_get_upstream_timeouts(const lb_t *lb, int *read_timeout_ms, int *write_timeout_ms) {
    if (read_timeout_ms)  *read_timeout_ms  = lb ? lb->cfg.upstream_read_timeout_ms  : 30000;
    if (write_timeout_ms) *write_timeout_ms = lb ? lb->cfg.upstream_write_timeout_ms : 30000;
}

/* ── Node selection ─────────────────────────────────────────────────────────*/

static upstream_node_t *pick_up_node(upstream_pool_t *pool) {
    for (int i = 0; i < pool->node_count; i++) {
        upstream_node_t *n = pool->nodes[i];
        if (upstream_node_is_selectable(n, pool)) return n;
    }
    return NULL;
}

/* Smooth Weighted Round Robin, nginx-style
 * (ngx_http_upstream_get_peer / ngx_http_upstream_round_robin.c algorithm):
 *
 *   for each UP node n:  n.current_weight += n.weight
 *   pick the node with the highest current_weight
 *   winner.current_weight -= total_weight_of_all_UP_nodes
 *
 * This is a single O(n) pass (accumulate total weight and track the
 * running max in the same loop) and spreads repeated picks of a
 * high-weight node out evenly instead of clustering them -- e.g. weights
 * {5,1,1} produces a sequence like A A B A C A A rather than A A A A A B C,
 * which matters for real traffic smoothing (avoids bursts hitting one
 * backend back-to-back) even though both sequences have the same 5:1:1
 * long-run ratio. current_weight lives on each upstream_node_t and is
 * only ever touched under wrr_lock, so no atomics are needed for it. */
static upstream_node_t *pick_wrr(lb_t *lb) {
    upstream_pool_t *pool = lb->pool;
    if (pool->node_count == 0) return NULL;

    pthread_mutex_lock(&lb->wrr_lock);

    /* Single pass: accumulate total weight of UP nodes, bump each UP
     * node's current_weight, and track the running best candidate.
     * Intentionally UP-only (not is_selectable) -- the weighted math
     * assumes stable pool membership for the duration of this call, which
     * a half-open trial (won via a one-shot CAS) can't provide. A
     * half-open trial for this pool is instead given a dedicated chance
     * below, only when no UP node exists at all. */
    int total_w = 0;
    upstream_node_t *best = NULL;
    int best_cw = 0;
    for (int i = 0; i < pool->node_count; i++) {
        upstream_node_t *n = pool->nodes[i];
        pthread_spin_lock(&n->state_lock);
        node_state_t st = n->state;
        pthread_spin_unlock(&n->state_lock);
        if (st != NODE_UP || n->weight <= 0) continue;

        total_w += n->weight;
        n->current_weight += n->weight;
        if (!best || n->current_weight > best_cw) {
            best = n;
            best_cw = n->current_weight;
        }
    }

    if (!best) {
        /* No UP nodes at all -- this is exactly the situation half-open
         * exists for. Give one DOWN node (if its trial window has
         * elapsed) a chance to prove it's back. */
        for (int i = 0; i < pool->node_count; i++) {
            upstream_node_t *n = pool->nodes[i];
            if (upstream_node_is_selectable(n, pool)) { best = n; break; }
        }
        pthread_mutex_unlock(&lb->wrr_lock);
        return best;
    }

    best->current_weight -= total_w;

    pthread_mutex_unlock(&lb->wrr_lock);
    return best;
}

/* Power of Two Choices */
static upstream_node_t *pick_p2c(lb_t *lb) {
    upstream_pool_t *pool = lb->pool;
    if (pool->node_count == 0) return NULL;
    if (pool->node_count == 1) return pick_up_node(pool);

    /* Collect UP nodes */
    upstream_node_t *up[pool->node_count]; /* NOLINT(cppcheck-allocaCalled) */
    int up_cnt = 0;
    for (int i = 0; i < pool->node_count; i++) {
        upstream_node_t *n = pool->nodes[i];
        pthread_spin_lock(&n->state_lock);
        node_state_t st = n->state;
        pthread_spin_unlock(&n->state_lock);
        if (st == NODE_UP) up[up_cnt++] = n;
    }
    if (up_cnt == 0) {
        /* No UP nodes -- offer a half-open trial instead of failing out. */
        for (int i = 0; i < pool->node_count; i++) {
            upstream_node_t *n = pool->nodes[i];
            if (upstream_node_is_selectable(n, pool)) return n;
        }
        return NULL;
    }
    if (up_cnt == 1) return up[0];

    /* Pick two distinct random candidates */
    int a = (int)(lb_rand() % (uint32_t)up_cnt);
    int b;
    do { b = (int)(lb_rand() % (uint32_t)up_cnt); } while (b == a);

    uint32_t inf_a = __atomic_load_n(&up[a]->inflight, __ATOMIC_RELAXED);
    uint32_t inf_b = __atomic_load_n(&up[b]->inflight, __ATOMIC_RELAXED);
    return inf_a <= inf_b ? up[a] : up[b];
}

/* Sticky-session override, checked BEFORE the configured lb_algo when
 * sticky sessions are enabled. sticky_cookie_value is the raw value of
 * the client's sticky cookie (a stringified node index into pool->nodes[],
 * as set by lb_sticky_cookie_value_for_node()), or NULL if the client
 * sent no such cookie (first visit) -- in which case this falls through
 * to the normal lb_pick_node() algorithm. If the cookie names a node that
 * is no longer UP (removed from config, or currently marked DOWN by
 * health checking), also falls through, rather than pinning the client
 * to a dead backend. */
upstream_node_t *lb_pick_node_sticky(lb_t *lb, const char *client_ip,
                                     const char *sticky_cookie_value) {
    if (lb->cfg.sticky_session_enabled && sticky_cookie_value && sticky_cookie_value[0]) {
        char *end = NULL;
        long idx = strtol(sticky_cookie_value, &end, 10);
        if (end != sticky_cookie_value && *end == '\0' &&
            idx >= 0 && idx < lb->pool->node_count) {
            upstream_node_t *node = lb->pool->nodes[idx];
            pthread_spin_lock(&node->state_lock);
            node_state_t st = node->state;
            pthread_spin_unlock(&node->state_lock);
            if (st == NODE_UP) return node;
            /* Deliberately NOT offering a half-open trial here: sticky
             * pinning to a DOWN node's trial would mean this one client
             * either gets the (likely still-failing) node or, worse,
             * silently steals the pool's only half-open slot on every
             * request while the rest of the pool has no chance to probe
             * recovery at all. Fall through to the normal algorithm
             * instead, same as any other stale/invalid cookie case. */
        }
        /* Cookie present but stale/invalid/node down -- fall through to
         * the normal algorithm, which will pick a live node and (via the
         * caller re-setting the Set-Cookie header) re-stick the client
         * to whatever it picks. */
    }
    return lb_pick_node(lb, client_ip);
}

/* Returns the stringified pool index for node, for use as a sticky
 * cookie value. Returns -1 (as a string via out_buf) if node is not
 * found in lb's pool (shouldn't normally happen). out_buf must be at
 * least 12 bytes. */
void lb_sticky_cookie_value_for_node(lb_t *lb, const upstream_node_t *node,
                                     char *out_buf, size_t out_buf_len) {
    for (int i = 0; i < lb->pool->node_count; i++) {
        if (lb->pool->nodes[i] == node) {
            snprintf(out_buf, out_buf_len, "%d", i);
            return;
        }
    }
    snprintf(out_buf, out_buf_len, "-1");
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
            if (upstream_node_is_selectable(node, pool)) return node;
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
        if (best) return best;
        /* No UP nodes -- offer a half-open trial instead of failing out. */
        for (int i = 0; i < pool->node_count; i++) {
            upstream_node_t *n = pool->nodes[i];
            if (upstream_node_is_selectable(n, pool)) return n;
        }
        return NULL;
    }
    case LB_IP_HASH: {
        if (!client_ip) return pick_up_node(pool);
        uint32_t h = fnv1a(client_ip, strlen(client_ip));
        int n = pool->node_count;
        if (n == 0) return NULL;
        for (int i = 0; i < n; i++) {
            upstream_node_t *node = pool->nodes[(h + (uint32_t)i) % (uint32_t)n];
            if (upstream_node_is_selectable(node, pool)) return node;
        }
        return NULL;
    }
    case LB_RANDOM: {
        /* Fisher-Yates sample */
        int n = pool->node_count;
        if (n == 0) return NULL;
        int start = (int)(lb_rand() % (uint32_t)n);
        for (int i = 0; i < n; i++) {
            upstream_node_t *node = pool->nodes[(start + i) % n];
            if (upstream_node_is_selectable(node, pool)) return node;
        }
        return NULL;
    }
    case LB_P2C:
        return pick_p2c(lb);

    case LB_CONSISTENT_HASH: {
        if (!lb->ring) return pick_up_node(pool);
        const char *key = client_ip ? client_ip : "default";
        uint32_t h = fnv1a(key, strlen(key));
        return ring_lookup(lb->ring, pool, h);
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

/* Hop-by-hop headers that must not cross the proxy (RFC 7230 §6.1) */
static int is_hop_by_hop(const char *name) {
    static const char *hop_by_hop[] = {
        "connection", "keep-alive", "transfer-encoding",
        "proxy-connection", "upgrade", "te", "trailer", NULL
    };
    for (int i = 0; hop_by_hop[i]; i++)
        if (strcasecmp(name, hop_by_hop[i]) == 0) return 1;
    return 0;
}

/* Serialize req into out for the upstream node, heap-backed so large bodies
 * are never truncated.  Rewrites per RFC 7230/7239: strips hop-by-hop
 * headers, rewrites Host to the upstream target, injects X-Forwarded-For,
 * X-Forwarded-Proto (when the frontend scheme is known) and Via.
 * Returns 0 on success, -1 on OOM. */
static int build_forward_request(const http_request_t *req,
                                 const char *client_ip,
                                 const char *proto,
                                 const upstream_node_t *node,
                                 const lb_config_t *cfg,
                                 buf_t *out)
{
#define BFR_PUT(s)            do { if (buf_append_str(out, (s)) < 0) return -1; } while (0)
#define BFR_PUTN(p, n)        do { if (buf_append(out, (p), (n)) < 0) return -1; } while (0)
    static const char *method_str[] = {
        "GET","POST","PUT","DELETE","HEAD",
        "PATCH","OPTIONS","TRACE","CONNECT","UNKNOWN"
    };
    int m = ((int)req->method >= 0 && (int)req->method < 10) ? (int)req->method : 9;

    buf_reset(out);

    /* Request line */
    BFR_PUT(method_str[m]);
    BFR_PUT(" ");
    BFR_PUT(req->path);
    if (req->query && req->query[0]) {
        BFR_PUT("?");
        BFR_PUT(req->query);
    }
    BFR_PUT(" HTTP/1.1\r\n");

    /* Host: rewritten to the upstream target */
    {
        char host[128];
        int n = snprintf(host, sizeof(host), "Host: %s:%d\r\n",
                         node->host, node->port);
        BFR_PUTN(host, (size_t)n);
    }

    /* Forward end-to-end headers; capture existing forwarding chains */
    const char *prev_xff = NULL;
    const char *prev_via = NULL;
    int had_content_length = 0;
    for (int i = 0; i < req->header_count; i++) {
        const char *k = req->headers[i].key;
        const char *v = req->headers[i].value ? req->headers[i].value : "";
        if (!k) continue;
        if (is_hop_by_hop(k))                            continue;
        if (strcasecmp(k, "host") == 0)                  continue;
        if (strcasecmp(k, "x-forwarded-proto") == 0)     continue;
        if (k[0] == ':')                                  continue;
        if (strcasecmp(k, "x-forwarded-for") == 0) { prev_xff = v; continue; }
        if (strcasecmp(k, "via") == 0)             { prev_via = v; continue; }
        if (strcasecmp(k, "content-length") == 0) {
            had_content_length = 1;   /* re-emitted from body_len below */
            continue;
        }
        if (cfg) {
            int removed = 0;
            for (int r = 0; r < cfg->request_header_remove_count; r++) {
                if (strcasecmp(k, cfg->request_header_remove[r]) == 0) { removed = 1; break; }
            }
            if (removed) continue;
        }
        BFR_PUT(k);
        BFR_PUT(": ");
        BFR_PUT(v);
        BFR_PUT("\r\n");
    }
    if (cfg) {
        for (int a = 0; a < cfg->request_header_add_count; a++) {
            BFR_PUT(cfg->request_header_add[a].name);
            BFR_PUT(": ");
            BFR_PUT(cfg->request_header_add[a].value);
            BFR_PUT("\r\n");
        }
    }

    /* X-Forwarded-For: append this client to any existing chain */
    BFR_PUT("X-Forwarded-For: ");
    if (prev_xff && prev_xff[0]) {
        BFR_PUT(prev_xff);
        BFR_PUT(", ");
    }
    BFR_PUT(client_ip && client_ip[0] ? client_ip : "unknown");
    BFR_PUT("\r\n");

    if (proto) {
        BFR_PUT("X-Forwarded-Proto: ");
        BFR_PUT(proto);
        BFR_PUT("\r\n");
    }

    /* Via: append ourselves to any existing chain */
    BFR_PUT("Via: ");
    if (prev_via && prev_via[0]) {
        BFR_PUT(prev_via);
        BFR_PUT(", ");
    }
    BFR_PUT("1.1 routa\r\n");

    /* Body is forwarded decoded, so Content-Length replaces any original
     * framing (including chunked Transfer-Encoding stripped above) */
    if (req->body_len > 0 || had_content_length) {
        char cl[64];
        int n = snprintf(cl, sizeof(cl), "Content-Length: %zu\r\n",
                         req->body_len);
        BFR_PUTN(cl, (size_t)n);
    }

    BFR_PUT("Connection: keep-alive\r\n");
    BFR_PUT("\r\n");

    if (req->body && req->body_len > 0)
        BFR_PUTN(req->body, req->body_len);

    return 0;
#undef BFR_PUT
#undef BFR_PUTN
}

/* ── Lifecycle ───────────────────────────────────────────────────────────────*/

void lb_config_init(lb_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->algo                    = LB_ROUND_ROBIN;
    cfg->pool_max_per_node       = 64;
    cfg->pool_connect_timeout_ms = 2000;
    cfg->upstream_read_timeout_ms = 30000;
    cfg->upstream_write_timeout_ms = 30000;
    cfg->pool_idle_timeout_s     = 60;
    cfg->passive_fail_threshold  = 3;
    cfg->passive_recover_threshold = 2;
    cfg->half_open_retry_after_ms = 30000;
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

    cfg->sticky_session_enabled = 0;
    strncpy(cfg->sticky_cookie_name, "routa_sticky", sizeof(cfg->sticky_cookie_name) - 1);
}

lb_t *lb_new(const lb_config_t *cfg) {
    lb_t *lb = calloc(1, sizeof(lb_t));
    if (!lb) return NULL;

    lb->cfg  = *cfg;
    lb->pool = upstream_pool_new();
    if (!lb->pool) { free(lb); return NULL; }

    lb->pool->passive_fail_threshold    = cfg->passive_fail_threshold;
    lb->pool->passive_recover_threshold = cfg->passive_recover_threshold;
    lb->pool->half_open_retry_after_ms   = cfg->half_open_retry_after_ms;

    pthread_mutex_init(&lb->wrr_lock, NULL);
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

int lb_add_upstream_tls(lb_t *lb, const char *host, uint16_t port, int weight)
{
    upstream_node_t *n = calloc(1, sizeof(upstream_node_t));
    if (!n) return -1;

    strncpy(n->host, host, sizeof(n->host) - 1);
    n->port     = port;
    n->weight   = weight > 0 ? weight : 1;
    n->state    = NODE_UP;
    n->pool_max = lb->cfg.pool_max_per_node;
    n->hc       = lb->cfg.hc;
    n->use_tls  = 1;

    pthread_mutex_init(&n->pool_lock, NULL);
    pthread_spin_init(&n->state_lock, PTHREAD_PROCESS_PRIVATE);

    if (upstream_pool_add_node(lb->pool, n) < 0) {
        pthread_mutex_destroy(&n->pool_lock);
        pthread_spin_destroy(&n->state_lock);
        free(n);
        return -1;
    }

    lb->has_tls_upstreams = 1;
    LOG_INFO("lb: added TLS upstream %s:%d weight=%d", host, port, n->weight);
    return 0;
}

int lb_is_tls_upstream(lb_t *lb)
{
    return lb && lb->has_tls_upstreams;
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

static int begin_forward_on_node(lb_t *lb,
                                  upstream_node_t      *node,
                                  const http_request_t *req,
                                  const char            *client_ip,
                                  const char            *proto,
                                  buf_t                 *req_buf,
                                  upstream_conn_t      **out_uconn)
{

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
        /* Validate: check if peer closed the idle connection              */
        char probe;
        ssize_t rc = recv(fd, &probe, 1, MSG_PEEK | MSG_DONTWAIT);
        if (rc == 0 || (rc < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
            /* Connection closed or errored — discard and open fresh one   */
            upstream_conn_release(uconn, 0);
            uconn = NULL;
        } else {
            __atomic_fetch_add(&node->inflight, 1u, __ATOMIC_RELAXED);
        }
    }

    if (!uconn) {
        pthread_mutex_lock(&node->pool_lock);
        if (node->active_count >= node->pool_max) {
            pthread_mutex_unlock(&node->pool_lock);
            LOG_WARN("lb_begin_forward: pool exhausted %s:%d active=%d max=%d",
            node->host, node->port, node->active_count, node->pool_max);
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

    /* Serialize request straight into the caller's buffer */
    if (build_forward_request(req, client_ip, proto, node, lb ? &lb->cfg : NULL, req_buf) < 0) {
        upstream_conn_release(uconn, 0);
        return -1;
    }

    *out_uconn = uconn;
    return fd;
}

int lb_begin_forward(lb_t *lb,
                     const http_request_t *req,
                     const char           *client_ip,
                     const char           *proto,
                     buf_t                *req_buf,
                     upstream_node_t     **out_node,
                     upstream_conn_t     **out_uconn)
{
    upstream_node_t *node = lb_pick_node(lb, client_ip);
    if (!node) { LOG_WARN("lb_begin_forward: no upstream"); return -1; }

    int fd = begin_forward_on_node(lb, node, req, client_ip, proto,
                                   req_buf, out_uconn);
    if (fd >= 0) *out_node = node;
    return fd;
}

int lb_begin_forward_to_node(lb_t *lb,
                             upstream_node_t      *node,
                             const http_request_t *req,
                             const char            *client_ip,
                             const char            *proto,
                             buf_t                 *req_buf,
                             upstream_conn_t      **out_uconn)
{
    if (!node) return -1;
    return begin_forward_on_node(lb, node, req, client_ip, proto,
                                 req_buf, out_uconn);
}

static ssize_t decode_chunked(const char *src, size_t src_len, char *dst) {
    const char *p   = src;
    const char *end = src + src_len;
    size_t out = 0;
    while (p < end) {
        char *crlf = memmem(p, (size_t)(end - p), "\r\n", 2);
        if (!crlf) break;
        size_t chunk_sz = (size_t)strtoul(p, NULL, 16);
        p = crlf + 2;
        if (chunk_sz == 0) break;
        if (p + chunk_sz > end) chunk_sz = (size_t)(end - p);
        memcpy(dst + out, p, chunk_sz);
        out += chunk_sz;
        p   += chunk_sz;
        if (p + 2 <= end && p[0] == '\r' && p[1] == '\n') p += 2;
    }
    return (ssize_t)out;
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
        memcpy(raw, buf_data(resp_buf), resp_buf->len);
        raw[resp_buf->len] = '\0';

        if (strncmp(raw, "HTTP/1.", 7) != 0) { free(raw); ret = -1; goto done; }

        int status = 0; char reason[64] = {0};
        char *end_ptr; status = (int)strtol(raw + 9, &end_ptr, 10);
        if (end_ptr == raw + 9) { free(raw); ret = -1; goto done; }
        if (*end_ptr == ' ') { strncpy(reason, end_ptr + 1, 63); reason[63] = '\0'; char *cr = strchr(reason, '\r'); if (cr) *cr = '\0'; }
        http_response_set_status(resp, status, reason);

        char *body_start = strstr(raw, "\r\n\r\n");
        if (body_start) {
            char *line = strchr(raw, '\n');
            if (line) line++;
            body_start += 4;

            int is_chunked = 0;
            while (line && line < body_start) {
                char *end = strstr(line, "\r\n");
                if (!end || end == line) break;
                *end = '\0';
                char *colon = strchr(line, ':');
                if (colon) {
                    *colon = '\0';
                    char *val = colon + 1;
                    while (*val == ' ') val++;
                    /* Strip hop-by-hop headers; Content-Length is re-emitted
                     * by http_response_set_body.  Lowercase the name — the
                     * H2 frontend rejects uppercase header field names. */
                    if (!is_hop_by_hop(line) &&
                        strcasecmp(line, "content-length") != 0) {
                        for (char *p = line; *p; p++)
                            *p = (char)tolower((unsigned char)*p);
                        http_response_set_header(resp, line, val);
                    }
                    if (strcasecmp(line, "content-length") == 0) {
                        size_t clen = (size_t)strtoll(val, NULL, 10);
                        size_t blen = resp_buf->len - (size_t)(body_start - raw);
                        size_t use  = clen < blen ? clen : blen;
                        if (use > 0)
                            http_response_set_body(resp, body_start, use);
                    }
                    if (strcasecmp(line, "transfer-encoding") == 0 &&
                        strncasecmp(val, "chunked", 7) == 0)
                        is_chunked = 1;
                }
                *end = '\r';
                line = end + 2;
            }
            if (is_chunked) {
                size_t blen = resp_buf->len - (size_t)(body_start - raw);
                if (blen > 0) {
                    char *dbuf = malloc(blen + 1);
                    if (dbuf) {
                        ssize_t dlen = decode_chunked(body_start, blen, dbuf);
                        if (dlen > 0) {
                            dbuf[dlen] = '\0';
                            http_response_set_body(resp, dbuf, (size_t)dlen);
                        }
                        free(dbuf);
                    }
                }
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
