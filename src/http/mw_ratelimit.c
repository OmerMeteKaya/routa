#define _GNU_SOURCE
#include "http/mw_ratelimit.h"
#include "http/response.h"
#include "util/logger.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#define BUCKET_COUNT 256
#define MAX_AGE 60

typedef struct bucket_entry {
    char ip[46];
    double tokens;
    time_t last_refill;
    struct bucket_entry *next;
} bucket_entry_t;

typedef struct {
    bucket_entry_t *buckets[BUCKET_COUNT];
    pthread_mutex_t mutexes[BUCKET_COUNT];
} rate_limiter_t;

static rate_limiter_t g_limiter;

static unsigned int hash_ip(const char *ip) {
    unsigned int hash = 5381;
    unsigned char c;
    while ((c = (unsigned char)*ip++))
        hash = ((hash << 5u) + hash) + c;
    return hash % BUCKET_COUNT;
}

static void init_rate_limiter(void) {
    static int initialized = 0;
    if (initialized) return;
    
    for (int i = 0; i < BUCKET_COUNT; i++) {
        pthread_mutex_init(&g_limiter.mutexes[i], NULL);
        g_limiter.buckets[i] = NULL;
    }
    initialized = 1;
}

rate_limit_config_t *mw_rate_limit_config_new(int rps, int burst) {
    init_rate_limiter();
    
    rate_limit_config_t *cfg = calloc(1, sizeof(rate_limit_config_t));
    if (!cfg) return NULL;
    
    cfg->requests_per_second = rps;
    cfg->burst = burst;
    return cfg;
}

void mw_rate_limit_config_free(rate_limit_config_t *cfg) {
    free(cfg);
}

void mw_rate_limit(middleware_chain_t *chain, const http_request_t *req,
                   http_response_t *resp, next_fn_t next, void *ctx) {
    rate_limit_config_t *cfg = (rate_limit_config_t *)ctx;
    
    // For simplicity, we'll use a dummy IP if not available
    const char *client_ip = "127.0.0.1"; // In real implementation, this would come from conn
    
    unsigned int bucket_idx = hash_ip(client_ip);
    bucket_entry_t *entry = NULL;
    time_t now = time(NULL);
    
    pthread_mutex_lock(&g_limiter.mutexes[bucket_idx]);
    
    /* Look for existing entry, evict stale ones */
    bucket_entry_t **prev = &g_limiter.buckets[bucket_idx];
    while (*prev) {
        bucket_entry_t *cur = *prev;
        if (now - cur->last_refill > MAX_AGE) {
            *prev = cur->next;
            free(cur);
            continue;   /* prev stays, check new *prev */
        }
        if (strcmp(cur->ip, client_ip) == 0) {
            double elapsed = (double)(now - cur->last_refill);
            double refill  = elapsed * (double)cfg->requests_per_second;
            cur->tokens    = (cur->tokens + refill > (double)cfg->burst)
                             ? (double)cfg->burst
                             : cur->tokens + refill;
            cur->last_refill = now;

            if (cur->tokens >= 1.0) {
                cur->tokens -= 1.0;
                pthread_mutex_unlock(&g_limiter.mutexes[bucket_idx]);
                next(chain, req, resp);
                return;
            } else {
                pthread_mutex_unlock(&g_limiter.mutexes[bucket_idx]);
                http_response_set_status(resp, 429, "Too Many Requests");
                http_response_set_header(resp, "Content-Type", "text/plain");
                http_response_set_body(resp, "Too Many Requests\n", 19);
                return;
            }
        }
        prev = &cur->next;
    }
    
    // Create new entry
    entry = calloc(1, sizeof(bucket_entry_t));
    if (entry) {
        strncpy(entry->ip, client_ip, sizeof(entry->ip) - 1);
        entry->ip[sizeof(entry->ip) - 1] = '\0';
        entry->tokens = cfg->burst - 1.0;
        entry->last_refill = now;
        entry->next = g_limiter.buckets[bucket_idx];
        g_limiter.buckets[bucket_idx] = entry;
        pthread_mutex_unlock(&g_limiter.mutexes[bucket_idx]);
        next(chain, req, resp);
        return;
    }
    
    pthread_mutex_unlock(&g_limiter.mutexes[bucket_idx]);
    next(chain, req, resp);
}
