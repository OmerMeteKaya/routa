#include "http/mw_acl.h"
#include "http/response.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

acl_config_t *acl_config_new(int default_allow) {
    acl_config_t *cfg = calloc(1, sizeof(acl_config_t));
    if (!cfg) return NULL;
    cfg->default_allow = default_allow;
    return cfg;
}

void acl_config_free(acl_config_t *cfg) {
    free(cfg);
}

/* Builds a prefix mask of `bits` set bits (from the MSB) into a
 * `total_bytes`-byte buffer, e.g. bits=8, total_bytes=4 -> ff 00 00 00. */
static void build_prefix_mask(uint8_t *mask, int bits, int total_bytes) {
    memset(mask, 0, (size_t)total_bytes);
    int full_bytes = bits / 8;
    int rem_bits   = bits % 8;
    for (int i = 0; i < full_bytes && i < total_bytes; i++) mask[i] = 0xff;
    if (rem_bits > 0 && full_bytes < total_bytes) {
        mask[full_bytes] = (uint8_t)(0xff << (8 - rem_bits));
    }
}

int acl_config_add_rule(acl_config_t *cfg, const char *rule, acl_action_t action) {
    if (!cfg || !rule) return -1;
    if (cfg->rule_count >= ACL_MAX_RULES) return -1;

    char addr_buf[128];
    int  prefix_bits = -1;

    const char *slash = strchr(rule, '/');
    if (slash) {
        size_t addr_len = (size_t)(slash - rule);
        if (addr_len >= sizeof(addr_buf)) return -1;
        memcpy(addr_buf, rule, addr_len);
        addr_buf[addr_len] = '\0';
        prefix_bits = atoi(slash + 1);
    } else {
        strncpy(addr_buf, rule, sizeof(addr_buf) - 1);
        addr_buf[sizeof(addr_buf) - 1] = '\0';
    }

    acl_rule_t *r = &cfg->rules[cfg->rule_count];
    memset(r, 0, sizeof(*r));
    r->action = action;

    struct in_addr  v4;
    struct in6_addr v6;
    if (inet_pton(AF_INET, addr_buf, &v4) == 1) {
        r->is_v6 = 0;
        memcpy(r->net, &v4, 4);
        if (prefix_bits < 0) prefix_bits = 32;
        if (prefix_bits > 32) return -1;
        build_prefix_mask(r->mask, prefix_bits, 4);
        for (int i = 0; i < 4; i++) r->net[i] &= r->mask[i];
    } else if (inet_pton(AF_INET6, addr_buf, &v6) == 1) {
        r->is_v6 = 1;
        memcpy(r->net, &v6, 16);
        if (prefix_bits < 0) prefix_bits = 128;
        if (prefix_bits > 128) return -1;
        build_prefix_mask(r->mask, prefix_bits, 16);
        for (int i = 0; i < 16; i++) r->net[i] &= r->mask[i];
    } else {
        return -1;   /* not a valid IPv4 or IPv6 address */
    }

    cfg->rule_count++;
    return 0;
}

int acl_check(const acl_config_t *cfg, const char *ip) {
    if (!cfg) return 1;   /* no ACL configured -- allow */
    if (!ip || !ip[0]) return cfg->default_allow;

    struct in_addr  v4;
    struct in6_addr v6;
    int      is_v6 = 0;
    uint8_t  addr[16];
    if (inet_pton(AF_INET, ip, &v4) == 1) {
        is_v6 = 0;
        memcpy(addr, &v4, 4);
    } else if (inet_pton(AF_INET6, ip, &v6) == 1) {
        is_v6 = 1;
        memcpy(addr, &v6, 16);
    } else {
        return cfg->default_allow;  /* unparseable -- fall back to default */
    }

    int addr_bytes = is_v6 ? 16 : 4;
    for (int i = 0; i < cfg->rule_count; i++) {
        const acl_rule_t *r = &cfg->rules[i];
        if (r->is_v6 != is_v6) continue;
        int match = 1;
        for (int b = 0; b < addr_bytes; b++) {
            if ((addr[b] & r->mask[b]) != r->net[b]) { match = 0; break; }
        }
        if (match) return r->action == ACL_ACTION_ALLOW ? 1 : 0;
    }
    return cfg->default_allow;
}

void mw_acl(middleware_chain_t *chain, const http_request_t *req,
           http_response_t *resp, next_fn_t next, void *ctx, int current) {
    const acl_config_t *cfg = (const acl_config_t *)ctx;
    if (!acl_check(cfg, req->remote_ip)) {
        http_response_set_status(resp, 403, "Forbidden");
        http_response_set_header(resp, "Content-Type", "text/plain");
        http_response_set_body(resp, "Forbidden\n", 10);
        return;   /* do not call next() -- request is blocked */
    }
    /* Bug fix: this was "current + 1", but every other middleware in
     * the chain (mw_logger, mw_cors, mw_auth, mw_rate_limit, mw_compress)
     * calls next() with the plain "current" it received, not "current + 1".
     * middleware_next() itself already computes and passes "current + 1"
     * to whichever middleware fn it invokes (see mw->fn(..., current + 1)
     * in middleware.c) -- so by the time mw_acl's own "current" parameter
     * is set, it's already the correct "next index to run" value. Passing
     * "current + 1" here made middleware_next() skip an extra slot beyond
     * that, silently dropping whichever middleware was registered
     * immediately after mw_acl in the chain (e.g. with the default
     * registration order logger -> acl -> cors -> auth -> ratelimit ->
     * compress, this made mw_cors never run whenever ACL was enabled --
     * or mw_compress, if cors/auth/ratelimit were all disabled, as in the
     * config that first surfaced this: gzip compression silently never
     * engaging on any server with acl_enabled=1). */
    next(chain, req, resp, current);
}
