#ifndef ROUTA_HTTP_MW_ACL_H
#define ROUTA_HTTP_MW_ACL_H
#include "http/middleware.h"
#include "http/request.h"
#include "http/response.h"

/* IPv4/IPv6 CIDR-based access control list. Rules are checked in the
 * order added; the first matching rule wins. If no rule matches,
 * default_allow decides the outcome. */

typedef enum {
    ACL_ACTION_ALLOW = 0,
    ACL_ACTION_DENY  = 1,
} acl_action_t;

typedef struct {
    acl_action_t action;
    /* Stored pre-parsed for fast matching: IPv4 as a 32-bit net/mask
     * pair, or IPv6 as a 128-bit net/mask pair. is_v6 selects which. */
    int      is_v6;
    uint8_t  net[16];   /* network address, first 4 or 16 bytes used  */
    uint8_t  mask[16];  /* prefix mask, same length as net             */
} acl_rule_t;

#define ACL_MAX_RULES 64

typedef struct {
    acl_rule_t rules[ACL_MAX_RULES];
    int        rule_count;
    int        default_allow;   /* 1 = allow, 0 = deny, when no rule matches */
} acl_config_t;

acl_config_t *acl_config_new(int default_allow);
void          acl_config_free(acl_config_t *cfg);

/* rule: "IP" or "IP/PREFIX" (e.g. "10.0.0.0/8", "192.168.1.100",
 * "2001:db8::/32"). Returns 0 on success, -1 on parse failure. */
int acl_config_add_rule(acl_config_t *cfg, const char *rule, acl_action_t action);

/* Returns 1 if ip is allowed, 0 if denied. */
int acl_check(const acl_config_t *cfg, const char *ip);

/* Middleware entry point -- ctx: acl_config_t* */
void mw_acl(middleware_chain_t *chain, const http_request_t *req,
           http_response_t *resp, next_fn_t next, void *ctx, int current);

#endif /* ROUTA_HTTP_MW_ACL_H */
