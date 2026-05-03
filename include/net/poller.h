//
// Created by mete on 3.05.2026.
//

#ifndef ROUTA_POLLER_H
#define ROUTA_POLLER_H

#include <stdint.h>

/* Event flags — platform independent */
#define POLLER_READ   0x01
#define POLLER_WRITE  0x02
#define POLLER_ET     0x04   /* edge-triggered */
#define POLLER_HUP    0x08   /* hangup (read-only, set by kernel) */
#define POLLER_ERR    0x10   /* error (read-only, set by kernel) */

typedef struct {
    void    *ptr;    /* user data pointer */
    uint32_t events; /* POLLER_* flags */
} poller_event_t;

typedef struct poller poller_t;

poller_t *poller_new(void);
void      poller_free(poller_t *p);

int  poller_add(poller_t *p, int fd, uint32_t events, void *ptr);
int  poller_mod(poller_t *p, int fd, uint32_t events, void *ptr);
int  poller_del(poller_t *p, int fd);

/* Returns number of events, -1 on error.
   timeout_ms: -1 = infinite, 0 = non-blocking */
int  poller_wait(poller_t *p, poller_event_t *evs, int maxevs, int timeout_ms);

#endif //ROUTA_POLLER_H
