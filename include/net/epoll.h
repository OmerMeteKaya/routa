#ifndef ROUTA_NET_EPOLL_H
#define ROUTA_NET_EPOLL_H

#include <sys/epoll.h>

typedef struct {
    int epfd;
} epoll_t;

int  epoll_init(epoll_t *ep);
int  epoll_add(epoll_t *ep, int fd, uint32_t events, void *ptr);
int  epoll_mod(epoll_t *ep, int fd, uint32_t events, void *ptr);
int  epoll_del(epoll_t *ep, int fd);
int  epoll_wait_events(epoll_t *ep, struct epoll_event *evs, int maxevs, int timeout_ms);

#endif // ROUTA_NET_EPOLL_H
