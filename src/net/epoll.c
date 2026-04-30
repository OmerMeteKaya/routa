#define _GNU_SOURCE
#include "net/epoll.h"
#include "util/logger.h"
#include <sys/epoll.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int epoll_init(epoll_t *ep) {
    ep->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (ep->epfd < 0) {
        LOG_ERROR("Failed to create epoll: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int epoll_add(epoll_t *ep, int fd, uint32_t events, void *ptr) {
    struct epoll_event ev;
    ev.events = events;
    ev.data.ptr = ptr;
    
    if (epoll_ctl(ep->epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        LOG_ERROR("Failed to add fd to epoll: %s", strerror(errno));
        return -1;
    }
    
    return 0;
}

int epoll_mod(epoll_t *ep, int fd, uint32_t events, void *ptr) {
    struct epoll_event ev;
    ev.events = events;
    ev.data.ptr = ptr;
    
    if (epoll_ctl(ep->epfd, EPOLL_CTL_MOD, fd, &ev) < 0) {
        LOG_ERROR("Failed to modify fd in epoll: %s", strerror(errno));
        return -1;
    }
    
    return 0;
}

int epoll_del(epoll_t *ep, int fd) {
    if (epoll_ctl(ep->epfd, EPOLL_CTL_DEL, fd, NULL) < 0) {
        LOG_ERROR("Failed to delete fd from epoll: %s", strerror(errno));
        return -1;
    }
    
    return 0;
}

int epoll_wait_events(epoll_t *ep, struct epoll_event *evs, int maxevs, int timeout_ms) {
    int nfds = epoll_wait(ep->epfd, evs, maxevs, timeout_ms);
    if (nfds < 0 && errno != EINTR) {
        LOG_ERROR("Epoll wait failed: %s", strerror(errno));
        return -1;
    }
    
    return nfds;
}
