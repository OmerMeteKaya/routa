//
// Created by mete on 3.05.2026.
//

#if defined(__linux__)
#define _GNU_SOURCE
#endif

#include "net/poller.h"
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

/* ================================================================
 * Linux — epoll
 * ================================================================ */
#if defined(__linux__)

#include <sys/epoll.h>

struct poller {
    int epfd;
};

poller_t *poller_new(void) {
    poller_t *p = calloc(1, sizeof(poller_t));
    if (!p) return NULL;
    p->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (p->epfd < 0) { free(p); return NULL; }
    return p;
}

void poller_free(poller_t *p) {
    if (!p) return;
    close(p->epfd);
    free(p);
}

static uint32_t to_epoll(uint32_t flags) {
    uint32_t ev = 0;
    if (flags & POLLER_READ)  ev |= EPOLLIN;
    if (flags & POLLER_WRITE) ev |= EPOLLOUT;
    if (flags & POLLER_ET)    ev |= EPOLLET;
    return ev;
}

static uint32_t from_epoll(uint32_t ev) {
    uint32_t flags = 0;
    if (ev & EPOLLIN)  flags |= POLLER_READ;
    if (ev & EPOLLOUT) flags |= POLLER_WRITE;
    if (ev & EPOLLHUP) flags |= POLLER_HUP;
    if (ev & EPOLLERR) flags |= POLLER_ERR;
    return flags;
}

int poller_add(poller_t *p, int fd, uint32_t events, void *ptr) {
    struct epoll_event ev;
    ev.events   = to_epoll(events);
    ev.data.ptr = ptr;
    return epoll_ctl(p->epfd, EPOLL_CTL_ADD, fd, &ev);
}

int poller_mod(poller_t *p, int fd, uint32_t events, void *ptr) {
    struct epoll_event ev;
    ev.events   = to_epoll(events);
    ev.data.ptr = ptr;
    return epoll_ctl(p->epfd, EPOLL_CTL_MOD, fd, &ev);
}

int poller_del(poller_t *p, int fd) {
    return epoll_ctl(p->epfd, EPOLL_CTL_DEL, fd, NULL);
}

int poller_wait(poller_t *p, poller_event_t *evs, int maxevs, int timeout_ms) {
    struct epoll_event raw[1024];
    int cap = maxevs < 1024 ? maxevs : 1024;
    int n = epoll_wait(p->epfd, raw, cap, timeout_ms);
    if (n < 0) return (errno == EINTR) ? 0 : -1;
    for (int i = 0; i < n; i++) {
        evs[i].ptr    = raw[i].data.ptr;
        evs[i].events = from_epoll(raw[i].events);
    }
    return n;
}

/* ================================================================
 * BSD / macOS — kqueue
 * ================================================================ */
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || \
      defined(__NetBSD__)  || defined(__APPLE__)

#include <sys/event.h>
#include <sys/time.h>

struct poller {
    int kqfd;
};

poller_t *poller_new(void) {
    poller_t *p = calloc(1, sizeof(poller_t));
    if (!p) return NULL;
    p->kqfd = kqueue();
    if (p->kqfd < 0) { free(p); return NULL; }
    return p;
}

void poller_free(poller_t *p) {
    if (!p) return;
    close(p->kqfd);
    free(p);
}

int poller_add(poller_t *p, int fd, uint32_t events, void *ptr) {
    struct kevent changes[2];
    int n = 0;
    unsigned short flags = EV_ADD | ((events & POLLER_ET) ? EV_CLEAR : 0);
    if (events & POLLER_READ)
        EV_SET(&changes[n++], (uintptr_t)fd, EVFILT_READ,  flags, 0, 0, ptr);
    if (events & POLLER_WRITE)
        EV_SET(&changes[n++], (uintptr_t)fd, EVFILT_WRITE, flags, 0, 0, ptr);
    if (n == 0) return 0;
    return kevent(p->kqfd, changes, n, NULL, 0, NULL) < 0 ? -1 : 0;
}

int poller_mod(poller_t *p, int fd, uint32_t events, void *ptr) {
    struct kevent changes[4];
    int n = 0;
    /* Delete both filters first, ignore errors (filter may not exist) */
    EV_SET(&changes[n++], (uintptr_t)fd, EVFILT_READ,  EV_DELETE, 0, 0, NULL);
    EV_SET(&changes[n++], (uintptr_t)fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
    unsigned short flags = EV_ADD | ((events & POLLER_ET) ? EV_CLEAR : 0);
    if (events & POLLER_READ)
        EV_SET(&changes[n++], (uintptr_t)fd, EVFILT_READ,  flags, 0, 0, ptr);
    if (events & POLLER_WRITE)
        EV_SET(&changes[n++], (uintptr_t)fd, EVFILT_WRITE, flags, 0, 0, ptr);
    kevent(p->kqfd, changes, n, NULL, 0, NULL);
    return 0;
}

int poller_del(poller_t *p, int fd) {
    struct kevent changes[2];
    EV_SET(&changes[0], (uintptr_t)fd, EVFILT_READ,  EV_DELETE, 0, 0, NULL);
    EV_SET(&changes[1], (uintptr_t)fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
    kevent(p->kqfd, changes, 2, NULL, 0, NULL);
    return 0;
}

int poller_wait(poller_t *p, poller_event_t *evs, int maxevs, int timeout_ms) {
    struct kevent raw[1024];
    int cap = maxevs < 1024 ? maxevs : 1024;
    struct timespec ts, *tsp = NULL;
    if (timeout_ms >= 0) {
        ts.tv_sec  = timeout_ms / 1000;
        ts.tv_nsec = (long)(timeout_ms % 1000) * 1000000L;
        tsp = &ts;
    }
    int n = kevent(p->kqfd, NULL, 0, raw, cap, tsp);
    if (n < 0) return (errno == EINTR) ? 0 : -1;
    for (int i = 0; i < n; i++) {
        evs[i].ptr    = raw[i].udata;
        evs[i].events = 0;
        if (raw[i].filter == EVFILT_READ)  evs[i].events |= POLLER_READ;
        if (raw[i].filter == EVFILT_WRITE) evs[i].events |= POLLER_WRITE;
        if (raw[i].flags  & EV_EOF)        evs[i].events |= POLLER_HUP;
        if (raw[i].flags  & EV_ERROR)      evs[i].events |= POLLER_ERR;
    }
    return n;
}

#else
#error "Unsupported platform: only Linux and BSD/macOS are supported"
#endif

