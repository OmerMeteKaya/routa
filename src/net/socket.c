#define _GNU_SOURCE
#include "net/socket.h"
#include "util/logger.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int net_server_socket(int port, int backlog) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        LOG_ERROR("Failed to create socket: %s", strerror(errno));
        return -1;
    }

    // Set socket options
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        LOG_ERROR("Failed to set SO_REUSEADDR: %s", strerror(errno));
        close(sockfd);
        return -1;
    }
    
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        LOG_ERROR("Failed to set SO_REUSEPORT: %s", strerror(errno));
        close(sockfd);
        return -1;
    }
    
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        LOG_ERROR("Failed to set SO_REUSEPORT: %s", strerror(errno));
        close(sockfd);
        return -1;
    }

    // Set non-blocking
    if (net_set_nonblocking(sockfd) < 0) {
        close(sockfd);
        return -1;
    }

    // Bind
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("Failed to bind socket: %s", strerror(errno));
        close(sockfd);
        return -1;
    }

    // Listen
    if (listen(sockfd, backlog) < 0) {
        LOG_ERROR("Failed to listen on socket: %s", strerror(errno));
        close(sockfd);
        return -1;
    }

    return sockfd;
}

int net_set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        LOG_ERROR("Failed to get socket flags: %s", strerror(errno));
        return -1;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        LOG_ERROR("Failed to set socket non-blocking: %s", strerror(errno));
        return -1;
    }

    return 0;
}

void net_close(int fd) {
    if (fd >= 0) {
        close(fd);
    }
}
