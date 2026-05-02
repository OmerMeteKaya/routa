#define _GNU_SOURCE
#include "net/io.h"
#include "util/logger.h"
#include <unistd.h>
#include <errno.h>
#include <string.h>

#define IO_BUFFER_SIZE 8192

ssize_t io_read_into_buf(int fd, buf_t *b, tls_conn_t *tls) {
    if (!b) {
        return -1;
    }
    
    uint8_t temp_buf[IO_BUFFER_SIZE];
    ssize_t n;
    
    if (tls) {
        n = tls_read(tls, temp_buf, sizeof(temp_buf));
        if (n == -1) {
            // Want read/write or error
            return 0;
        }
    } else {
        n = read(fd, temp_buf, sizeof(temp_buf));
        
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0; // No data available right now
            }
            LOG_ERROR("Read failed: %s", strerror(errno));
            return -1;
        }
    }
    
    if (n == 0) {
        return 0; // EOF
    }
    
    if (buf_append(b, temp_buf, (size_t)n) < 0) {
        LOG_ERROR("Failed to append to buffer");
        return -1;
    }
    
    return n;
}

ssize_t io_write_from_buf(int fd, buf_t *b, tls_conn_t *tls) {
    if (!b || b->len == 0) {
        return 0;
    }
    
    ssize_t n;
    
    if (tls) {
        n = tls_write(tls, b->data, b->len);
        if (n == -1) {
            // Want read/write or error
            return 0;
        }
    } else {
        n = write(fd, b->data, b->len);
        
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0; // Can't write right now
            }
            LOG_ERROR("Write failed: %s", strerror(errno));
            return -1;
        }
    }
    
    if (n > 0) {
        buf_consume(b, (size_t)n);
    }
    
    return n;
}
