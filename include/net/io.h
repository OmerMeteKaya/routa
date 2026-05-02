#ifndef ROUTA_NET_IO_H
#define ROUTA_NET_IO_H

#include "util/buf.h"
#include "net/tls.h"
#include <unistd.h>

ssize_t io_read_into_buf(int fd, buf_t *b, tls_conn_t *tls);
ssize_t io_write_from_buf(int fd, buf_t *b, tls_conn_t *tls);

#endif // ROUTA_NET_IO_H
