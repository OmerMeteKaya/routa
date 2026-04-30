#ifndef ROUTA_NET_IO_H
#define ROUTA_NET_IO_H

#include "util/buf.h"
#include <unistd.h>

ssize_t io_read_into_buf(int fd, buf_t *b);
ssize_t io_write_from_buf(int fd, buf_t *b);

#endif // ROUTA_NET_IO_H
