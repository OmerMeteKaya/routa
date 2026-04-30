#ifndef ROUTA_NET_SOCKET_H
#define ROUTA_NET_SOCKET_H

int  net_server_socket(int port, int backlog);
int  net_set_nonblocking(int fd);
void net_close(int fd);

#endif // ROUTA_NET_SOCKET_H
