#ifndef NET_UTIL_H
#define NET_UTIL_H

#include "shim_struct.h"

struct fd_ctx;

/* Network functions */
int make_socket_non_blocking(int sfd);
int create_and_bind(char *port);
int create_and_connect(char *port);
int sendall(struct fd_ctx *fd_ctx, const void *buf, size_t len);
int fd_ctx_read(struct fd_ctx *fd_ctx, char *buf, size_t len, bool *eagain);
int close_fd_if_valid(int fd);

#endif
