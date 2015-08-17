/**
 * Copyright 2015 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
