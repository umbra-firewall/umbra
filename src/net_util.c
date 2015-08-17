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

#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "net_util.h"
#include "log.h"


/* Create listening socket and bind to port */
int create_and_bind(char *port) {
    struct addrinfo hints = {{0}};
    struct addrinfo *result = NULL, *rp = NULL;
    int s, sfd;
    int yes = 1;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC; /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */
    hints.ai_flags = AI_PASSIVE; /* All interfaces */

    s = getaddrinfo(NULL, port, &hints, &result);
    if (s != 0) {
        log_info("getaddrinfo: %s\n", gai_strerror(s));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1) {
            continue;
        }

        if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int))
                == -1) {
            perror("setsockopt");
            exit(1);
        }

        s = bind(sfd, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            /* We managed to bind successfully! */
            break;
        }

        close(sfd);
    }

    if (rp == NULL) {
        log_error("Could not bind\n");
        return -1;
    }

    freeaddrinfo(result);

    return sfd;
}

/* Connect to server, returning socket on success, -1 otherwise. */
int create_and_connect(char *port) {
    int sockfd, rv, rc = 0;
    struct addrinfo hints, *servinfo = NULL, *p = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(server_hostname, port, &hints, &servinfo)) != 0) {
        log_warn("getaddrinfo: %s\n", gai_strerror(rv));
        rc = -1;
        goto error;
    }

    // loop through all the results and connect to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol))
                == -1) {
            perror("socket");
            continue;
        }
        rc = sockfd;

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("connect");
            continue;
        }

        break;
    }

    if (p == NULL) {
        log_error("client: failed to connect\n");
        rc = -1;
        goto error;
    }

error:
    if (servinfo) {
        freeaddrinfo(servinfo);
    }
    return rc;
}

/* Sets socket as non blocking */
int make_socket_non_blocking(int sfd) {
    int flags, s;

    flags = fcntl(sfd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl");
        return -1;
    }

    flags |= O_NONBLOCK;
    s = fcntl(sfd, F_SETFL, flags);
    if (s == -1) {
        perror("fcntl");
        return -1;
    }

    return 0;
}

/* Send entire buffer over socket, using multiple sends if necessary */
int sendall(struct fd_ctx *fd_ctx, const void *buf, size_t len) {
    int sent_bytes;

    if (fd_ctx == NULL) {
        log_error("Passed NULL fd_ctx in sendall()\n");
        return -1;
    }

#if ENABLE_HTTPS
    if (fd_ctx->is_tls) {
        /* HTTP over TLS */
        while (len > 0) {
            sent_bytes = SSL_write(fd_ctx->ssl, buf, len);
            if (sent_bytes <= 0) {
                int error = SSL_get_error(fd_ctx->ssl, sent_bytes);

                /* Check for clean shutdown */
                if (sent_bytes == 0) {
                    if (SSL_get_shutdown(fd_ctx->ssl) & SSL_RECEIVED_SHUTDOWN) {
                        log_trace("  Got SSL_RECEIVED_SHUTDOWN\n");
                        return 0;
                    }
                    if (error == SSL_ERROR_ZERO_RETURN) {
                        log_trace("  Got SSL_ERROR_ZERO_RETURN\n");
                        return 0;
                    }
                }

                if (error == SSL_ERROR_WANT_READ
                        || error == SSL_ERROR_WANT_WRITE) {
                    log_dbg("Got SSL EAGAIN during sendall; retrying\n");
                    continue;
                }
                log_ssl_error("SSL_write() failed\n");
                return -1;
            }
            buf += sent_bytes;
            len -= sent_bytes;
        }
        return 0;
    }
#endif

    /* Plain HTTP */
    while (len > 0) {
        sent_bytes = send(fd_ctx->sock_fd, buf, len, 0);
        if (sent_bytes < 0) {
            if (errno == EAGAIN) {
                log_dbg("Got EAGAIN during sendall; retrying\n");
                continue;
            }
            perror("send");
            return -1;
        }
        buf += sent_bytes;
        len -= sent_bytes;
    }
    return 0;
}

/* Reads from fd_ctx into bufffer of given length. Sets eagain if to whether
 * EAGAIN was returned by send (or equivalent for SSL).
 * Returns number of bytes read on successful read; returns int < 0 otherwise.
 */
int fd_ctx_read(struct fd_ctx *fd_ctx, char *buf, size_t len, bool *eagain) {
    int rc;

    if (fd_ctx == NULL || eagain == NULL) {
        log_error("Passed NULL fd_ctx or eagain in fd_ctx_read()\n");
        return -1;
    }

#if ENABLE_HTTPS
    if (fd_ctx->is_tls) {
        log_dbg("  Reading SSL...\n");
        /* HTTP over TLS */
        rc = SSL_read(fd_ctx->ssl, buf, len);
        if (rc <= 0) {
            /* Possible error */
            int err = SSL_get_error(fd_ctx->ssl, rc);

            /* Check for clean shutdown */
            if (rc == 0) {
                if (SSL_get_shutdown(fd_ctx->ssl) & SSL_RECEIVED_SHUTDOWN) {
                    log_trace("  Got SSL_RECEIVED_SHUTDOWN\n");
                    *eagain = false;
                    return 0;
                }
                if (err == SSL_ERROR_ZERO_RETURN) {
                    log_trace("  Got SSL_ERROR_ZERO_RETURN\n");
                    *eagain = false;
                    return 0;
                }
            }

            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                *eagain = true;
                return rc;
            }
            log_ssl_error("SSL_read() failed\n");
        }
        *eagain = false;
        return rc;
    }
#endif

    /* Plain HTTP */
    log_dbg("  Reading socket...\n");
    rc = read(fd_ctx->sock_fd, buf, len);
    if (rc < 0) {
        if (errno == EAGAIN) {
            *eagain = true;
            return rc;
        }
        perror("read");
    }
    *eagain = false;
    return rc;
}

/* Close file descriptor fd if it is greater than zero. Returns return value
 * of close if fd was closed, otherwise returns 0. */
int close_fd_if_valid(int fd) {
    if (fd > 0) {
        return close(fd);
    }
    return 0;
}
