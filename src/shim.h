#ifndef SHIM_H
#define SHIM_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/epoll.h>
#include <errno.h>
#include "bytearray.h"

#define MAXEVENTS 256

//#define DEBUG
#ifdef DEBUG
#define DBG_PRINT(args...) fprintf(stdout, "[dbg] " args); fflush(stdout)
#else
#define DBG_PRINT(msg, args...) ;
#endif

typedef enum {
    CLIENT_LISTENER, SERVER_LISTENER
} event_t;

typedef enum {
    WAITING_FOR_FLINE, WAITING_FOR_HEADER, WAITING_FOR_BODY
} conn_state_t;

#define HTTP_REQ_HEAD (1 << 0)
#define HTTP_REQ_GET (1 << 1)
#define HTTP_REQ_POST (1 << 2)
#define HTTP_REQ_PUT (1 << 3)
#define HTTP_REQ_DELETE (1 << 4)
#define HTTP_REQ_TRACE (1 << 5)
#define HTTP_REQ_CONNECT (1 << 6)

struct connection_info;

struct event_data {
    event_t type;
    int listen_fd;
    int send_fd;
    conn_state_t state;
    struct connection_info *conn_info;
};

struct connection_info {
    struct event_data *client_ev_data;
    struct event_data *server_ev_data;
};

int make_socket_non_blocking(int sfd);
int create_and_bind(char *port);
int create_and_connect(char *port);
void free_connection_info(struct connection_info *ci);
int sendall(int sockfd, const void *buf, size_t len);

void handle_event(int efd, struct epoll_event *ev, int sfd);
int handle_client_event(struct epoll_event *ev);
int handle_server_event(struct epoll_event *ev);
void handle_new_connection(int efd, struct epoll_event *ev, int sfd);

#endif
