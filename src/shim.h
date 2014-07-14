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
#include <stdbool.h>
#include "http_parser.h"
#include "bytearray.h"
#include "config.h"

#define MAXEVENTS 256
#define READ_BUF_SIZE 4096

#define TRACE
#ifdef TRACE
#define log_trace(args...) fprintf(stdout, "[trace] " args); fflush(stdout)
#else
#define log_trace(msg, args...) ;
#endif

//#define DEBUG
#ifdef DEBUG
#define log_dbg(args...) fprintf(stdout, "[ dbg ] " args); fflush(stdout)
#else
#define log_dbg(msg, args...) ;
#endif

#define log_warn(args...) fprintf(stderr, "[warn ] " args); fflush(stdout)
#define log_info(args...) fprintf(stderr, "[info ] " args); fflush(stdout)
#define log_error(args...) fprintf(stderr, "[error] " args); fflush(stdout)

typedef enum {
    CLIENT_LISTENER, SERVER_LISTENER
} event_t;

typedef enum {
    WAITING_FOR_URL, URL_COMPLETE, HEADERS_COMPLETE, MESSAGE_COMPLETE
} conn_state_t;


/* HTTP_REQ definitions must be defined in same order as http_parser */
#define HTTP_REQ_DELETE (1 << 0)
#define HTTP_REQ_GET (1 << 1)
#define HTTP_REQ_HEAD (1 << 2)
#define HTTP_REQ_POST (1 << 3)
#define HTTP_REQ_PUT (1 << 4)
#define HTTP_REQ_CONNECT (1 << 5)
#define HTTP_REQ_OPTIONS (1 << 6)
#define HTTP_REQ_TRACE (1 << 7)
#define NUM_HTTP_REQ_TYPES 8


struct connection_info;

struct event_data {
    int listen_fd;
    int send_fd;
    http_parser parser;
    struct params default_params;
    struct connection_info *conn_info;
    bytearray_t *url;
    struct page_conf *page_match;
    event_t type : 8;
    conn_state_t state : 8;
    bool is_cancelled : 1;
    bool have_done_after_header_checks : 1;
};

struct connection_info {
    struct event_data *client_ev_data;
    struct event_data *server_ev_data;
};

int make_socket_non_blocking(int sfd);
int create_and_bind(char *port);
int create_and_connect(char *port);
void free_event_data(struct event_data *ev);
void free_connection_info(struct connection_info *ci);
int sendall(int sockfd, const void *buf, size_t len);

void handle_event(int efd, struct epoll_event *ev, int sfd);
int handle_client_event(struct epoll_event *ev);
int handle_server_event(struct epoll_event *ev);
void handle_new_connection(int efd, struct epoll_event *ev, int sfd);
void init_error_page(char *error_page_file);
void init_structures(char *error_page_file);
void init_page_conf();
struct connection_info *init_conn_info(int infd, int outfd);
void do_after_header_checks(struct event_data *ev_data);
void check_request_type(struct event_data *ev_data);
int http_parser_method_to_shim(enum http_method method);
void check_url_params(struct event_data *ev_data);
void check_single_arg(struct event_data *ev_data, char *arg, size_t len);
void cancel_connection(struct event_data *ev_data);
bool is_conn_cancelled(struct event_data *ev_data);
void copy_default_params(struct page_conf *page_conf, struct params *params);
struct params *find_matching_param(char *name, size_t name_len,
        struct params *params, unsigned int params_len,
        struct event_data *ev_data);
size_t url_encode_buf_len(char *data, size_t len, struct event_data *ev_data);
bool is_hex_digit(char c);

/* HTTP parser callbacks */
int on_message_begin_cb(http_parser *p);
int on_headers_complete_cb(http_parser *p);
int on_message_complete_cb(http_parser *p);
int on_url_cb(http_parser *p, const char *at, size_t length);
int on_header_field_cb(http_parser *p, const char *at, size_t length);
int on_header_value_cb(http_parser *p, const char *at, size_t length);
int on_body_cb(http_parser *p, const char *at, size_t length);

#define SIMPLE_HTTP_RESPONSE \
    "HTTP/1.0 201 OK\r\n" \
    "Content-type: text/html\r\n" \
    "\r\n"

#define DEFAULT_ERROR_PAGE_STR \
    "<html>" \
    "<head>" \
    "<title>Action Not Allowed</title>" \
    "</head>" \
    "<body>" \
    "<h1>Action Not Allowed</h1>" \
    "This request has been blocked by the firewall shim. " \
    "Please contact your network administrator for more details." \
    "</body>" \
    "</html>"

#endif
