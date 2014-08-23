#ifndef SHIM_STRUCT_H
#define SHIM_STRUCT_H

#include <stdbool.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "bytearray.h"
#include "struct_array.h"
#include "shim.h"
#include "config.h"

/* Enums */

typedef enum {
    CLIENT_LISTENER, SERVER_LISTENER
} event_t;


/* Structures */

struct connection_info;

struct fd_ctx {
    int sock_fd;
    bool is_tls;
#if ENABLE_HTTPS
    SSL *ssl;
#endif
    bool is_server : 1;
    bool started_conn : 1;
};

struct event_data {
    struct fd_ctx listen_fd;
    struct fd_ctx send_fd;
    http_parser parser;
    struct connection_info *conn_info;
    bytearray_t *url;
    bytearray_t *body;
    char *http_msg_newline;
    bytearray_t *headers_cache;

#if ENABLE_SESSION_TRACKING
    /* Do not free; references to members of all_header struct_array */
    bytearray_t *cookie_header_value_ref;
    bytearray_t *content_length_header_value_ref;

    struct_array_t *cookie_name_array;
    struct_array_t *cookie_value_array;

    long long content_original_length;
#endif

    /* Current header field/value */
    bytearray_t *header_field;
    bytearray_t *header_value;

    /* Array of all header fields/values, whose entries are assumed to be NUL
     * terminated. */
    struct_array_t *all_header_fields;
    struct_array_t *all_header_values;

    event_t type : 8;

    /* Boolean values */
    bool is_cancelled : 1;
    bool msg_begun : 1;
    bool headers_complete : 1;
    bool msg_complete : 1;
    bool just_visited_header_field : 1;
    bool got_eagain : 1;
    bool sent_js_snippet : 1;
    bool headers_have_been_sent : 1;

#if ENABLE_SESSION_TRACKING
    bool content_length_specified : 1;
    bool found_shim_session_cookie : 1;
#endif

#if ENABLE_CSRF_PROTECTION
    bool found_csrf_correct_token : 1;
#endif
};


struct connection_info {
    struct event_data *client_ev_data;
    struct event_data *server_ev_data;
    struct session *session;
    struct params default_params;
    struct page_conf *page_match;
};


/* Global variables */
extern int num_conn_infos;


/* Structure functions */
struct connection_info *init_conn_info(int infd, int outfd, bool in_is_tls,
        bool out_is_tls);
struct event_data *init_event_data(event_t type, int listen_fd, int send_fd,
        bool listen_is_tls, bool send_is_tls, enum http_parser_type parser_type,
        struct connection_info *conn_info);
int init_fd_ctx(struct fd_ctx *fd_ctx, int sock_fd, bool is_tls,
        bool is_server);
void reset_event_data(struct event_data *ev);
void reset_connection_info(struct connection_info *ci);
void free_event_data(struct event_data *ev);
void free_connection_info(struct connection_info *ci);
void copy_default_params(struct page_conf *page_conf, struct params *params);
bool is_conn_cancelled(struct event_data *ev_data);
void cancel_connection(struct event_data *ev_data);

#endif
