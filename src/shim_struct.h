#ifndef SHIM_STRUCT_H
#define SHIM_STRUCT_H

#include <stdbool.h>
#include "bytearray.h"
#include "struct_array.h"
#include "shim.h"
#include "config.h"

/* Enums */

typedef enum {
    CLIENT_LISTENER, SERVER_LISTENER
} event_t;

typedef enum {
    WAITING_FOR_URL, URL_COMPLETE, HEADERS_COMPLETE, MESSAGE_COMPLETE
} conn_state_t;


/* Structures */

struct connection_info;

struct event_data {
    int listen_fd;
    int send_fd;
    http_parser parser;
    struct connection_info *conn_info;
    bytearray_t *url;
    bytearray_t *body;

#if ENABLE_SESSION_TRACKING
    bytearray_t *cookie;
    bytearray_t *headers_cache;
    const char *content_len_value;
    size_t content_len_value_len;
#endif

#if ENABLE_HEADERS_TRACKING
    bytearray_t *header_field;
    bytearray_t *header_value;
    const char *header_value_loc;
    const char *header_field_loc;
    struct_array_t *all_header_fields;
    struct_array_t *all_header_values;
#endif

    event_t type : 8;
    bool is_cancelled : 1;
    bool msg_begun : 1;
    bool headers_complete : 1;
    bool msg_complete : 1;
    bool just_visited_header_field : 1;
    bool got_eagain : 1;
    bool sent_js_snippet : 1;

#if ENABLE_SESSION_TRACKING
    bool content_length_specified : 1;
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

/* Structure functions */
struct connection_info *init_conn_info(int infd, int outfd);
struct event_data *init_event_data(event_t type, int listen_fd, int send_fd,
        enum http_parser_type parser_type, struct connection_info *conn_info);
void reset_event_data(struct event_data *ev);
void reset_connection_info(struct connection_info *ci);
void free_event_data(struct event_data *ev);
void free_connection_info(struct connection_info *ci);
void copy_default_params(struct page_conf *page_conf, struct params *params);

#endif
