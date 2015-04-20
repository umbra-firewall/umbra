#ifndef SHIM_STRUCT_H
#define SHIM_STRUCT_H

#include <stdbool.h>

#if ENABLE_HTTPS
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#include "bytearray.h"
#include "struct_array.h"
#include "shim.h"
#include "config.h"

/* Enums */

typedef enum {
    CLIENT_LISTENER, SERVER_LISTENER
} event_t;


#define CANCEL_REASON_MAP(XX) \
    XX(REASON_NOT_CANCELLED, "Connection is not cancelled") \
    \
    XX(REASON_INTERNAL_ERROR, "Internal shim error") \
    XX(REASON_INVALID_HTTP, "Malformed HTTP message") \
    XX(REASON_HTTP_FEATURE_NOT_SUPPORTED, "HTTP feature not supported") \
    XX(REASON_NETWORK_ERROR, "Network error") \
    \
    /* Security violations */ \
    XX(REASON_SECURITY_VIOLATION, "Security violation") \
    XX(REASON_OVERSIZED_HEADER_FIELD, "Header field too large") \
    XX(REASON_OVERSIZED_HEADER_VALUE, "Header value too large") \
    XX(REASON_DIR_TRAVERSAL, "Attempted directory traversal") \
    XX(REASON_INVALID_CSRF_TOKEN, "Did not receive valid CSRF token") \
    XX(REASON_INVALID_CSRF_COOKIE, "Did not receive valid CSRF cookie") \
    XX(REASON_HTTP_METHOD, "HTTP method not allowed for page") \
    XX(REASON_PARAM_CHARACTER_NOT_ALLOWED, "Character not allowed in parameter") \
    XX(REASON_PARAM_LEN_EXCEEDED, "Max parameter length exceeded") \
    XX(REASON_PARAM_NOT_ALLOWED, "Parameter not in whitelist for page") \
    XX(REASON_NO_AUTH_HEADER, "No authentication header found") \
    XX(REASON_INVALID_AUTH_CREDS, "Invalid username/password authorization") \
    \
    /* Used to determine if reason is for security */ \
    XX(REASON_SECURITY_UNUSED, "")

/* Cancel reason enum */
#define CANCEL_REASON_DESCRIPTION(name, description) name,
typedef enum {
    CANCEL_REASON_MAP(CANCEL_REASON_DESCRIPTION)
} cancel_reason_t;
#undef CANCEL_REASON_DESCRIPTION

extern const char *cancel_reason_names[];
extern const char *cancel_reason_descriptions[];

#define REASON_NAME(reason) cancel_reason_names[reason]
#define REASON_DESCRIPTION(reason) cancel_reason_descriptions[reason]


/* Indicates what has been received */
typedef enum {
    CHUNK_SZ, CHUNK_SZ_LF, CHUNK_BODY, CHUNK_BODY_CR, CHUNK_BODY_LF
} chunk_state_t;

/* Structures */

struct connection_info;

struct fd_ctx {
    int sock_fd;
    bool is_tls;
#if ENABLE_HTTPS
    SSL *ssl;
#endif
    bool is_server : 1;
};

struct event_data {
    struct fd_ctx *listen_fd;
    struct fd_ctx *send_fd;
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
    bytearray_t *chunk;
    uint64_t remaining_chunk_bytes;

    struct_array_t *cookie_name_array;
    struct_array_t *cookie_value_array;

    int64_t content_original_length;
#endif

    /* Current header field/value */
    bytearray_t *header_field;
    bytearray_t *header_value;

    /* Array of all header fields/values, whose entries are assumed to be NUL
     * terminated. */
    struct_array_t *all_header_fields;
    struct_array_t *all_header_values;

    cancel_reason_t cancel_reason : 8;

    event_t type : 8;

#if ENABLE_SESSION_TRACKING
    chunk_state_t chunk_state : 8;
#endif

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
    bool chunked_encoding_specified : 1;
    bool on_last_chunk : 1;
    bool found_shim_session_cookie : 1;
#endif

#if ENABLE_CSRF_PROTECTION
    bool found_csrf_correct_token : 1;
#endif
};


struct connection_info {
    struct event_data *client_ev_data;
    struct event_data *server_ev_data;
    struct params default_params;
    struct page_conf *page_match;

#if ENABLE_SESSION_TRACKING
    struct session *session;
#endif
};


/* Global variables */
extern int num_conn_infos;


/* Structure functions */
struct connection_info *init_conn_info(int infd, int outfd, bool in_is_tls,
        bool out_is_tls);
struct event_data *init_event_data(event_t type, struct fd_ctx *listen_fd,
        struct fd_ctx *send_fd, enum http_parser_type parser_type,
        struct connection_info *conn_info);
struct fd_ctx *init_fd_ctx(int sock_fd, bool is_tls, bool is_server);
void reset_event_data(struct event_data *ev);
void reset_connection_info(struct connection_info *ci);
void free_fd_ctx(struct fd_ctx *fd_ctx);
void free_event_data(struct event_data *ev);
void free_connection_info(struct connection_info *ci);
void copy_default_params(struct page_conf *page_conf, struct params *params);
bool is_conn_cancelled(struct event_data *ev_data);
void cancel_connection(struct event_data *ev_data, cancel_reason_t reason);
bool cancel_reason_is_security_violation(cancel_reason_t reason);
bool cancel_reason_requires_auth(cancel_reason_t reason);

#endif
