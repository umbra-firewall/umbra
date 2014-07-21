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
#include <time.h>
#include "http_parser.h"
#include "bytearray.h"
#include "config.h"


/* Macros */

#define SHIM_VERSION "v0.5.0"

#define MAXEVENTS 256
#define READ_BUF_SIZE 4096

/* Logging macros */
#ifdef DEBUG
#define log_trace(args...) fprintf(stdout, "[trace] " args); fflush(stdout)
#define log_dbg(args...) fprintf(stdout, "[ dbg ] " args); fflush(stdout)
#else
#define log_trace(msg, args...) ;
#define log_dbg(msg, args...) ;
#endif
#define log_warn(args...) fprintf(stderr, "[warn ] " args); fflush(stdout)
#define log_info(args...) fprintf(stderr, "[info ] " args); fflush(stdout)
#define log_error(args...) fprintf(stderr, "[error] " args); fflush(stdout)

/* Computed enable macros */
#define PAGES_CONF_LEN (sizeof(pages_conf) / sizeof(*pages_conf))
#define ENABLE_PARAM_CHECKS (ENABLE_PARAM_LEN_CHECK || ENABLE_PARAM_WHITELIST_CHECK)
#define ENABLE_SESSION_TRACKING (ENABLE_CSRF_PROTECTION)
#define ENABLE_HEADER_FIELD_CHECK (ENABLE_HEADER_FIELD_LEN_CHECK || ENABLE_HEADERS_TRACKING)
#define ENABLE_HEADER_VALUE_CHECK (ENABLE_HEADER_VALUE_LEN_CHECK || ENABLE_HEADERS_TRACKING)
#define ENABLE_HEADERS_TRACKING ENABLE_SESSION_TRACKING

/* HTTP_REQ_* definitions must be defined in same order as http_parser */
#define HTTP_REQ_DELETE (1 << 0)
#define HTTP_REQ_GET (1 << 1)
#define HTTP_REQ_HEAD (1 << 2)
#define HTTP_REQ_POST (1 << 3)
#define HTTP_REQ_PUT (1 << 4)
#define HTTP_REQ_CONNECT (1 << 5)
#define HTTP_REQ_OPTIONS (1 << 6)
#define HTTP_REQ_TRACE (1 << 7)
#define NUM_HTTP_REQ_TYPES 8

/* Stringification macros */
/* XSTR will expand a macro value into a string literal. */
#define XSTR(a) STR(a)
#define STR(a) #a

/* HTTP macros */
#define CRLF "\r\n"

#define HTTP_RESPONSE_OK \
    "HTTP/1.0 201 OK\r\n" \
    "Content-type: text/html\r\n" \
    "\r\n"

#define HTTP_RESPONSE_FORBIDDEN \
    "HTTP/1.0 403 Forbidden\r\n" \
    "Content-type: text/html\r\n" \
    "Cache-Control: no-cache, no-store, must-revalidate\r\n" \
    "Pragma: no-cache\r\n" \
    "Expires: 0\r\n" \
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

/* Session macros */
#define SHIM_SESSID_NAME "SHIM_SESSID"
#define SHIM_SESSID_NAME_STRLEN (sizeof(SHIM_SESSID_NAME) - 1)
#define SHIM_SESSID_RAND_BYTES 10
#define SHIM_SESSID_LEN (2 * SHIM_SESSID_RAND_BYTES)

#define SET_COOKIE_HEADER_FORMAT \
    "Set-Cookie: " \
        SHIM_SESSID_NAME "=%s; " \
        "max-age=" XSTR(SESSION_LIFE_SECONDS) "; " \
        "path=/" \
        CRLF

#define ESTIMATED_SET_COOKIE_HEADER_LEN \
    (sizeof(SET_COOKIE_HEADER_FORMAT) + SHIM_SESSID_LEN)

#define MAX_HTTP_RESPONSE_HEADERS_SIZE 8096

#define COOKIE_HEADER "Cookie"
#define COOKIE_HEADER_STRLEN (sizeof(COOKIE_HEADER) - 1)

#define CONTENT_LENGTH_HEADER "Content-Length"
#define CONTENT_LENGTH_HEADER_STRLEN \
    (sizeof(CONTENT_LENGTH_HEADER) - 1)

#define TRANSFER_ENCODING_HEADER "Transfer-Encoding"
#define TRANSFER_ENCODING_HEADER_STRLEN \
    (sizeof(TRANSFER_ENCODING_HEADER) - 1)

#define TE_HEADER "TE"
#define TE_HEADER_STRLEN (sizeof(TE_HEADER) - 1)

#define CONTENT_ENCODING_HEADER "Content-Encoding"
#define CONTENT_ENCODING_HEADER_STRLEN \
    (sizeof(CONTENT_ENCODING_HEADER) - 1)

#define CSRF_TOKEN_NAME "_umbra_csrf_token"
#define CSRF_TOKEN_NAME_LEN (sizeof(CSRF_TOKEN_NAME) - 1)

#define INSERT_HIDDEN_TOKEN_JS_FORMAT \
    "<script>" \
    "var input = document.createElement(\"input\");" \
    "input.setAttribute(\"type\", \"hidden\");" \
    "input.setAttribute(\"name\", \"" CSRF_TOKEN_NAME "\");" \
    "input.setAttribute(\"value\", \"%s\");" \
    "var forms = document.getElementsByTagName('form');" \
    "for (var i = 0, length = forms.length; i < length; i ++) {" \
    "  forms[i].appendChild(input);" \
    "}" \
    "</script>"
#define INSERT_HIDDEN_TOKEN_JS_STRLEN \
    (sizeof(INSERT_HIDDEN_TOKEN_JS_FORMAT) + SHIM_SESSID_LEN - 3)


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
    const char *content_len_value;
    size_t content_len_value_len;
#endif

#if ENABLE_HEADERS_TRACKING
    bytearray_t *header_field;
    bytearray_t *header_value;
    const char *header_value_loc;
    const char *header_field_loc;
#endif

    event_t type : 8;
    bool is_cancelled : 1;
    bool msg_begun : 1;
    bool headers_complete : 1;
    bool msg_complete : 1;
    bool just_visited_header_field : 1;

#if ENABLE_SESSION_TRACKING
    bool content_length_specified : 1;
#endif

#if ENABLE_CSRF_PROTECTION
    bool found_csrf_correct_token : 1;
#endif
};

struct session {
    char session_id[SHIM_SESSID_LEN + 1];
    time_t expires_at;
};

struct connection_info {
    struct event_data *client_ev_data;
    struct event_data *server_ev_data;
    struct session *session;
    struct params default_params;
    struct page_conf *page_match;
};


/* Function prototypes */

/* Initialization functions */
void init_error_page(char *error_page_file);
void init_structures(char *error_page_file);
void init_page_conf();
struct connection_info *init_conn_info(int infd, int outfd);
struct event_data *init_event_data(event_t type, int listen_fd, int send_fd,
        enum http_parser_type parser_type, struct connection_info *conn_info);

/* Network functions */
int make_socket_non_blocking(int sfd);
int create_and_bind(char *port);
int create_and_connect(char *port);
void free_event_data(struct event_data *ev);
void free_connection_info(struct connection_info *ci);
int sendall(int sockfd, const void *buf, size_t len);

/* Event handlers */
void handle_event(int efd, struct epoll_event *ev, int sfd);
int handle_client_server_event(struct epoll_event *ev);
int handle_new_connection(int efd, struct epoll_event *ev, int sfd);
void sigint_handler(int dummy);

/* Feature checks */
void do_client_header_complete_checks(struct event_data *ev_data);
void check_request_type(struct event_data *ev_data);
void check_buffer_params(bytearray_t *buf, bool is_url_param,
        struct event_data *ev_data);
void check_single_arg(struct event_data *ev_data, char *arg, size_t len);
void check_arg_len_whitelist(struct params *param, char *value,
        size_t value_len, struct event_data *ev_data);
void check_url_dir_traversal(struct event_data *ev_data);
void check_header_pair(struct event_data *ev_data);

/* Feature check helpers */
struct page_conf *find_matching_page(char *url, size_t len);
void copy_default_params(struct page_conf *page_conf, struct params *params);
struct params *find_matching_param(char *name, size_t name_len,
        struct params *params, unsigned int params_len,
        struct event_data *ev_data);
size_t url_encode_buf_len_whitelist(char *data, size_t len,
        struct event_data *ev_data, const char *whitelist);
bool whitelist_char_allowed(const char *whitelist, const char x);
int check_char_whitelist(const char *whitelist, const char c,
        struct event_data *ev_data);
int update_bytearray(bytearray_t *b, const char *at, size_t length,
        struct event_data *ev_data);
int do_http_parse_send(char *buf, size_t len, struct event_data *ev_data,
        http_parser_settings *parser_settings, char *insert_header,
        size_t insert_header_len, size_t insert_offset);
int send_error_page(int sock);
void parse_argument_name_value(char *arg, size_t arg_len, char **name,
        size_t *name_len, char **value, size_t *value_len);
bool str_to_url_encoded_memeq(const char *str, char *url_data,
        size_t url_data_len, struct event_data *ev_data);
void update_http_header_pair(struct event_data *ev_data, bool is_header_field,
        const char *at, size_t length);
int populate_set_cookie_header(char *buf, size_t buf_len,
        struct event_data *ev_data);

/* Util functions */
int http_parser_method_to_shim(enum http_method method);
bool is_hex_digit(char c);
bool is_conn_cancelled(struct event_data *ev_data);
void cancel_connection(struct event_data *ev_data);
int fill_rand_bytes(char *buf, size_t len);

/* Session functions */
void find_session_from_cookie(struct event_data *ev_data);
char *extract_sessid_cookie_value(char *cookie_header_value);
struct session *get_conn_session(struct connection_info *conn_info);
struct session *new_session();
bool is_session_entry_clear(struct session *sess);
void renew_session(struct session *sess);
void clear_session(struct session *sess);
struct session *search_session(char *sess_id);
void expire_sessions();
bool is_session_expired(struct session *s);
int get_num_active_sessions();

/* HTTP parser callbacks */
int on_message_begin_cb(http_parser *p);
int on_headers_complete_cb(http_parser *p);
int on_message_complete_cb(http_parser *p);
int on_url_cb(http_parser *p, const char *at, size_t length);
int on_status_cb(http_parser *p, const char *at, size_t length);
int on_header_field_cb(http_parser *p, const char *at, size_t length);
int on_header_value_cb(http_parser *p, const char *at, size_t length);
int on_body_cb(http_parser *p, const char *at, size_t length);


#endif
