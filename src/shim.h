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
#include <stdbool.h>
#include <time.h>
#include "http_parser.h"
#include "bytearray.h"
#include "session.h"
#include "shim_struct.h"
#include "struct_array.h"
#include "config.h"


/* Macros */

#define SHIM_VERSION "v0.5.4"

#define MAXEVENTS 256
#define READ_BUF_SIZE 4096

/* Stringification macros */
/* XSTR will expand a macro value into a string literal. */
#define XSTR(a) STR(a)
#define STR(a) #a

/* index, name, required, enabled, var, description */
#define ARGUMENT_MAP(XX) \
    /* Required args */ \
    XX(0, "shim-http-port", true, true, shim_http_port_str, \
            "HTTP port on which shim should listen") \
    XX(1, "server-http-port", true, true, server_http_port_str, \
            "port of listening HTTP server") \
    XX(2, "shim-tls-port", true, ENABLE_HTTPS, shim_tls_port_str, \
            "HTTPS port on which shim should listen") \
    XX(3, "server-tls-port", true, ENABLE_HTTPS, server_tls_port_str, \
            "port of listening HTTPS server") \
    \
    /* Optional args */ \
    XX(4, "error-page", false, true, error_page_file, \
            "file containing contents for error page")

#define GETOPT_OPTIONS_LAMBDA(index, name, required, enabled, var, description) \
    {name, required ? required_argument : optional_argument, NULL, 0},

#define ARGUMENT_USAGE_FORMAT "--%-16s    %s\n"

#define PRINT_USAGE_REQUIRED_LAMBDA(index, name, required, enabled, var, description) \
    if (required) {\
        printf(ARGUMENT_USAGE_FORMAT, name, description); \
    }

#define PRINT_USAGE_OPTIONAL_LAMBDA(index, name, required, enabled, var, description) \
    if (!required) {\
        printf(ARGUMENT_USAGE_FORMAT, name, description); \
    }

struct variable_enabled {
    char **variable;
    bool enabled;
};
#define ARG_VARIABLE_LAMBDA(index, name, required, enabled, var, description) \
    {&var, enabled},

#define PRINT_ARGS_LAMBDA(index, name, required, enabled, var, description) \
    log_dbg("  %s=%s\n", name, var ? var : "NULL");

/* Function prototypes */

/* Initialization functions */
void init_structures(char *error_page_file);
void init_page_conf();
void init_ssl();

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
struct page_conf *url_find_matching_page(char *url, size_t len);
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
int do_http_parse_send(char *headers_buf, size_t header_buf_len, char *body_buf,
        size_t body_buf_len, struct event_data *ev_data,
        http_parser_settings *parser_settings,
        bool send_headers);
void parse_argument_name_value(char *arg, size_t arg_len, char **name,
        size_t *name_len, char **value, size_t *value_len);
void update_http_header_pair(struct event_data *ev_data, bool is_header_field,
        const char *at, size_t length);
int populate_set_cookie_header_value(char *buf, size_t buf_len,
        struct event_data *ev_data);
int check_send_csrf_js_snippet(struct event_data *ev_data);
int flush_server_event(struct event_data *server_ev_data);

/* Util functions */
bool is_hex_digit(char c);
bool is_conn_cancelled(struct event_data *ev_data);
void cancel_connection(struct event_data *ev_data);
int fill_rand_bytes(char *buf, size_t len);
void print_usage(char **argv);
void parse_program_arguments(int argc, char **argv);

#endif
