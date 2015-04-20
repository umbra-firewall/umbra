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

#define SHIM_VERSION "v0.7.0"

#define DEFAULT_SERVER_HOST "localhost"
#define MAXEVENTS 256
#define MAX_CHUNK_SIZE_LEN 8
#define READ_BUF_SIZE 4096
#define MAX_CREDS_BUF_LEN 1024

#ifdef FRAMA_C
#include "frama_c_includes.h"
#endif

#define MIN(a,b) ((a) < (b) ? (a) : (b))


/* Stringification macros */
/* XSTR will expand a macro value into a string literal. */
#define XSTR(a) STR(a)
#define STR(a) #a

/* (index, name, required, enabled, var, arg_requirement, description)
 * arg_requirement is one of:
 *      no_argument (assumed to be type bool)
 *      required_argument (assumbed to be type char *)
 */
#define ARGUMENT_MAP(XX) \
    /* Required args */ \
    XX(0, "shim-http-port", true, true, shim_http_port_str, \
            required_argument, "HTTP port on which shim should listen") \
    XX(1, "server-http-port", true, true, server_http_port_str, \
            required_argument, "port of listening HTTP server") \
    XX(2, "shim-tls-port", true, ENABLE_HTTPS, shim_tls_port_str, \
            required_argument, "HTTPS port on which shim should listen") \
    XX(3, "server-tls-port", true, ENABLE_HTTPS, server_tls_port_str, \
            required_argument, "port of listening HTTPS server") \
    XX(4, "tls-cert", true, ENABLE_HTTPS, tls_cert_file, \
            required_argument, "PEM file with TLS certificate chain") \
    XX(5, "tls-key", true, ENABLE_HTTPS, tls_key_file, \
            required_argument, "PEM file with server private key") \
    XX(6, "passwd-file", true, ENABLE_AUTHENTICATION_CHECK, passwd_filename, \
            required_argument, "file that will contains credentials of the form base64(USER:PASS)") \
    \
    /* Optional args */ \
    XX(7, "error-page", false, true, error_page_file, \
            required_argument, "file containing contents for error page") \
    XX(8, "server-host", false, true, server_hostname, \
            required_argument, "IP address or hostname of webserver. " \
            "Defaults to " DEFAULT_SERVER_HOST ".") \
    XX(9, "print-config", false, true, print_config, \
            no_argument, "Print compiled in configuration data")

#define GETOPT_OPTIONS_LAMBDA(index, name, required, enabled, var, arg_requirement, description) \
    {name, arg_requirement, NULL, 0},

#define ARGUMENT_USAGE_FORMAT "--%-16s    %s\n"

#define PRINT_USAGE_REQUIRED_LAMBDA(index, name, required, enabled, var, arg_requirement, description) \
    if ((enabled) && (required)) {\
        printf(ARGUMENT_USAGE_FORMAT, name, description); \
    }

#define PRINT_USAGE_OPTIONAL_LAMBDA(index, name, required, enabled, var, arg_requirement, description) \
    if ((enabled) && !(required)) {\
        printf(ARGUMENT_USAGE_FORMAT, name, description); \
    }

struct variable_enabled {
    void *variable;
    bool enabled;
    bool required;
};
#define ARG_VARIABLE_LAMBDA(index, name, required, enabled, var, arg_requirement, description) \
    {&var, enabled, required},

#define PRINT_ARGS_LAMBDA(index, name, required, enabled, var, arg_requirement, description) \
    if (enabled) {\
        if (arg_requirement == no_argument) { \
            log_dbg("  %s=%s\n", name, var ? "true" : "false"); \
        } else { \
            log_dbg("  %s=%s\n", name, var ? ((char *) var) : "NULL"); \
        }\
    }


/* Global variables */
extern char *tls_cert_file;
extern char *tls_key_file;
extern char *server_hostname;

#if ENABLE_HTTPS
extern SSL_CTX* ssl_ctx_server;
extern SSL_CTX* ssl_ctx_client;
#endif


/* Function prototypes */

/* Initialization functions */
int init_structures(char *error_page_file);
int init_page_conf();
int init_ssl();
int init_ssl_ctx();
void free_ssl();

/* Event handlers */
void handle_event(int efd, struct epoll_event *ev, int sfd, int sfd_tls);
int handle_client_server_event(struct epoll_event *ev);
int handle_new_connection(int efd, struct epoll_event *ev, int sfd, bool is_tls);
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
int check_header_pair(struct event_data *ev_data);
void check_page_auth(struct event_data *ev_data);

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
int handle_chunked_parse_send(char *buf, size_t buf_len,
        http_parser_settings *parser_settings, struct event_data *ev_data);
int check_send_csrf_js_snippet(struct event_data *ev_data);
int flush_server_event(struct event_data *server_ev_data);
bool is_basic_auth_found(bytearray_t *ba);

/* Util functions */
int fill_rand_bytes(char *buf, size_t len);
void print_usage(char **argv);
int set_up_socket_listener(char *port_str);
int init_listen_event_data(struct epoll_event *e, int efd, int sfd);
int parse_program_arguments(int argc, char **argv);
ssize_t read_file_to_buf(char *buf, size_t len, const char *filename);

#endif
