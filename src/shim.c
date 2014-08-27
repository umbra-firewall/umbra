#include <inttypes.h>
#include <getopt.h>
#include <errno.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include "shim.h"
#include "config.h"
#include "http_callbacks.h"
#include "http_util.h"
#include "net_util.h"
#include "shim_struct.h"
#include "config_printer.h"
#include "log.h"

char *shim_http_port_str = NULL, *server_http_port_str = NULL;
char *shim_tls_port_str = NULL, *server_tls_port_str = NULL;
char *tls_cert_file = NULL, *tls_key_file = NULL;
char *server_hostname = DEFAULT_SERVER_HOST;
bool print_config = false;

#if ENABLE_HTTPS
SSL_CTX *ssl_ctx_server;
SSL_CTX *ssl_ctx_client;
#endif

char *error_page_file = NULL;

static bool sigint_received = false;

http_parser_settings client_parser_settings = {
    .on_message_begin = on_message_begin_cb,
    .on_url = on_url_cb,
    .on_status = NULL,
    .on_header_field = on_header_field_cb,
    .on_header_value = on_header_value_cb,
    .on_headers_complete = on_headers_complete_cb,
    .on_body = on_body_cb,
    .on_message_complete = on_message_complete_cb
};

http_parser_settings server_parser_settings = {
    .on_message_begin = on_message_begin_cb,
    .on_url = NULL,
    .on_status = on_status_cb,
    .on_header_field = on_header_field_cb,
    .on_header_value = on_header_value_cb,
    .on_headers_complete = on_headers_complete_cb,
    .on_body = on_body_cb,
    .on_message_complete = on_message_complete_cb
};

/*
 * Attempts to find matching page conf. If it cannot find one, it returns a
 * pointer to the default page conf structure.
 */
struct page_conf *url_find_matching_page(char *url, size_t len) {
    // @Todo(Travis) Implement trie search

    int i;

    /* Account for possible URL parameters */
    char *amp_loc = memchr(url, '?', len);
    if (amp_loc) {
        len = amp_loc - url;
    }

    for (i = 0; i < PAGES_CONF_LEN; i++) {
        if (len == strlen(pages_conf[i].name)
                && memcmp(url, pages_conf[i].name, len) == 0) {
            return &pages_conf[i];
        }
    }
    return &default_page_conf;
}

/* Add buffer to end of bytearray, cancelling the connection if it fails */
int update_bytearray(bytearray_t *b, const char *at, size_t length,
        struct event_data *ev_data) {
    if (bytearray_append(b, at, length) < 0) {
        cancel_connection(ev_data);
        log_error("Cancelling request because out of memory\n");
        return -1;
    }
    return 0;
}

/* Inspects current header pair */
int check_header_pair(struct event_data *ev_data) {
    int rc = 0;
    char *field = ev_data->header_field->data;
    char *value = ev_data->header_value->data;
    size_t field_len = ev_data->header_field->len;
    size_t value_len = ev_data->header_value->len;
    (void) value_len;

    /* NUL terminate header field and value */
    if (bytearray_append(ev_data->header_field, "\0", 1) < 0) {
        log_error("Could not append to bytearray\n");
        goto error;
    }
    if (bytearray_append(ev_data->header_value, "\0", 1) < 0) {
        log_error("Could not append to bytearray\n");
        goto error;
    }

    log_trace("Header: \"%s\": \"%s\"\n", ev_data->header_field->data,
            ev_data->header_value->data);


    if (ev_data->type == CLIENT_LISTENER) {
        /* Request only Headers */

#if ENABLE_SESSION_TRACKING
        /* Handle Cookie header */
        if (field_len == COOKIE_HEADER_STRLEN
                && strcasecmp(COOKIE_HEADER, field) == 0) {
            log_trace("Found Cookie header\n");
            /* Set pointer to cookie value */
            ev_data->cookie_header_value_ref = ev_data->header_value;
        }
#endif

    } else {
        /* Response only Headers */
    }


    /* Request or Response headers */

    /* With session tracking, we inject a JS snippet, so we need to understand
     * how the body is sent. Otherwise, we do not care how the body is encoded.
     * The exception is chunked transfer encoding with trailers, which may
     * include additional headers.
     */
    if ((field_len == TRANSFER_ENCODING_HEADER_STRLEN
            && strcasecmp(TRANSFER_ENCODING_HEADER, field) == 0)
            || (field_len == TE_HEADER_STRLEN
                    && strcasecmp(TE_HEADER, field) == 0)) {

        if (value_len == CHUNKED_STRLEN && strcasecmp(CHUNKED, value) == 0) {
            /* Only chunked encoding is allowed */
#if ENABLE_SESSION_TRACKING
            log_dbg("Chunked encoding specified\n");
            ev_data->chunked_encoding_specified = true;

            if (ev_data->content_length_specified) {
                log_warn("HTTP message specified Content-Length and Chunked "
                        "encoding; can only specify one.\n");
                goto error;
            }
#endif
        } else {
            /* Warn against unhandled Transfer-Encoding, such as trailers */
            log_warn("Transfer-Encoding \"%s\" is not supported\n", value);
            goto error;
        }

    } else if (field_len == TRAILERS_STRLEN
            && strcasecmp(TRAILERS, field) == 0) {
        log_warn("Trailers not supported for chunked encoding\n");
        goto error;
    }
#if ENABLE_SESSION_TRACKING
    else if (field_len == CONTENT_ENCODING_HEADER_STRLEN
            && strcasecmp(CONTENT_ENCODING_HEADER, field) == 0) {
        /* Warn against Content-Encoding */
        log_warn("Content-Encoding \"%s\" is not supported\n", value);
        goto error;

    } else if (field_len == CONTENT_LENGTH_HEADER_STRLEN
            && strcasecmp(CONTENT_LENGTH_HEADER, field) == 0) {
        /* Handle Content-Length */
        log_dbg("Content-Length specified\n");
        ev_data->content_length_specified = true;
        ev_data->content_length_header_value_ref = ev_data->header_value;

        if (update_original_content_length(ev_data) < 0) {
            log_error("update_content_length() failed\n");
            goto error;
        }

        if (ev_data->chunked_encoding_specified) {
            log_warn("HTTP message specified Content-Length and Chunked "
                    "encoding; can only specify one.\n");
            goto error;

        }
    }
#endif

    /* Add header field and value to list of all header pairs */
    rc = struct_array_add(ev_data->all_header_fields,
            ev_data->header_field);
    if (rc < 0) {
        log_warn("header_fields append failed\n");
        goto error;
    }
    ev_data->header_field = NULL;

    rc = struct_array_add(ev_data->all_header_values,
            ev_data->header_value);
    if (rc < 0) {
        log_warn("header_values append failed\n");
        goto error;
    }
    ev_data->header_value = NULL;

    /* Allocate new header field/value bytearrays */
    ev_data->header_field = bytearray_new();
    if (ev_data->header_field == NULL) {
        goto error;
    }

    ev_data->header_value = bytearray_new();
    if (ev_data->header_field == NULL) {
        goto error;
    }

    return 0;

error:
    cancel_connection(ev_data);
    return -1;
}


/* Updates current header field or value.
 * Inspects previous header once a new header starts. */
void update_http_header_pair(struct event_data *ev_data, bool is_header_field,
        const char *at, size_t length) {
    bytearray_t *ba;

    /* Inspect header if field and value are present. */
    if (is_header_field && !ev_data->just_visited_header_field
            && ev_data->header_field->len != 0) {
        check_header_pair(ev_data);
    }

    if (is_header_field) {
        ba = ev_data->header_field;
    } else {
        ba = ev_data->header_value;
    }

    update_bytearray(ba, at, length, ev_data);
    ev_data->just_visited_header_field = is_header_field;
}


/* Handle a new incoming connection */
int handle_new_connection(int efd, struct epoll_event *ev, int sfd,
        bool is_tls) {
    int s;
    struct epoll_event client_event = {0}, server_event = {0};
    struct connection_info *conn_info;

    while (1) {
        struct sockaddr in_addr;
        socklen_t in_len;
        int infd = 0, outfd = 0;
        char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

        in_len = sizeof(in_addr);
        infd = accept(sfd, &in_addr, &in_len);
        if (infd == -1) {
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                /* We have processed all incoming
                 connections. */
                break;
            } else {
                perror("accept");
                break;
            }
        }

        s = getnameinfo(&in_addr, in_len, hbuf, sizeof(hbuf), sbuf,
                sizeof(sbuf),
                NI_NUMERICHOST | NI_NUMERICSERV);
        if (s < 0) {
            perror("getnameinfo");
            goto error;
        }

        log_trace("Accepted connection on descriptor %d (host=%s, port=%s)\n",
                infd, hbuf, sbuf);

        /* Make the incoming socket non-blocking and add it to the
         list of fds to monitor. */
        s = make_socket_non_blocking(infd);
        if (s < 0) {
            log_error("Could not make new socket non-blocking\n");
            goto error;
        }

        /* Create proxy socket to server */
        outfd = create_and_connect(server_http_port_str);
        if (outfd < 0) {
            goto error;
        }

        s = make_socket_non_blocking(outfd);
        if (s < 0) {
            log_error("Could not make forward socket non-blocking\n");
            goto error;
        }

        /* Allocate data */
        conn_info = init_conn_info(infd, outfd, is_tls, is_tls);
        if (conn_info == NULL) {
            log_error("init_conn_info() failed\n");
            goto error;
        }
        infd = 0;
        outfd = 0;


        client_event.data.ptr = conn_info->client_ev_data;
        client_event.events = EPOLLIN | EPOLLET;

        server_event.data.ptr = conn_info->server_ev_data;
        server_event.events = EPOLLIN | EPOLLET;

        s = epoll_ctl(efd, EPOLL_CTL_ADD,
                conn_info->client_ev_data->listen_fd.sock_fd, &client_event);
        if (s == -1) {
            perror("epoll_ctl");
            goto error;
        }

        s = epoll_ctl(efd, EPOLL_CTL_ADD,
                conn_info->server_ev_data->listen_fd.sock_fd, &server_event);
        if (s == -1) {
            perror("epoll_ctl");
            goto error;
        }

error:
    close_fd_if_valid(infd);
    close_fd_if_valid(outfd);
    return -1;
    }

    return 0;
}

/* Check HTTP request types */
void check_request_type(struct event_data *ev_data) {
    enum http_method method = ev_data->parser.method;
    log_trace("Checking request type %s\n", http_method_str(method));

    int http_method = http_parser_method_to_shim(method);
    if (!(ev_data->conn_info->page_match->request_types & http_method)) {
        log_error("Request type %s not allowed\n", http_method_str(method));
        cancel_connection(ev_data);
    }
}

/* Find location and size of argument name and value */
void parse_argument_name_value(char *arg, size_t arg_len, char **name,
        size_t *name_len, char **value, size_t *value_len) {
    char *n, *v;
    size_t n_len, v_len;

    n = arg;

    v = memchr(arg, '=', arg_len);
    if (v == NULL) {
        v = n + arg_len;
        v_len = 0;
        n_len = arg_len;
    } else {
        n_len = (v - n);
        v_len = arg_len - n_len - 1;
        v++;
    }

    *name = n;
    *name_len = n_len;
    *value = v;
    *value_len = v_len;
}

/* Finds matching parameter struct based on the parameter name. Returns NULL
 * if one cannot be found */
struct params *find_matching_param(char *name, size_t name_len,
        struct params *params, unsigned int params_len,
        struct event_data *ev_data) {
    bool is_valid, matches;
    int i;
    for (i = 0; i < params_len; i++) {
        matches = str_to_url_encoded_memeq(params[i].name, name, name_len,
                &is_valid);
        if (!is_valid) {
            log_warn("Invalid URL encoding\n");
            cancel_connection(ev_data);
        }
        if (matches) {
            return &params[i];
        }
    }
    return NULL;
}

/* Checks if character is allowed by whitelist, cancelling the connection if it
 * is not. Returns -1 on error, otherwise 0. */
int check_char_whitelist(const char *whitelist, const char c,
        struct event_data *ev_data) {
    if (!whitelist_char_allowed(whitelist, c)) {
        log_info("Character '\\x%02hhx' not allowed\n", c);
        cancel_connection(ev_data);
        return -1;
    }

    return 0;
}

/* Calculates the number of bytes are in the URL decoded data and checks
 * whether each byte is allowed by the whitelist. */
size_t url_encode_buf_len_whitelist(char *data, size_t len,
        struct event_data *ev_data, const char *whitelist) {
    size_t ret_len = len;
    char *data_end = data + len;
    char byte;
    while (data < data_end) {
        if (*data == '%') { /* URL encoded byte */
            if (data + 2 < data_end && sscanf(data + 1, "%02hhx", &byte) == 1) {
                data += 3;
                ret_len -= 2;
#if ENABLE_PARAM_WHITELIST_CHECK
                if (check_char_whitelist(whitelist, byte, ev_data) < 0) {
                    return 0;
                }
#endif
            } else {
                log_warn("Invalid URL encoding found during length check\n");
                cancel_connection(ev_data);
                return 0;
            }
        } else {
#if ENABLE_PARAM_WHITELIST_CHECK
            if (check_char_whitelist(whitelist, *data, ev_data) < 0) {
                return 0;
            }
#endif
            data++;
        }
    }
    return ret_len;
}

/* Returns whether character is allowed according to whitelist */
bool whitelist_char_allowed(const char *whitelist, const char x) {
    unsigned const char c = (unsigned const char) x;
    unsigned int byte = c / 8;
    unsigned int bit = c % 8;
    unsigned char mask = 1 << bit;
    return (whitelist[byte] & mask) != 0;
}

/* Enforce maximum parameter length */
void check_arg_len_whitelist(struct params *param, char *value,
        size_t value_len, struct event_data *ev_data) {
    size_t url_decode_len = url_encode_buf_len_whitelist(value, value_len,
            ev_data, param->whitelist);
    log_dbg("  decode_len=%zd\n", url_decode_len);
    if (url_decode_len > param->max_param_len) {
        log_warn("Length of parameter value \"%.*s\" %zd exceeds max %d\n",
                (int) value_len, value, url_decode_len, param->max_param_len);
        cancel_connection(ev_data);
    }
}

/* Perform argument specific checks */
void check_single_arg(struct event_data *ev_data, char *arg, size_t len) {
    log_dbg("arg=\"%.*s\", len=%zd\n", (int) len, arg, len);

    if (len < 0) {
        log_warn("Malformed argument\n");
        cancel_connection(ev_data);
    }

    char *name = arg, *value;
    size_t name_len, value_len; // Length of buffers

    parse_argument_name_value(arg, len, &name, &name_len, &value, &value_len);

    log_dbg("  name=\"%.*s\" len=%zd, value=\"%.*s\" len=%zd\n", (int) name_len,
            name, name_len, (int) value_len, value, value_len);

    struct page_conf *page_match = ev_data->conn_info->page_match;

#if ENABLE_CSRF_PROTECTION
    /* Check if argument is CSRF token */
    if (page_match->receives_csrf_form_action
            && name_len == CSRF_TOKEN_NAME_LEN
            && memcmp(name, CSRF_TOKEN_NAME, CSRF_TOKEN_NAME_LEN) == 0) {

        /* Check that valid session cookie was sent */
        if (!ev_data->conn_info->session) {
            log_warn("Request did not have a valid session cookie, which "
                    "is required on pages that receive CSRF form action\n");
            cancel_connection(ev_data);
            return;
        }

        /* Check that CSRF token matches SESSION_ID */
        if (SHIM_SESSID_LEN != value_len
                || memcmp(value, ev_data->conn_info->session->session_id,
                SHIM_SESSID_LEN) != 0) {
            log_warn("Invalid CSRF token found\n");
            cancel_connection(ev_data);
        } else {
            log_trace("Correct CSRF token found\n");
            ev_data->found_csrf_correct_token = true;
        }
        return;
    }
#endif

    struct params *param = find_matching_param(name, name_len,
            page_match->params, page_match->params_len, ev_data);

    if (param == NULL) {
        if (page_match->restrict_params) {
            log_warn("Parameter sent when not allowed\n");
            cancel_connection(ev_data);
            return;
        } else {
            param = &ev_data->conn_info->default_params;
        }
    }
    log_trace("Using param \"%s\"\n", param->name ? param->name : "default");

#if ENABLE_PARAM_LEN_CHECK || ENABLE_PARAM_WHITELIST_CHECK
    check_arg_len_whitelist(param, value, value_len, ev_data);
#endif
}

/* Check parameters passed in the URL */
void check_buffer_params(bytearray_t *buf, bool is_url_param,
        struct event_data *ev_data) {
    log_trace("Checking %s parameters\n", is_url_param ? "URL" : "POST");
    char *query;
    size_t query_len;

    if (is_url_param) {
        char *quest = memchr(buf->data, '?', buf->len);
        if (quest == NULL) {
            log_trace("URL has no parameters\n");
            return;
        }
        query = quest + 1;
        query_len = buf->len - (query - buf->data);
    } else {
        query = buf->data;
        query_len = buf->len;
    }

    if (query_len <= 0) {
        log_trace("Empty query\n");
    }

    log_dbg("query: \"%.*s\", len=%zd\n", (int) query_len, query, query_len);

    /* Examine each query parameter */
    char *next = memchr(query, '&', query_len);
    size_t arg_len;
    while (query_len >= 0) {
        arg_len = next ? (next - query) : query_len;

        check_single_arg(ev_data, query, arg_len);

        if (next == NULL) {
            break;
        }

        query_len -= arg_len + 1;
        query = next + 1;
        next = memchr(query, '&', query_len);
    }
}

/* Cancels connection if url contains ".." */
#if ENABLE_URL_DIRECTORY_TRAVERSAL_CHECK
void check_url_dir_traversal(struct event_data *ev_data) {
    log_trace("Checking URL for directory traversal attack\n");
    char *data = ev_data->url->data;
    int num_dots = 0;
    char byte;
    char *data_end;

    /* Do not look at URL parameters */
    char *quest = memchr(data, '?', ev_data->url->len);
    data_end = (quest ? quest : data + ev_data->url->len);


    while (data < data_end) {
        if (*data == '%') { /* URL encoded byte */
            if (data + 2 < data_end && sscanf(data + 1, "%02hhx", &byte) == 1) {
                if (byte == '.') {
                    num_dots++;
                }
                data += 3;
            } else {
                log_warn("Invalid URL encoding found during length check\n");
                cancel_connection(ev_data);
            }
        } else {
            if (*data == '.') {
                num_dots++;
            }
            data++;
        }

        if (num_dots >= 2) {
            log_warn("Possible URL directory traversal blocked\n");
            cancel_connection(ev_data);
            return;
        }
    }
}
#endif


/* Fills buffer with random bytes from /dev/urandom. Returns 0 on success and
 * -1 on failure. */
int fill_rand_bytes(char *buf, size_t len) {
    int rc = 0;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }
    if (read(fd, buf, len) != len) {
        log_error("Did not read enough bytes from /dev/urandom\n");
        rc = -1;
    }
    if (close(fd) < 0) {
        perror("close");
        rc = -1;
    }
    return rc;
}

/* Do checks that are possible after the header is received */
void do_client_header_complete_checks(struct event_data *ev_data) {
    ev_data->conn_info->page_match = url_find_matching_page(
            (char *) ev_data->url->data,
            ev_data->url->len);
    log_trace("page_match=\"%s\"\n", ev_data->conn_info->page_match->name);

    copy_default_params(ev_data->conn_info->page_match,
            &ev_data->conn_info->default_params);

#if ENABLE_REQUEST_TYPE_CHECK
    check_request_type(ev_data);
#endif

#if ENABLE_URL_DIRECTORY_TRAVERSAL_CHECK
    check_url_dir_traversal(ev_data);
#endif

#if ENABLE_PARAM_CHECKS
    /* Check URL parameters */
    check_buffer_params(ev_data->url, true, ev_data);
#endif

#if ENABLE_SESSION_TRACKING
    find_session_from_cookie(ev_data);
#endif
}

/* Finishes server event if it was not finished previously. Returns 0 on
 * success, -1 otherwise. */
int flush_server_event(struct event_data *server_ev_data) {
    log_trace("Got request on socket that has already processed a response;"
                    " Finishing parsing and clearing connection info\n");
    if (!server_ev_data->msg_complete) {
        /* Finish parsing if it has not already completed */
        size_t nparsed = http_parser_execute(&server_ev_data->parser,
                &server_parser_settings, NULL, 0);
        (void) nparsed; // Suppress unused variable warning

        if (is_conn_cancelled(server_ev_data)) {
            return -1;
        }

        enum http_errno hte = HTTP_PARSER_ERRNO(&server_ev_data->parser);
        if (hte != HPE_OK) {
            log_warn("Error during HTTP parsing\n");
            log_warn("%s: %s\n", http_errno_name(hte),
                    http_errno_description(hte));
            cancel_connection(server_ev_data);
            return -1;
        }
    }

#if ENABLE_CSRF_PROTECTION
    if (!server_ev_data->chunked_encoding_specified) {
        check_send_csrf_js_snippet(server_ev_data);
    }
#endif

    reset_connection_info(server_ev_data->conn_info);
    return 0;
}

/* Handles incoming client requests.
 * Returns boolean indicated if connection is done */
int handle_client_server_event(struct epoll_event *ev) {
    int done = 0;
    ssize_t count;
    char buf[READ_BUF_SIZE];

    struct event_data *ev_data = (struct event_data *) ev->data.ptr;
    ev_data->got_eagain = false; // Reset on each handle call
    event_t type = ev_data->type;
    bytearray_t *headers_cache = ev_data->headers_cache;

    /* Reset conn info if already processed a response */
    if (type == CLIENT_LISTENER
            && ev_data->conn_info->server_ev_data->msg_begun) {
        struct event_data *server_ev_data = ev_data->conn_info->server_ev_data;

        /* Ensure that JS snippet is sent, regardless of eagain having
         * occurred */
        server_ev_data->got_eagain = false;

        if (flush_server_event(server_ev_data) < 0) {
            goto check_cancelled;
        }
    }

    log_trace("*****HANDLING EVENT TYPE %s*****\n",
            type == CLIENT_LISTENER ? "REQUEST" : "RESPONSE");

    http_parser_settings *parser_settings;
    if (type == CLIENT_LISTENER) {
        parser_settings = &client_parser_settings;
    } else { // type == SERVER_LISTENER
        parser_settings = &server_parser_settings;
    }

    /* Read into buffer */
    while (!done) {
        bool eagain = false;
        count = fd_ctx_read(&ev_data->listen_fd, buf, READ_BUF_SIZE, &eagain);
        if (count < 0) {
            if (eagain) {
                /* We have read all data for now */
                log_dbg("Got EAGAIN on read\n");
                ev_data->got_eagain = true;
                done = 1;
                break;
            } else {
                /* Error occurred reading */
                cancel_connection(ev_data);
                done = 1;
                break;
            }
            break;
        } else if (count == 0) {
            /* End of file. The remote has closed the connection. */
            done = 1;
        }


        /* Do not have all headers cached yet */
        if (!ev_data->headers_have_been_sent) {
            log_dbg("Caching message headers\n");
            if (bytearray_append(headers_cache, buf, count) < 0) {
                log_error("bytearray_append failed\n");
                cancel_connection(ev_data);
                done = 1;
                break;
            }

            /* Make safe to use C string funtions on bytearray until modified */
            if (bytearray_nul_terminate(headers_cache) < 0) {
                log_error("bytearray_nul_terminate failed\n");
                cancel_connection(ev_data);
                done = 1;
                break;
            }

            char *crlf_end = strstr(headers_cache->data, CRLF CRLF);
            char *lf_end = strstr(headers_cache->data, LF LF);
            if (crlf_end || lf_end) {
                char *body_ptr = NULL;
                size_t body_len = 0;
                /* Set newline type */
                if (crlf_end) {
                    /* CRLF line endings */
                    ev_data->http_msg_newline = CRLF;
                    body_ptr = crlf_end + strlen(CRLF CRLF);

                } else {
                    /* LF line endings */
                    ev_data->http_msg_newline = LF;
                    body_ptr = lf_end + strlen(LF LF);
                }
                size_t headers_len = body_ptr - headers_cache->data;
                body_len = headers_cache->len - headers_len;

                done |= do_http_parse_send(headers_cache->data,
                        headers_len, body_ptr, 0,
                        ev_data, parser_settings, true);

                /* Done with the headers cache */
                ev_data->headers_have_been_sent = true;

                /* Handle body after headers */
                log_dbg("Sending body after headers\n");

#if ENABLE_SESSION_TRACKING
                if (ev_data->chunked_encoding_specified) {
                    done |= handle_chunked_parse_send(body_ptr, body_len,
                            parser_settings, ev_data);
                    continue;
                }
#endif

                if (body_len > 0) {
                    done |= do_http_parse_send(NULL, 0, body_ptr, body_len,
                            ev_data, parser_settings, false);
                }

                continue;
            }

            /* Do not have all headers yet */

            /* Check if headers are too large */
            if (headers_cache->len > MAX_HTTP_RESPONSE_HEADERS_SIZE) {
                log_warn("End of Headers not found after %d bytes into "
                        "response; ""aborting\n",
                        MAX_HTTP_RESPONSE_HEADERS_SIZE);
                cancel_connection(ev_data);
                done = 1;
                break;
            }

            log_dbg("All response headers not received yet\n");
            continue;
        }

        log_dbg("Sending data normally\n");

#if ENABLE_SESSION_TRACKING
        if (ev_data->chunked_encoding_specified) {
            done |= handle_chunked_parse_send(buf, count, parser_settings,
                    ev_data);
            continue;
        }
#endif

        done |= do_http_parse_send(NULL, 0, buf, count, ev_data,
                parser_settings, false);
    }


#if ENABLE_CSRF_PROTECTION
    /* Send CSRF token JavaScript snippet */
    if (!ev_data->chunked_encoding_specified) {
        done |= check_send_csrf_js_snippet(ev_data);
    }
#endif

check_cancelled:
    if (type == CLIENT_LISTENER && is_conn_cancelled(ev_data)) {
        if (send_error_page(&ev_data->listen_fd)) {
            log_info("Failed to send error page.\n");
        }
        close(ev_data->listen_fd.sock_fd);
        close(ev_data->send_fd.sock_fd);
        ev_data->listen_fd.sock_fd = 0;
        ev_data->send_fd.sock_fd = 0;
        log_info("Closed_connection\n");
        return 1;
    }

    return done;
}

#if ENABLE_SESSION_TRACKING
/* Handles sending/parsing when chunked encoding is used. */
int handle_chunked_parse_send(char *buf, size_t buf_len,
        http_parser_settings *parser_settings, struct event_data *ev_data) {

    size_t add_bytes;
    char *cr;
    bool fallthrough;
    bool finished_last_chunk = false;
    uint64_t chunk_bytes;
    int done = 0;

    log_trace("Handling chunked encoding\n");

    while (buf_len > 0 && !finished_last_chunk) {
        switch (ev_data->chunk_state) {
        case CHUNK_SZ: /* Still getting chunk size */
            log_dbg("  Getting chunk size\n");

            /* buf points to digits CR */

            if ((cr = memchr(buf, '\r', buf_len)) != NULL) {
                /* Found CR, will move to next state*/
                add_bytes = cr - buf;
                fallthrough = true;
                ev_data->chunk_state = CHUNK_SZ_LF;
            } else {
                /* Did not find CR */
                add_bytes = buf_len;
                fallthrough = false;
            }
            if (bytearray_append(ev_data->chunk, buf, add_bytes) < 0) {
                goto error;
            }

            buf += add_bytes;
            buf_len -= add_bytes;

            if (ev_data->chunk->len > MAX_CHUNK_SIZE_LEN) {
                log_warn("Did not find CR in chunk header after %zd bytes\n",
                        ev_data->chunk->len);
                goto error;
            }

            if (!fallthrough) {
                /* buf_len may be 0 if CR was not found. Because buf_len is
                 * unsigned, and we check if it is > 0, we need to make sure it
                 * does not wrap around. */
                continue;
            }

            /* Shift stream forward past CR */
            log_dbg("  Got chunk size CR\n");
            buf += 1;
            buf_len -= 1;

            /* Check if buf_len is 0 */
            continue;

        case CHUNK_SZ_LF:
            /* Got CR, waiting for LF; buf points to LF */
            if (*buf != '\n') {
                log_warn("Did not find expected LF in chunk header\n");
                goto error;
            }

            ev_data->chunk_state = CHUNK_BODY;
            buf += 1;
            buf_len -= 1;

            /* buf points to body */

            /* Got LF, waiting for body */
            log_dbg("  Got chunk size LF, reading chunk size\n");

            /* Add header CRLF */
            if (bytearray_append(ev_data->chunk, CRLF, 2) < 0) {
                goto error;
            }

            /* Make it safe to use C string functions */
            if (bytearray_nul_terminate(ev_data->chunk) < 0) {
                goto error;
            }

            /* Read chunk size */
            if (sscanf(ev_data->chunk->data, "%" SCNx64 CRLF,
                    &ev_data->remaining_chunk_bytes) != 1) {
                perror("sscanf");
                log_error("Reading chunk size failed\n");
                goto error;
            }

            log_dbg("    chunk size=%zd\n", ev_data->remaining_chunk_bytes);

            if (ev_data->remaining_chunk_bytes == 0) {
                log_dbg("  Found last chunk\n");
                ev_data->on_last_chunk = true;
                check_send_csrf_js_snippet(ev_data);

                /* Skip CHUNK_BODY state */
                ev_data->chunk_state = CHUNK_BODY_CR;
            }

            /* Send chunk header */
            done |= do_http_parse_send(NULL, 0, ev_data->chunk->data,
                    ev_data->chunk->len, ev_data, parser_settings, false);
            if (done) {
                goto error;
            }

            continue;

        case CHUNK_BODY:
            /* buf points to body */

            chunk_bytes = MIN(buf_len, ev_data->remaining_chunk_bytes);

            log_dbg("  processing body chunk len %" PRId64 "\n", chunk_bytes);

            done |= do_http_parse_send(NULL, 0, buf, chunk_bytes, ev_data,
                    parser_settings, false);
            if (done) {
                goto error;
            }

            ev_data->remaining_chunk_bytes -= chunk_bytes;
            buf += chunk_bytes;
            buf_len -= chunk_bytes;

            if (ev_data->remaining_chunk_bytes == 0) {
                /* Chunk body is finished */
                ev_data->chunk_state = CHUNK_BODY_CR;
            }

            continue;

        case CHUNK_BODY_CR:
            log_dbg("  processing traliing body CR\n");

            if (*buf != '\r') {
                log_warn("Did not find expected CR after chunk body\n");
                goto error;
            }

            buf += 1;
            buf_len -= 1;
            ev_data->chunk_state = CHUNK_BODY_LF;

            continue;

        case CHUNK_BODY_LF:
            log_dbg("  processing traliing body LF\n");

            if (*buf != '\n') {
                log_warn("Did not find expected LF after chunk body\n");
                goto error;
            }

            buf += 1;
            buf_len -= 1;

            /* Send trailing CRLF */
            done |= do_http_parse_send(NULL, 0, CRLF, 2, ev_data,
                parser_settings, false);
            if (done) {
                goto error;
            }

            /* Reset chunk state */
            ev_data->chunk_state = CHUNK_SZ;
            if (bytearray_clear(ev_data->chunk) < 0) {
                goto error;
            }

            if (ev_data->on_last_chunk) {
                finished_last_chunk = true;
            }

            continue;

        default:
            log_error("Unhandled chunk state");
        }
    }

    return done;

error:
    cancel_connection(ev_data);
    return 1;
}
#endif

#if ENABLE_CSRF_PROTECTION
/* Sends CSRF JS snippet if page is configured for it */
int check_send_csrf_js_snippet(struct event_data *ev_data) {
    int done = 0;
    bytearray_t *send_array = NULL;

    log_dbg("Checking if page has CSRF protection\n");
    if (ev_data->type == SERVER_LISTENER && !is_conn_cancelled(ev_data)
            && ev_data->conn_info->page_match
            && ev_data->conn_info->page_match->has_csrf_form
            && !ev_data->sent_js_snippet
            && (ev_data->msg_complete || ev_data->chunked_encoding_specified)) {
        log_trace("Page has CSRF protected form; sending JS snippet\n");
        int s;
        char js_snippet[INSERT_HIDDEN_TOKEN_JS_STRLEN + 10];
        char header_buf[20];
        int snippet_len = snprintf(js_snippet, sizeof(js_snippet),
                INSERT_HIDDEN_TOKEN_JS_FORMAT,
                ev_data->conn_info->session->session_id);
        if (snippet_len >= sizeof(js_snippet) || snippet_len < 0) {
            perror("snprintf");
            goto error;
        }

        if ((send_array = bytearray_new()) == NULL) {
            goto error;
        }

        /* Send header if chunked encoding */
        if (ev_data->chunked_encoding_specified) {
            /* Write hex length to buffer with CRLF */
            int header_buf_len = snprintf(header_buf, sizeof(header_buf),
                    "%x\r\n", snippet_len);
            if (header_buf_len >= sizeof(header_buf) || header_buf_len < 0) {
                log_error("chunked header buffer too small\n");
                goto error;
            }

            /* Add buffer to send array */
            if (bytearray_append(send_array, header_buf, header_buf_len) < 0) {
                goto error;
            }
        }

        /* Add JS snippet */
        if (bytearray_append(send_array, js_snippet, snippet_len) < 0) {
            goto error;
        }

        /* Add trailing CRLF */
        if (ev_data->chunked_encoding_specified) {
            if (bytearray_append(send_array, CRLF, strlen(CRLF)) < 0) {
                goto error;
            }
        }

        s = sendall(&ev_data->send_fd, send_array->data, send_array->len);
        if (s < 0) {
            goto error;
        }

        ev_data->sent_js_snippet = true;
    } else {
        log_dbg("Not sending JS snippet\n");
    }

    bytearray_free(send_array);
    return done;

error:
    bytearray_free(send_array);
    cancel_connection(ev_data);
    return 1;
}
#endif

/* Parse http buffer and run checks.
 * headers_buf is the buffer containing the first line and all headers of the
 *      HTTP message. It is also expected to have the contents of body_buf after
 *      the headers (body_buf should be a pointer to the inside of headers_buf
 *      if headers_buf is passed).
 * body_buf is the buffer containing all data after headers.
 * send_headers is a boolean indicating whether the headers should be sent,
 *      which should only be set to true on the first call for a message (the
 *      headers should only be sent once)
 * Returns done state sending on socket. */
int do_http_parse_send(char *headers_buf, size_t header_buf_len, char *body_buf,
        size_t body_buf_len, struct event_data *ev_data,
        http_parser_settings *parser_settings,
        bool send_headers) {
    int s;

    char *parse_buf;
    size_t parse_len;

    if (send_headers) {
        parse_buf = headers_buf;
        parse_len = header_buf_len;
    } else {
        parse_buf = body_buf;
        parse_len = body_buf_len;
    }

    /* Do HTTP parsing */
    size_t nparsed = http_parser_execute(&ev_data->parser, parser_settings,
            parse_buf, parse_len);
    (void) nparsed; // Suppress unused variable warning

    log_trace("Parsed %zd / %zd bytes\n", nparsed, parse_len);

    enum http_errno hte = HTTP_PARSER_ERRNO(&ev_data->parser);
    if (hte != HPE_OK) {
        log_warn("Error during HTTP parsing\n");
        log_warn("%s: %s\n", http_errno_name(hte), http_errno_description(hte));
        cancel_connection(ev_data);
        return 1;
    }

    if (ev_data->parser.upgrade) {
        /* Wants to upgrade connection */
        log_warn("HTTP upgrade not supported\n");
        cancel_connection(ev_data);
        return 1;
    }

    if (is_conn_cancelled(ev_data)) {
        return 1;
    }

    if (send_headers) {

#if ENABLE_SESSION_TRACKING
        /* Add Set-Cookie header */
        if (ev_data->type == SERVER_LISTENER
                && add_set_cookie_header(ev_data) < 0) {
            return 1;
        }

        /* Remove SHIM_SESSID cookie from Cookie header */
        if (ev_data->type == CLIENT_LISTENER
                && ev_data->cookie_header_value_ref != NULL
                && remove_shim_sessid_cookie(ev_data) < 0) {
            return 1;
        }

        /* Modify Content-Length header as needed */
        if (set_new_content_length(ev_data) < 0) {
            return 1;
        }
#endif

        send_http_headers(ev_data);
    }

    /* Send rest of buf */
    s = sendall(&ev_data->send_fd, body_buf, body_buf_len);
    if (s < 0) {
        log_error("sendall failed\n");
        cancel_connection(ev_data);
        return 1;
    }

    return 0;
}

/* Handle epoll event */
void handle_event(int efd, struct epoll_event *ev, int sfd_http, int sfd_tls) {
    int done;
    struct event_data *ev_data = (struct event_data *) (ev->data.ptr);
    int listen_sock = ev_data->listen_fd.sock_fd;

    if ((ev->events & EPOLLERR) || (ev->events & EPOLLHUP)
            || (!(ev->events & EPOLLIN))) {
        /* An error has occured on this fd, or the socket is not
         ready for reading (why were we notified then?) */
        log_error("epoll error\n");
        free_connection_info(ev_data->conn_info);
        ev->data.ptr = NULL;
        return;

    } else if (sfd_http == listen_sock || sfd_tls == listen_sock) {
        /* We have a notification on a listening socket, which
         means one or more incoming connections. */

        bool is_tls = (sfd_tls == listen_sock);
        int sfd = ev_data->listen_fd.sock_fd;
        if (handle_new_connection(efd, ev, sfd, is_tls) < 0) {
            free_connection_info(ev_data->conn_info);
            ev->data.ptr = NULL;
        }
        return;
    } else if (ev->data.ptr != NULL) {
        /* We have data on the fd waiting to be read. Read and
         display it. We must read whatever data is available
         completely, as we are running in edge-triggered mode
         and won't get a notification again for the same
         data. */

        if (ev_data->type == CLIENT_LISTENER
                || ev_data->type == SERVER_LISTENER) {
            done = handle_client_server_event(ev);
        } else {
            log_error("Invalid event_data type \"%d\"\n", ev_data->type);
            done = 1;
        }

        if (is_conn_cancelled(ev_data) || (done && !ev_data->got_eagain)) {
            free_connection_info(ev_data->conn_info);
            ev->data.ptr = NULL;
        }
    } else {
        log_error("Unhandled epoll event\n");
    }

}

/* Handler for SIGINT */
void sigint_handler(int dummy) {
    sigint_received = true;
}

/* Initialize structures for walking pages */
int init_page_conf() {
    // @Todo(Travis) Create trie to index pages
    return 0;
}


#if ENABLE_HTTPS
/* Tries to initialize SSL ctx. Returns 0 on success, -1 otherwise. */
int init_ssl_ctx() {
    /* Initialize server context */
    //@Todo(Travis) make the TLS version configurable
    ssl_ctx_server = SSL_CTX_new(TLSv1_server_method());
    if (ssl_ctx_server == NULL) {
        log_ssl_error("Server SSL_CTX_new() failed\n");
        return -1;
    }

    /* Generate new DH key each time */
    SSL_CTX_set_options(ssl_ctx_server, SSL_OP_SINGLE_DH_USE);
    SSL_CTX_set_options(ssl_ctx_server, SSL_OP_NO_SSLv2);

    /* Pass in the server certificate chain file */
    if (SSL_CTX_use_certificate_chain_file(ssl_ctx_server,
                    tls_cert_file) != 1) {
        log_ssl_error("SSL_CTX_use_certificate_chain_file(\"%s\") failed\n",
                tls_cert_file);
        return -1;
    }

    /* Pass in the server private key */
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx_server,
                    tls_key_file, SSL_FILETYPE_PEM) != 1) {
        log_ssl_error("SSL_CTX_use_PrivateKey_file(\"%s\") failed\n",
                tls_key_file);
        return -1;
    }

    /* Verify private key */
    if (!SSL_CTX_check_private_key(ssl_ctx_server)) {
        log_error("Private key does not match the certificate\n");
        return -1;
    }

    // Load trusted root authorities ??

    /* Initialize client context */
    ssl_ctx_client = SSL_CTX_new(TLSv1_client_method());
    if (ssl_ctx_server == NULL) {
        log_ssl_error("Client SSL_CTX_new() failed\n");
        return -1;
    }

    SSL_CTX_set_options(ssl_ctx_client, SSL_OP_NO_SSLv2);

    return 0;
}

void print_openssl_info() {
    log_dbg("OpenSSL information:\n");
    log_dbg("  %s\n", SSLeay_version(SSLEAY_VERSION));
    log_dbg("  %s\n", SSLeay_version(SSLEAY_CFLAGS));
    log_dbg("  %s\n", SSLeay_version(SSLEAY_BUILT_ON));
    log_dbg("  %s\n", SSLeay_version(SSLEAY_PLATFORM));
}

/* Initialize OpenSSL */
int init_ssl() {
    print_openssl_info();

    CRYPTO_malloc_init();

    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();

    if (init_ssl_ctx() < 0) {
        return -1;
    }

    return 0;
}

/* Free memory associated with OpenSSL */
void free_ssl() {
    SSL_CTX_free(ssl_ctx_server);
    SSL_CTX_free(ssl_ctx_client);

    ENGINE_cleanup();
    CONF_modules_unload(1);
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();

    /* Free ssl_comp_methods stack and its elements */
    sk_SSL_COMP_pop_free(SSL_COMP_get_compression_methods(),
            (void (*)(SSL_COMP *) ) CRYPTO_free);

    ERR_remove_state(0); /* Free state of current thread */
    ERR_free_strings();
}
#endif


/* Do main initialization */
int init_structures(char *error_page_file) {
    if (init_error_page(error_page_file) < 0) {
        return -1;
    }

    init_config_vars();

    if (init_page_conf() < 0) {
        return -1;
    }

#if ENABLE_SESSION_TRACKING
    memset(current_sessions, 0, sizeof(current_sessions));
#endif

#if ENABLE_HTTPS
    if (init_ssl() < 0) {
        return -1;
    }
#endif

    return 0;
}

void parse_program_arguments_error(char **argv) {
    print_usage(argv);
    exit(EXIT_FAILURE);
}

/* Print usage information for shim */
void print_usage(char **argv) {
    printf("Shim %s\n", SHIM_VERSION);
    printf("Usage: %s <REQUIRED ARGUMENTS> [OPTIONAL ARGUMENTS]\n",
            argv[0]);
    printf("\n");

    printf("Required arguments:\n");
    ARGUMENT_MAP(PRINT_USAGE_REQUIRED_LAMBDA);
    printf("\n");

    printf("Optional arguments:\n");
    ARGUMENT_MAP(PRINT_USAGE_OPTIONAL_LAMBDA);
    printf("\n");
}

/* Parses program arguments, setting the option variables. Returns 0 on success,
 * -1 otherwise.
 */
int parse_program_arguments(int argc, char **argv) {
    int c, i;

    struct option long_options[] = {
        ARGUMENT_MAP(GETOPT_OPTIONS_LAMBDA)
        { 0, 0, 0, 0 }
    };

    struct variable_enabled variable_arr[] = {
        ARGUMENT_MAP(ARG_VARIABLE_LAMBDA)
    };

    while (1) {
        int option_index = 0;

        /* '-' causes getopt_long to return 1 for extra arguments */
        char optstring[] = "-";

        c = getopt_long_only(argc, argv, optstring, long_options, &option_index);

        /* Detect the end of the options. */
        if (c == -1) {
            break;
        }

        switch (c) {
        case 0:
            if (long_options[option_index].has_arg == required_argument
                    && optarg == NULL) {
                log_error("getopt_long did not set optarg\n");
                return -1;
            }
            if (variable_arr[option_index].enabled) {
                if (long_options[option_index].has_arg == no_argument) {
                    *((bool *) variable_arr[option_index].variable) = true;
                } else if (long_options[option_index].has_arg
                        == required_argument) {
                    *((char **) variable_arr[option_index].variable) = optarg;
                } else {
                    log_error("Unhandled has_arg case\n");
                }
            } else {
                parse_program_arguments_error(argv);
            }
            break;

        case 1:
            /* Argument without corresponding option */
            /* Fallthrough to error case*/
        case '?':
            parse_program_arguments_error(argv);
            break;

        default:
            log_error("getopt() parsing case %d not handled "
                    "unexpectedly\n", c);
            return -1;
        }
    }

    if (print_config) {
        print_configuration();
        exit(EXIT_SUCCESS);
    }

    bool found_error = false;
    int len = sizeof(variable_arr) / sizeof(struct variable_enabled);
    for (i = 0; i < len; i++) {
        struct variable_enabled *var = &variable_arr[i];
        if (var->enabled && var->required
                && *((char **) var->variable) == NULL) {
            found_error = true;
            printf("Argument \"--%s\" not specified\n", long_options[i].name);
        }
    }

    if (found_error) {
        print_usage(argv);
        exit(EXIT_FAILURE);
    }

    log_dbg("Running with arguments:\n");
    ARGUMENT_MAP(PRINT_ARGS_LAMBDA);

    return 0;
}

/* Set up non-blocking listener on given port. Returns the listening socket
 * file descriptor on success, -1 otherwise.
 */
int set_up_socket_listener(char *port_str) {
    int s, sfd;

    sfd = create_and_bind(port_str);
    if (sfd == -1) {
        return -1;
    }

    s = make_socket_non_blocking(sfd);
    if (s == -1) {
        return -1;
    }

    s = listen(sfd, SOMAXCONN);
    if (s == -1) {
        perror("listen");
        return -1;
    }

    return sfd;
}

/* Initializes listening epoll_event with socket sfd. Returns 0 on success,
 * -1 otherwise.
 */
int init_listen_event_data(struct epoll_event *e, int efd, int sfd) {
    int s;

    e->data.ptr = calloc(1, sizeof(struct event_data));
    if (e->data.ptr == NULL) {
        perror("calloc");
        return -1;
    }

    ((struct event_data *) e->data.ptr)->listen_fd.sock_fd = sfd;

    e->events = EPOLLIN | EPOLLET;
    s = epoll_ctl(efd, EPOLL_CTL_ADD, sfd, e);
    if (s == -1) {
        perror("epoll_ctl");
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[]) {
    int sfd_http = -1, sfd_tls = -1;
    int efd = -1;
    struct epoll_event event_http;
    struct epoll_event *events = NULL;
#if ENABLE_HTTPS
    struct epoll_event event_tls;
#endif

    memset(&event_http, 0, sizeof(struct epoll_event));

#if ENABLE_HTTPS
    memset(&event_tls, 0, sizeof(struct epoll_event));
#endif

    if (parse_program_arguments(argc, argv) < 0) {
        goto finish;
    }

    if (signal(SIGINT, sigint_handler) < 0) {
        perror("signal");
        goto finish;
    }

    if (init_structures(error_page_file) < 0) {
        goto finish;
    }

    /* Set up HTTP listener */
    sfd_http = set_up_socket_listener(shim_http_port_str);
    if (sfd_http < 0) {
        goto finish;
    }

#if ENABLE_HTTPS
    /* Set up HTTPS listener */
    sfd_tls = set_up_socket_listener(shim_tls_port_str);
    if (sfd_tls < 0) {
        goto finish;
    }
#endif

    efd = epoll_create(20);
    if (efd == -1) {
        perror("epoll_create");
        goto finish;
    }

    if (init_listen_event_data(&event_http, efd, sfd_http) < 0) {
        goto finish;
    }

#if ENABLE_HTTPS
    if (init_listen_event_data(&event_tls, efd, sfd_tls) < 0) {
        goto finish;
    }
#endif

    /* Buffer where events are returned */
    events = calloc(MAXEVENTS, sizeof(struct epoll_event));
    if (events == NULL) {
        goto finish;
    }

    /* The event loop */
    while (!sigint_received) {
        int n, i;

        /* Block indefinitely */
        n = epoll_wait(efd, events, MAXEVENTS, -1);

        if (sigint_received) {
            break;
        }

#if ENABLE_SESSION_TRACKING
        /* Set time for tracking session expiration */
        time(&current_time);
        next_session_expiration_time = current_time + SESSION_LIFE_SECONDS;

        expire_sessions();
#endif

        for (i = 0; i < n; i++) {
            handle_event(efd, &events[i], sfd_http, sfd_tls);
        }

        log_trace("Number of active connections = %d\n", num_conn_infos);

#if ENABLE_SESSION_TRACKING
        log_trace("Now tracking %d active sessions\n",
                get_num_active_sessions());
#endif
    }

finish:
    close_fd_if_valid(efd);
    close_fd_if_valid(sfd_http);
    free(events);
    free(event_http.data.ptr);
    free(error_page_buf);

#if ENABLE_HTTPS
    close_fd_if_valid(sfd_tls);
    free(event_tls.data.ptr);
    free_ssl();
#endif

    return EXIT_SUCCESS;
}
