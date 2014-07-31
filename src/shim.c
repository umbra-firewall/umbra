#include <errno.h>
#include "shim.h"
#include "config.h"
#include "http_callbacks.h"
#include "http_util.h"
#include "net_util.h"
#include "shim_struct.h"
#include "log.h"

int connction_num = 0;
char *http_port_str, *server_http_port_str;

bool sigint_received = false;

#ifdef TRACE
int num_conn_infos = 0;
#endif

http_parser_settings client_parser_settings = {
    .on_message_begin = on_message_begin_cb,
    .on_url = on_url_cb,
    .on_status = NULL,

#if ENABLE_HEADER_FIELD_CHECK
    .on_header_field = on_header_field_cb,
#else
    .on_header_field = NULL,
#endif

#if ENABLE_HEADER_VALUE_CHECK
    .on_header_value = on_header_value_cb,
#else
    .on_header_value = NULL,
#endif

    .on_headers_complete = on_headers_complete_cb,
    .on_body = on_body_cb,
    .on_message_complete = on_message_complete_cb
};

http_parser_settings server_parser_settings = {
    .on_message_begin = on_message_begin_cb,
    .on_url = NULL,
    .on_status = on_status_cb,

#if ENABLE_HEADER_FIELD_CHECK
    .on_header_field = on_header_field_cb,
#else
    .on_header_field = NULL,
#endif

#if ENABLE_HEADER_VALUE_CHECK
    .on_header_value = on_header_value_cb,
#else
    .on_header_value = NULL,
#endif

    .on_headers_complete = on_headers_complete_cb,
    .on_body = on_body_cb,
    .on_message_complete = on_message_complete_cb
};


/* Set connection to cancelled state */
void cancel_connection(struct event_data *ev_data) {
    log_trace("Cancelling connection\n.");
    ev_data->is_cancelled = true;
}

/* Returns whether connection is cancelled */
bool is_conn_cancelled(struct event_data *ev_data) {
    if (ev_data->is_cancelled) {
        return true;
    } else {
        return false;
    }
}

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
#if ENABLE_SESSION_TRACKING
void check_header_pair(struct event_data *ev_data) {
    char *field = ev_data->header_field->data;
    char *value = ev_data->header_value->data;
    size_t field_len = ev_data->header_field->len;
    size_t value_len = ev_data->header_value->len;

    /* NUL terminate header field and value */
    if (bytearray_append(ev_data->header_field, "\0", 1) < 0) {
        log_error("Could not append to bytearray\n");
        cancel_connection(ev_data);
        return;
    }
    if (bytearray_append(ev_data->header_value, "\0", 1) < 0) {
        log_error("Could not append to bytearray\n");
        cancel_connection(ev_data);
        return;
    }

    log_trace("Header: \"%s\": \"%s\"\n", ev_data->header_field->data,
            ev_data->header_value->data);


    if (ev_data->type == CLIENT_LISTENER ) {
        /* Request Headers */

        /* Handle Cookie header */
        if (field_len == COOKIE_HEADER_STRLEN
                && strcasecmp(COOKIE_HEADER, field) == 0) {
            log_trace("Found Cookie header\n");
            /* Copy cookie, including NUL byte */
            update_bytearray(ev_data->cookie, value, value_len + 1, ev_data);
        }
    } else {
        /* Response Headers */

        if (field_len == TRANSFER_ENCODING_HEADER_STRLEN
                && strcasecmp(TRANSFER_ENCODING_HEADER, field) == 0) {
            /* Warn against Transfer-Encoding */
            log_warn("Transfer-Encoding \"%s\" is not supported\n", value);
            cancel_connection(ev_data);

        } else if (field_len == TE_HEADER_STRLEN
                && strcasecmp(TE_HEADER, field) == 0) {
            /* Warn against TE abbreviated version */
            log_warn("Transfer-Encoding \"%s\" is not supported\n", value);
            cancel_connection(ev_data);

        } else if (field_len == CONTENT_ENCODING_HEADER_STRLEN
                && strcasecmp(CONTENT_ENCODING_HEADER, field) == 0) {
            /* Warn against Content-Encoding */
            log_warn("Content-Encoding \"%s\" is not supported\n", value);
            cancel_connection(ev_data);

        } else if (field_len == CONTENT_LENGTH_HEADER_STRLEN
                && strcasecmp(CONTENT_LENGTH_HEADER, field) == 0) {
            /* Handle Content-Length */
            log_dbg("Content-Length specified\n");
            ev_data->content_length_specified = true;
            ev_data->content_len_value_len = value_len;
            ev_data->content_len_value = ev_data->header_value_loc;
        }
    }
}
#endif


/* Updates current header field or value.
 * Inspects previous header once a new header starts. */
#if ENABLE_HEADERS_TRACKING
void update_http_header_pair(struct event_data *ev_data, bool is_header_field,
        const char *at, size_t length) {
    bytearray_t *ba;

    if (is_header_field) {
        ba = ev_data->header_field;
    } else {
        ba = ev_data->header_value;
    }


    /* Set original field and value locations */
    if (is_header_field && !ev_data->just_visited_header_field) {
        ev_data->header_field_loc = at;
    } else if (!is_header_field && ev_data->just_visited_header_field) {
        ev_data->header_value_loc = at;
    }

    /* Inspect header if field and value are present. */
    if (is_header_field && !ev_data->just_visited_header_field
            && ba->len != 0) {
        check_header_pair(ev_data);
        bytearray_clear(ev_data->header_field);
        bytearray_clear(ev_data->header_value);
    }

    update_bytearray(ba, at, length, ev_data);
    ev_data->just_visited_header_field = is_header_field;
}
#endif


/* Handle a new incoming connection */
int handle_new_connection(int efd, struct epoll_event *ev, int sfd) {
    int s;
    struct epoll_event client_event = {0}, server_event = {0};
    struct connection_info *conn_info;

    while (1) {
        struct sockaddr in_addr;
        socklen_t in_len;
        int infd, outfd;
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
        if (s == 0) {
            log_trace("Accepted connection on descriptor %d "
                    "(host=%s, port=%s)\n",
                    infd, hbuf, sbuf);
        }

        /* Make the incoming socket non-blocking and add it to the
         list of fds to monitor. */
        s = make_socket_non_blocking(infd);
        if (s < 0) {
            log_error("Could not make new socket non-blocking\n");
            return -1;
        }

        /* Create proxy socket to server */
        outfd = create_and_connect(server_http_port_str);
        if (outfd < 0) {
            return -1;
        }

        s = make_socket_non_blocking(outfd);
        if (s < 0) {
            log_error("Could not make forward socket non-blocking\n");
            return -1;
        }

        /* Allocate data */
        conn_info = init_conn_info(infd, outfd);
        if (conn_info == NULL) {
            log_error("init_conn_info() failed");
            return -1;
        }

        client_event.data.ptr = conn_info->client_ev_data;
        client_event.events = EPOLLIN | EPOLLET;

        server_event.data.ptr = conn_info->server_ev_data;
        server_event.events = EPOLLIN | EPOLLET;

        s = epoll_ctl(efd, EPOLL_CTL_ADD, infd, &client_event);
        if (s == -1) {
            perror("epoll_ctl");
            return -1;
        }

        s = epoll_ctl(efd, EPOLL_CTL_ADD, outfd, &server_event);
        if (s == -1) {
            perror("epoll_ctl");
            return -1;
        }
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
            cancel_connection(ev_data);;
        }
        if (matches) {
            return &params[i];
        }
    }
    return NULL;
}

/* Returns whether character corresponds to a hexadecimal digit */
bool is_hex_digit(char c) {
    return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f')
            || ('A' <= c && c <= 'F');
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
    if (page_match->receives_csrf_form_action && name_len == CSRF_TOKEN_NAME_LEN
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
    ev_data->conn_info->page_match = url_find_matching_page((char *) ev_data->url->data,
            ev_data->url->len);
    log_trace("page_match=\"%s\"\n", ev_data->conn_info->page_match->name);

    copy_default_params(ev_data->conn_info->page_match, &ev_data->conn_info->default_params);

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

/* Handles incoming client requests.
 * Returns boolean indicated if connection is done */
int handle_client_server_event(struct epoll_event *ev) {
    int done = 0;
    ssize_t count;
    char buf[READ_BUF_SIZE];

    struct event_data *ev_data = (struct event_data *) ev->data.ptr;
    ev_data->got_eagain = false; // Reset on each handle call
    event_t type = ev_data->type;

#if ENABLE_SESSION_TRACKING
    bytearray_t *headers_cache = ev_data->headers_cache;
#endif

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
        count = read(ev_data->listen_fd, buf, READ_BUF_SIZE);
        if (count == -1) {
            log_dbg("    read=%zd, errno=%d\n", count, errno);
            /* If errno == EAGAIN, that means we have read all
             data for now. So go back to the main loop. */
            if (errno == EAGAIN) {
                log_dbg("Got EAGAIN on read\n");
                ev_data->got_eagain = true;
                done = 1;
                break;
            } else {
                perror("read");
                cancel_connection(ev_data);
                done = 1;
                break;
            }
            break;
        } else if (count == 0) {
            /* End of file. The remote has closed the
             connection. */
            done = 1;
        }

#if ENABLE_SESSION_TRACKING
        /* Add session Set-Cookie header */
        if (type == SERVER_LISTENER && headers_cache) {
            log_dbg("Caching first part of response\n");
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

            if (strstr(headers_cache->data, "\r\n\r\n")
                    || strstr(headers_cache->data, "\n\n")) {
                /* Have all headers in buffer, so if Content-Length is
                 * specified, then it is in the buffer. */

                char insert_header[ESTIMATED_SET_COOKIE_HEADER_LEN + 10];
                int insert_header_len = populate_set_cookie_header(
                        insert_header, sizeof(insert_header), ev_data);
                if (insert_header_len < 0) {
                    done = 1;
                    cancel_connection(ev_data);
                    break;
                }

                char *insert_header_loc = strchr(headers_cache->data, '\n') + 1;
                size_t insert_offset = insert_header_loc - headers_cache->data;

                done |= do_http_parse_send(headers_cache->data,
                        headers_cache->len, ev_data, parser_settings,
                        insert_header, insert_header_len, insert_offset);

                /* Done with the headers cache */
                bytearray_free(headers_cache);
                headers_cache = NULL;
                ev_data->headers_cache = NULL;
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
#endif
        log_dbg("Sending data normally\n");
        done |= do_http_parse_send(buf, count, ev_data, parser_settings, NULL,
                0, 0);
    }


#if ENABLE_CSRF_PROTECTION
    /* Send CSRF token JavaScript snippet */
    if (type == SERVER_LISTENER) {
        log_dbg("Checking if page has CSRF protection\n");
        if (!is_conn_cancelled(ev_data) && !ev_data->got_eagain
                && ev_data->conn_info->page_match
                && ev_data->conn_info->page_match->has_csrf_form) {
            log_trace("Page has CSRF protected form; sending JS snippet\n");
            int s;
            char js_snippet[INSERT_HIDDEN_TOKEN_JS_STRLEN + 10];
            int snippet_len = snprintf(js_snippet, sizeof(js_snippet),
                    INSERT_HIDDEN_TOKEN_JS_FORMAT,
                    ev_data->conn_info->session->session_id);
            if (snippet_len < 0) {
                perror("snprintf");
                cancel_connection(ev_data);
                done = 1;
            }
            s = sendall(ev_data->send_fd, js_snippet, snippet_len);
            if (s < 0) {
                log_error("sendall failed\n");
                cancel_connection(ev_data);
                done = 1;
            }
        }
    }
#endif

    if (type == CLIENT_LISTENER && is_conn_cancelled(ev_data)) {
        if (send_error_page(ev_data->listen_fd)) {
            log_info("Failed to send error page.\n");
        }
        close(ev_data->listen_fd);
        close(ev_data->send_fd);
        ev_data->listen_fd = 0;
        ev_data->send_fd = 0;
        log_info("Closed_connection\n");
        return 1;
    }

    return done;
}

/* Parse http buffer and run checks. If insert_header is not NULL, it is sent
 * at insert_offset. Returns done sending on socket. */
int do_http_parse_send(char *buf, size_t len, struct event_data *ev_data,
        http_parser_settings *parser_settings, char *insert_header,
        size_t insert_header_len, size_t insert_offset) {
    int s;
    size_t nparsed = http_parser_execute(&ev_data->parser, parser_settings,
            buf, len);
    (void) nparsed; // Avoid unused variable compiler warning

    log_trace("Parsed %zd / %zd bytes\n", nparsed, len);

    if (ev_data->parser.upgrade) {
        /* Wants to upgrade connection */
        log_warn("HTTP upgrade not supported\n");
        cancel_connection(ev_data);
        return 1;
    } else if (is_conn_cancelled(ev_data)) {
        return 1;
    }


#if ENABLE_SESSION_TRACKING
    if (insert_header) { /* Insert header */
        /* Send first line */
        s = sendall(ev_data->send_fd, buf, insert_offset);
        if (s < 0) {
            log_error("sendall failed\n");
            cancel_connection(ev_data);
            return 1;
        }
        buf += insert_offset;
        len -= insert_offset;

        /* Send insert header */
        s = sendall(ev_data->send_fd, insert_header, insert_header_len);
        if (s < 0) {
            log_error("sendall failed\n");
            cancel_connection(ev_data);
            return 1;
        }

        if (ev_data->conn_info->page_match->has_csrf_form
                && ev_data->content_length_specified) {
            size_t send_len;

            /* Insert new Content-Length, accounting for JS snippet length that
             * is to be sent. */

            log_trace("Replacing Content-Length that was found\n");

            /* Send up to Content-Length value */
            send_len = ev_data->content_len_value - buf;
            s = sendall(ev_data->send_fd, buf, send_len);
            if (s < 0) {
                log_error("sendall failed\n");
                cancel_connection(ev_data);
                return 1;
            }
            buf += send_len;
            len -= send_len;

            /* Read original value */
            size_t old_len;
            if (sscanf(buf, "%zd\n", &old_len) != 1) {
                log_error("Could not read Content-Length value: %.*s\n",
                        (int) ev_data->content_len_value_len, buf);
                cancel_connection(ev_data);
                return 1;
            }

            /* Write new value to string */
            size_t new_len = old_len + INSERT_HIDDEN_TOKEN_JS_STRLEN;
            char new_len_buf[ev_data->content_len_value_len + 10];
            int new_len_buf_len = snprintf(new_len_buf, sizeof(new_len_buf),
                    "%zd", new_len);
            if (new_len_buf_len < 0) {
                log_error("Could not write new calculated Content-Length "
                        "to buffer\n");
                cancel_connection(ev_data);
                return 1;
            }

            /* Send new value */
            s = sendall(ev_data->send_fd, new_len_buf, new_len_buf_len);
            if (s < 0) {
                log_error("sendall failed\n");
                cancel_connection(ev_data);
                return 1;
            }

            /* Skip over old length */
            buf += ev_data->content_len_value_len;
            len -= ev_data->content_len_value_len;
        }
    }
#endif

    /* Send rest of buf */
    s = sendall(ev_data->send_fd, buf, len);
    if (s < 0) {
        log_error("sendall failed\n");
        cancel_connection(ev_data);
        return 1;
    }

    return 0;
}

/* Handle epoll event */
void handle_event(int efd, struct epoll_event *ev, int sfd) {
    int done;
    struct event_data *ev_data = (struct event_data *) (ev->data.ptr);

    if ((ev->events & EPOLLERR) || (ev->events & EPOLLHUP)
            || (!(ev->events & EPOLLIN))) {
        /* An error has occured on this fd, or the socket is not
         ready for reading (why were we notified then?) */
        log_error("epoll error\n");
        free_connection_info(ev_data->conn_info);
        ev->data.ptr = NULL;
        return;

    } else if (sfd == ev_data->listen_fd) {
        /* We have a notification on the listening socket, which
         means one or more incoming connections. */
        if (handle_new_connection(efd, ev, sfd) < 0) {
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
    }

}

/* Handler for SIGINT */
void sigint_handler(int dummy) {
    sigint_received = true;
}

/* Initialize structures for walking pages */
void init_page_conf() {
    // @Todo(Travis) Create trie to index pages
}

/* Do main initialization */
void init_structures(char *error_page_file) {
    init_error_page(error_page_file);
    init_config_vars();
    init_page_conf();
#if ENABLE_SESSION_TRACKING
    memset(current_sessions, 0, sizeof(current_sessions));
#endif
}

int main(int argc, char *argv[]) {
    int sfd, s;
    int efd;
    struct epoll_event event;
    struct epoll_event *events;
    char *error_page_file = NULL;

    memset(&event, 0, sizeof(struct epoll_event));

    if (argc != 3 && argc != 4) {
        log_error("Usage: %s SHIM_PORT SERVER_PORT [ERROR_PAGE]\n", argv[0]);
        log_error("Shim %s\n", SHIM_VERSION);
        exit(EXIT_FAILURE);
    }

    if (signal(SIGINT, sigint_handler) < 0) {
        perror("signal");
        abort();
    }

    http_port_str = argv[1];
    server_http_port_str = argv[2];

    if (argc == 4) {
        error_page_file = argv[3];
    }

    init_structures(error_page_file);

    /* Set up listener */
    sfd = create_and_bind(http_port_str);
    if (sfd == -1) {
        abort();
    }

    s = make_socket_non_blocking(sfd);
    if (s == -1) {
        abort();
    }

    s = listen(sfd, SOMAXCONN);
    if (s == -1) {
        perror("listen");
        abort();
    }

    efd = epoll_create(20);
    if (efd == -1) {
        perror("epoll_create");
        abort();
    }

    event.data.ptr = calloc(1, sizeof(struct event_data));
    if (event.data.ptr == NULL) {
        perror("calloc");
        abort();
    }

    ((struct event_data *) event.data.ptr)->listen_fd = sfd;

    event.events = EPOLLIN | EPOLLET;
    s = epoll_ctl(efd, EPOLL_CTL_ADD, sfd, &event);
    if (s == -1) {
        perror("epoll_ctl");
        abort();
    }

    /* Buffer where events are returned */
    events = calloc(MAXEVENTS, sizeof(struct epoll_event));

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
            handle_event(efd, &events[i], sfd);
        }

#if ENABLE_SESSION_TRACKING
        log_trace("Now tracking %d active sessions\n", get_num_active_sessions());
#endif
    }

    close(efd);
    free(events);
    free(event.data.ptr);
    free(error_page_buf);

    close(sfd);

    return EXIT_SUCCESS;
}
