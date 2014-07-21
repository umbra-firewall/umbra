#include "shim.h"

int connction_num = 0;
char *http_port_str, *server_http_port_str;

char *error_page_buf = NULL;
size_t error_page_len;

bool sigint_received = false;

int num_conn_infos = 0;// DEBUG

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
    .on_header_field = NULL,
    .on_header_value = NULL,
    .on_headers_complete = on_headers_complete_cb,
    .on_body = on_body_cb,
    .on_message_complete = on_message_complete_cb
};


#if ENABLE_SESSION_TRACKING
struct session current_sessions[MAX_NUM_SESSIONS];

time_t current_time, next_session_expiration_time;
#endif


/* Set connection to cancelled state */
void cancel_connection(struct event_data *ev_data) {
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

int on_message_begin_cb(http_parser *p) {
    log_trace("***MESSAGE BEGIN***\n");
    return 0;
}

/*
 * Attempts to find matching page conf. If it cannot find one, it returns a
 * pointer to the default page conf structure.
 */
struct page_conf *find_matching_page(char *url, size_t len) {
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

/* Copy default param fields in page_conf struct to params struct */
void copy_default_params(struct page_conf *page_conf, struct params *params) {
    params->max_param_len = page_conf->max_param_len;
    params->whitelist = page_conf->whitelist;
}

int on_headers_complete_cb(http_parser *p) {
    log_trace("***HEADERS COMPLETE***\n");
    struct event_data *ev_data = (struct event_data *) p->data;
    ev_data->headers_complete = true;

    /* Check last header pair */
    if (ev_data->header_field->len != 0) {
        check_header_pair(ev_data);

        /* We are done with tracking headers */
        bytearray_free(ev_data->header_field);
        bytearray_free(ev_data->header_value);

        /* Set pointers to NULL to make sure they are not
         * free'd during cleanup */
        ev_data->header_field = NULL;
        ev_data->header_value = NULL;
    }

    if (ev_data->type == CLIENT_LISTENER) {
        do_client_header_complete_checks(ev_data);
    }

    return 0;
}

int on_message_complete_cb(http_parser *p) {
    log_trace("***MESSAGE COMPLETE***\n");
    struct event_data *ev_data = (struct event_data *) p->data;
    ev_data->msg_complete = true;

#if ENABLE_PARAM_CHECKS
    /* Check POST parameters, use http_parser macro */
    if (ev_data->type == CLIENT_LISTENER && p->method == HTTP_POST) {
        check_buffer_params(ev_data->body, false, ev_data);
    }
#endif

    return 0;
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

int on_url_cb(http_parser *p, const char *at, size_t length) {
    struct event_data *ev_data = (struct event_data *) p->data;

    if (update_bytearray(ev_data->url, at, length, ev_data) < 0) {
        return -1;
    }
    log_trace("Url: \"%.*s\"\n", (int) ev_data->url->len, ev_data->url->data);

    return 0;
}

int on_status_cb(http_parser *p, const char *at, size_t length) {
    log_trace("Status: %.*s\n", (int)length, at);
    return 0;
}

/* Inspects current header pair */
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

        /* Handle Cookie header */
        if (field_len == COOKIE_HEADER_FIELD_STRLEN
                && strcasecmp(COOKIE_HEADER_FIELD, field) == 0) {
            log_trace("Found Cookie header\n");
            /* Copy cookie, including NUL byte */
            update_bytearray(ev_data->cookie, value, value_len + 1, ev_data);
        }
    } else {
        //@todo(Travis) check for TE, Transfer-Encoding, Content-Length
        ;
    }
}

#if ENABLE_HEADER_FIELD_CHECK
int on_header_field_cb(http_parser *p, const char *at, size_t length) {
    //log_trace("Header field: %.*s\n", (int)length, at);
    struct event_data *ev_data = (struct event_data *) p->data;

#if ENABLE_HEADER_FIELD_LEN_CHECK
    if (length > MAX_HEADER_FIELD_LEN) {
        log_info("Blocked request because header field length %ld; "
                "max is %ld\n",
                length, (long ) MAX_HEADER_FIELD_LEN);
        cancel_connection(ev_data);
        return -1;
    }
#endif

#if ENABLE_HEADERS_TRACKING
    update_http_header_pair(ev_data, true, at, length);
#endif

    return 0;
}
#endif


#if ENABLE_HEADER_VALUE_CHECK
int on_header_value_cb(http_parser *p, const char *at, size_t length) {
    //log_trace("Header value: %.*s\n", (int)length, at);
    struct event_data *ev_data = (struct event_data *) p->data;
#if ENABLE_HEADER_VALUE_LEN_CHECK
    if (length > MAX_HEADER_VALUE_LEN) {
        log_info("Blocked request because header value length %ld; "
                "max is %ld\n",
                length, (long ) MAX_HEADER_VALUE_LEN);
        cancel_connection(ev_data);
        return -1;
    }
#endif

#if ENABLE_HEADERS_TRACKING
    update_http_header_pair(ev_data, false, at, length);
#endif

    return 0;
}
#endif

/* Updates current header field or value.
 * Inspects previous header once a new header starts. */
void update_http_header_pair(struct event_data *ev_data, bool is_header_field,
        const char *at, size_t length) {
    bytearray_t *ba;

    if (is_header_field) {
        ba = ev_data->header_field;
    } else {
        ba = ev_data->header_value;
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

int on_body_cb(http_parser *p, const char *at, size_t length) {
#if ENABLE_PARAM_CHECKS
    if (p->method == HTTP_POST) { /* Use http_parser macro */
        struct event_data *ev_data = (struct event_data *) p->data;
        if (update_bytearray(ev_data->body, at, length, ev_data) < 0) {
            return -1;
        }
        log_trace("POST Body: \"%.*s\"\n", (int) ev_data->body->len, ev_data->body->data);
    }
#endif
    return 0;
}

/* Sets socket as non blocking */
int make_socket_non_blocking(int sfd) {
    int flags, s;

    flags = fcntl(sfd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl");
        return -1;
    }

    flags |= O_NONBLOCK;
    s = fcntl(sfd, F_SETFL, flags);
    if (s == -1) {
        perror("fcntl");
        return -1;
    }

    return 0;
}

/* Create listening socket and bind to port */
int create_and_bind(char *port) {
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, sfd;
    int yes = 1;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC; /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */
    hints.ai_flags = AI_PASSIVE; /* All interfaces */

    s = getaddrinfo(NULL, port, &hints, &result);
    if (s != 0) {
        log_info("getaddrinfo: %s\n", gai_strerror(s));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1) {
            continue;
        }

        if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int))
                == -1) {
            perror("setsockopt");
            exit(1);
        }

        s = bind(sfd, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            /* We managed to bind successfully! */
            break;
        }

        close(sfd);
    }

    if (rp == NULL) {
        log_error("Could not bind\n");
        return -1;
    }

    freeaddrinfo(result);

    return sfd;
}

/* Create listening socket */
int create_and_connect(char *port) {
    int sockfd, rv, rc = 0;
    struct addrinfo hints, *servinfo = NULL, *p = NULL;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo("127.0.0.1", port, &hints, &servinfo)) != 0) {
        log_info("getaddrinfo: %s\n", gai_strerror(rv));
        rc = -1;
        goto error;
    }

    // loop through all the results and connect to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol))
                == -1) {
            perror("socket");
            continue;
        }
        rc = sockfd;

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("connect");
            continue;
        }

        break;
    }

    if (p == NULL) {
        log_error("client: failed to connect\n");
        rc = -1;
        goto error;
    }

error:
    if (servinfo) {
        freeaddrinfo(servinfo);
    }
    return rc;
}

/* Free memory associated with event data */
void free_event_data(struct event_data *ev) {
    //log_trace("Freeing event data %p\n", ev);
    if (ev != NULL) {
        bytearray_free(ev->url);
        bytearray_free(ev->body);

#if ENABLE_SESSION_TRACKING
        bytearray_free(ev->cookie);
#endif

#if ENABLE_HEADERS_TRACKING
        bytearray_free(ev->header_field);
        bytearray_free(ev->header_value);
#endif

        free(ev);
    }
}

/* Free memory and close sockets associated with connection structure */
void free_connection_info(struct connection_info *ci) {
    if (ci != NULL) {
        log_trace("Freeing conn info %p (%d total)\n", ci, --num_conn_infos);
        if (ci->client_ev_data) {
            int listen_fd = ci->client_ev_data->listen_fd;
            if (listen_fd && close(listen_fd)) {
                perror("close");
            }

            int send_fd = ci->client_ev_data->send_fd;
            if (send_fd && close(send_fd)) {
                perror("close");
            }
            free_event_data(ci->client_ev_data);
        }
        free_event_data(ci->server_ev_data);

        free(ci);
    } else {
        log_trace("Freeing NULL conn info (%d total)\n", num_conn_infos);
    }
}

/* Send entire buffer over socket, using multiple sends if necessary */
int sendall(int sockfd, const void *buf, size_t len) {
    int sent_bytes;
    while (len > 0) {
        sent_bytes = send(sockfd, buf, len, 0);
        if (sent_bytes < 0) {
            if (errno == EAGAIN) {
                continue;
            }
            perror("send");
            return -1;
        }
        buf += sent_bytes;
        len -= sent_bytes;
    }
    return 0;
}

/* Initialize event data structure */
struct event_data *init_event_data(event_t type, int listen_fd, int send_fd,
        enum http_parser_type parser_type, struct connection_info *conn_info) {

    struct event_data *ev_data = calloc(1, sizeof(struct event_data));

    if (ev_data != NULL) {
        ev_data->type = type;
        ev_data->listen_fd = listen_fd;
        ev_data->send_fd = send_fd;
        ev_data->conn_info = conn_info;

        if ((ev_data->url = bytearray_new()) == NULL) {
            log_warn("Allocating new bytearray failed\n");
            goto error;
        }

        if ((ev_data->body = bytearray_new()) == NULL) {
            log_warn("Allocating new bytearray failed\n");
            goto error;
        }

#if ENABLE_SESSION_TRACKING
        if ((ev_data->cookie = bytearray_new()) == NULL) {
            log_warn("Allocating new bytearray failed\n");
            goto error;
        }
#endif

#if ENABLE_HEADERS_TRACKING
        if ((ev_data->header_field = bytearray_new()) == NULL) {
            log_warn("Allocating new bytearray failed\n");
            goto error;
        }

        if ((ev_data->header_value = bytearray_new()) == NULL) {
            log_warn("Allocating new bytearray failed\n");
            goto error;
        }
#endif

        http_parser_init(&ev_data->parser, parser_type);
        ev_data->parser.data = ev_data;
    }

    return ev_data;

error:
    bytearray_free(ev_data->url);
    bytearray_free(ev_data->body);

#if ENABLE_SESSION_TRACKING
    bytearray_free(ev_data->cookie);
#endif

#if ENABLE_HEADERS_TRACKING
    bytearray_free(ev_data->header_field);
    bytearray_free(ev_data->header_value);
#endif

    free(ev_data);
    return NULL;
}

/* Initialize connection_info structure */
struct connection_info *init_conn_info(int infd, int outfd) {
    struct event_data *client_ev_data = NULL, *server_ev_data = NULL;
    struct connection_info *conn_info = NULL;
    num_conn_infos++;
    log_trace("init_conn_info() (%d total)\n", num_conn_infos);

    conn_info = calloc(1, sizeof(struct connection_info));
    if (conn_info == NULL) {
        goto fail;
    }

    client_ev_data = init_event_data(CLIENT_LISTENER, infd, outfd, HTTP_REQUEST, conn_info);
    if (client_ev_data == NULL) {
        goto fail;
    }

    server_ev_data = init_event_data(SERVER_LISTENER, outfd, infd, HTTP_RESPONSE, conn_info);
    if (server_ev_data == NULL) {
        goto fail;
    }

    conn_info->client_ev_data = client_ev_data;
    conn_info->server_ev_data = server_ev_data;
    conn_info->page_match = NULL;

    return conn_info;

fail:
    num_conn_infos--;
    free(client_ev_data);
    free(server_ev_data);
    free(conn_info);
    return NULL;
}

/* Handle a new incoming connection */
int handle_new_connection(int efd, struct epoll_event *ev, int sfd) {
    int s;
    struct epoll_event client_event, server_event;
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

/* Send a error page back on a socket */
int send_error_page(int sock) {
    if (sendall(sock, HTTP_RESPONSE_FORBIDDEN, sizeof(HTTP_RESPONSE_FORBIDDEN))
            < 0) {
        return -1;
    }
    if (sendall(sock, error_page_buf, error_page_len) < 0) {
        return -1;
    }
    return 0;
}

/* Converts http_parser method to shim method. Returns 0 if not valid. */
int http_parser_method_to_shim(enum http_method method) {
    if (0 <= method && method < NUM_HTTP_REQ_TYPES) {
        return 1 << method;
    } else {
        log_warn("Invalid http_parser method %d\n", method);
        return 0;
    }
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

/* Compares NUL terminated string to buffer that is URL encoded */
bool str_to_url_encoded_memeq(const char *str, char *url_data,
        size_t url_data_len, struct event_data *ev_data) {
    int byte;
    char *url_data_end = url_data + url_data_len;
    char *str_should_end = (char *) (str + url_data_len);
    while (*str && url_data < url_data_end) {
        if (*str == *url_data) {
            str++;
            url_data++;
            url_data_len--;
        } else if (*url_data == '%') { /* Percent encoded */
            if (url_data_len >= 3 && sscanf(url_data + 1, "%02x", &byte) == 1
                    && byte == *str) {
                str++;
                str_should_end -= 2;  // Account for miscalculating before
                url_data += 3;
                url_data_len -= 3;
            } else {
                log_warn("Invalid URL encoding\n");
                cancel_connection(ev_data);
                return false;
            }
        } else {
            return false;
        }
    }
    return str == str_should_end && *str == '\0';
}

/* Finds matching parameter struct based on the parameter name. Returns NULL
 * if one cannot be found */
struct params *find_matching_param(char *name, size_t name_len,
        struct params *params, unsigned int params_len,
        struct event_data *ev_data) {
    int i;
    for (i = 0; i < params_len; i++) {
        if (str_to_url_encoded_memeq(params[i].name, name, name_len, ev_data)) {
            return &params[i];
        }
    }
    return NULL;
}

/* Returns whether character corresponds to a hexadecimal digit */
bool is_hex_digit(char c) {
    return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F');
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

/* Calculates the number of decoded bytes are in a argument value */
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
    log_dbg("  decode_len=%ld\n", url_decode_len);
    if (url_decode_len > param->max_param_len) {
        log_warn("Length of parameter value \"%.*s\" %ld exceeds max %d\n",
                (int ) value_len, value, url_decode_len, param->max_param_len);
        cancel_connection(ev_data);
    }
}

/* Perform argument specific checks */
void check_single_arg(struct event_data *ev_data, char *arg, size_t len) {
    log_dbg("arg=\"%.*s\", len=%ld\n", (int) len, arg, len);

    if (len < 0) {
        log_warn("Malformed argument\n");
        cancel_connection(ev_data);
    }

    char *name = arg, *value;
    size_t name_len, value_len; // Length of buffers

    parse_argument_name_value(arg, len, &name, &name_len, &value, &value_len);

    log_dbg("  name=\"%.*s\" len=%ld, value=\"%.*s\" len=%ld\n", (int) name_len,
            name, name_len, (int) value_len, value, value_len);

    struct page_conf *page_match = ev_data->conn_info->page_match;
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

    log_dbg("query: \"%.*s\", len=%ld\n", (int) query_len, query, query_len);

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

/* Returns value of session id given a NUL terminated string with the Cookie
 * header value. */
char *extract_sessid_cookie_value(char *cookie_header_value) {
    char *tok = strtok(cookie_header_value, ";");

    /* Examine each query parameter */
    while (tok  != NULL) {
        tok = strstr(tok, SHIM_SESSID_NAME "=");
        if (tok) {
            tok += SHIM_SESSID_NAME_STRLEN + 1;
            if (*tok == '"') {
                tok++;
            }
            return tok;
        }
        tok = strtok(NULL, ";");
    }

    return NULL;
}

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


/* Find session associated with cookie */
#if ENABLE_SESSION_TRACKING
void find_session_from_cookie(struct event_data *ev_data) {
    /* Cookie should be NUL terminated from check_header_pair(),
     * so C string functions can be used. */

    char *sess_id = extract_sessid_cookie_value(ev_data->cookie->data);
    if (sess_id == NULL) {
        log_trace("SESSION_ID not found in HTTP request\n");
        return;
    }

    size_t sess_id_len = strlen(sess_id);
    if (sess_id_len != SHIM_SESSID_LEN) {
        log_warn("Found SESSION_ID with length %ld instead of expected %d\n",
                sess_id_len, SHIM_SESSID_LEN);
        cancel_connection(ev_data);
    }

    ev_data->conn_info->session = search_session(sess_id);

#ifdef DEBUG
    if (ev_data->conn_info->session) {
        log_trace("Found existing session \"%s\"\n",
                ev_data->conn_info->session->session_id);
    } else {
        log_trace("Could not find existing existing session\n");
    }
#endif
}
#endif

/* Do checks that are possible after the header is received */
void do_client_header_complete_checks(struct event_data *ev_data) {
    ev_data->conn_info->page_match = find_matching_page((char *) ev_data->url->data,
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


/* Session tracking functions */
#if ENABLE_SESSION_TRACKING

/* Clear session (clears entry in array) */
void clear_session(struct session *sess) {
    memset(sess, 0, sizeof(struct session));
}

/* Returns whether session entry is ununsed */
bool is_session_entry_clear(struct session *sess) {
    return sess->session_id[0] == 0;
}

/* Tries to find session with given sess_id. Returns NULL if none is found. */
struct session *search_session(char *sess_id) {
    int i;
    for (i = 0; i < MAX_NUM_SESSIONS; i++) {
        if (strcmp(sess_id, current_sessions[i].session_id) == 0) {
            return &current_sessions[i];
        }
    }

    return NULL;
}

/* Returns whether a session is expired */
bool is_session_expired(struct session *s) {
    return current_time >= s->expires_at;
}

/* Clears all entries that have expired */
void expire_sessions() {
    struct session *sess;
    int i;

    for (i = 0; i < MAX_NUM_SESSIONS; i++) {
        sess = &current_sessions[i];
        if (!is_session_entry_clear(sess) && is_session_expired(sess)) {
            log_trace("Expiring session \"%s\"\n", sess->session_id);
            clear_session(sess);
        }
    }
}

int get_num_active_sessions() {
    int num_sessions = 0, i;

    for (i = 0; i < MAX_NUM_SESSIONS; i++) {
        if (!is_session_entry_clear(&current_sessions[i])) {
            num_sessions++;
        }
    }
    return num_sessions;
}

/* Create a new session and returns the session structure. Returns NULL on
 * error. */
struct session *new_session() {
    log_trace("Creating new session\n");

    struct session *sess = NULL;
    int i;

    /* Find first free entry */
    for (i = 0; i < MAX_NUM_SESSIONS; i++) {
        if (is_session_entry_clear(&current_sessions[i])) {
            sess = &current_sessions[i];
            break;
        }
    }

    /* No free entry found */
    if (sess == NULL) {
        return NULL;
    }

    sess->expires_at = next_session_expiration_time;
    char rand_bytes[SHIM_SESSID_RAND_BYTES];
    if (fill_rand_bytes(rand_bytes, SHIM_SESSID_RAND_BYTES) < 0) {
        goto error;
    }

    for (i = 0; i < SHIM_SESSID_RAND_BYTES; i++) {
        sprintf(sess->session_id + 2 * i, "%02hhX", rand_bytes[i]);
    }

    return sess;

error:
    memset(sess, 0, sizeof(struct session));
    return NULL;
}

/* Returns session structure associated with connection. If one does not exists,
 * then a new one is created. NULL is returned if the maximum number of sessions
 * exist already. */
struct session *get_conn_session(struct connection_info *conn_info) {
    if (conn_info->session == NULL) {
        conn_info->session = new_session();
    }
    return conn_info->session;
}

#endif /* ENABLE_SESSION_TRACKING */


/* Handles incoming client requests.
 * Returns boolean indicated if connection is done */
int handle_client_server_event(struct epoll_event *ev) {
    int done = 0;
    ssize_t count;
    char buf[READ_BUF_SIZE];

    struct event_data *ev_data = (struct event_data *) ev->data.ptr;
    event_t type = ev_data->type;

#if ENABLE_SESSION_TRACKING
    /* Cache first response to find where headers begin */
    char *newline_loc;
    bytearray_t *first_response_line = NULL;
    if (type == SERVER_LISTENER) {
        if ((first_response_line = bytearray_new()) == NULL) {
            log_warn("Allocating new bytearray failed\n");
            cancel_connection(ev_data);
            return 1;
        }
    }
#endif

    log_trace("*****HANDLING EVENT TYPE %s*****\n",
            type == CLIENT_LISTENER ? "REQUEST" : "RESPONSE");

    http_parser_settings *parser_settings;
    if (type == CLIENT_LISTENER) {
        parser_settings = &client_parser_settings;
    } else { // type == SERVER_LISTENER
        parser_settings = &server_parser_settings;
    }

    while (!done) {
        count = read(ev_data->listen_fd, buf,
                READ_BUF_SIZE);
        if (count == -1) {
            /* If errno == EAGAIN, that means we have read all
             data. So go back to the main loop. */
            if (errno != EAGAIN) {
                perror("read");
                done = 1;
            }
            break;
        } else if (count == 0) {
            /* End of file. The remote has closed the
             connection. */
            done = 1;
        }

#if ENABLE_SESSION_TRACKING
        /* Add session Set-Cookie header */
        if (type == SERVER_LISTENER && first_response_line) {
            log_dbg("Caching first line of response\n");
            if (bytearray_append(first_response_line, buf, count) < 0) {
                log_error("bytearray_append failed\n");
                cancel_connection(ev_data);
                done = 1;
                continue;
            }
            newline_loc = memchr(buf, '\n', count);
            if (newline_loc) { // has '\n'
                log_dbg("Found newline\n");
                char insert_header[ESTIMATED_SET_COOKIE_HEADER_LEN + 10];
                struct session *sess = get_conn_session(ev_data->conn_info);
                if (sess == NULL) {
                    log_error("Could not allocate new session\n");
                    done = 1;
                    cancel_connection(ev_data);
                    continue;
                }
                char *token = sess->session_id;
                log_dbg("Sending SESSION_ID: %s\n", token);
                int insert_header_len = snprintf(insert_header,
                        sizeof(insert_header),
                        SET_COOKIE_HEADER_FORMAT, token);
                size_t insert_offset = first_response_line->len - count
                        + (newline_loc - buf + 1);
                done |= do_http_parse_send(first_response_line->data,
                        first_response_line->len, ev_data, parser_settings,
                        insert_header, insert_header_len, insert_offset);
                bytearray_free(first_response_line);
                first_response_line = NULL;
                continue;
            } else if (first_response_line->len
                    > MAX_HTTP_RESPONSE_FIRST_LINE_LEN) {
                log_warn("Newline not found after %d bytes into response\n",
                        MAX_HTTP_RESPONSE_FIRST_LINE_LEN);
                cancel_connection(ev_data);
                done = 1;
                continue;
            } else {
                log_dbg("No newline found yet\n");
                continue;
            }
        }
#endif
        log_dbg("Sending data normally\n");
        done |= do_http_parse_send(buf, count, ev_data, parser_settings, NULL,
                0, 0);
    }

#if ENABLE_SESSION_TRACKING
    if (first_response_line) {
        bytearray_free(first_response_line);
    }
#endif


#if ENABLE_CSRF_PROTECTION
    /* Send CSRF token JavaScript snippet */
    if (type == SERVER_LISTENER) {
        log_dbg("Checking if page has CSRF protection\n");
        if (!is_conn_cancelled(ev_data) && ev_data->conn_info->page_match
                && ev_data->conn_info->page_match->has_csrf_form) {
            log_trace("Page has CSRF protected form; sending JS snippet\n");
            int s;
            s = sendall(ev_data->send_fd, INSERT_HIDDEN_TOKEN_JS,
                    INSERT_HIDDEN_TOKEN_JS_STRLEN);
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
 * at insert_offset. */
int do_http_parse_send(char *buf, size_t len, struct event_data *ev_data,
        http_parser_settings *parser_settings, char *insert_header,
        size_t insert_header_len, size_t insert_offset) {
    int s;
    size_t nparsed = http_parser_execute(&ev_data->parser, parser_settings,
            buf, len);

    log_trace("Parsed %ld / %ld bytes\n", nparsed, len);

    if (ev_data->parser.upgrade) {
        /* Wants to upgrade connection */
        log_warn("HTTP upgrade not supported\n");
        cancel_connection(ev_data);
        return 1;
    }

    if (insert_header) { /* Insert header */
        /* Send first line */
        s = sendall(ev_data->send_fd, buf, insert_offset);
        if (s < 0) {
            log_error("sendall failed\n");
            cancel_connection(ev_data);
            return 1;
        }

        /* Send insert header */
        s = sendall(ev_data->send_fd, insert_header, insert_header_len);
        if (s < 0) {
            log_error("sendall failed\n");
            cancel_connection(ev_data);
            return 1;
        }

        /* Send rest of buf */
        s = sendall(ev_data->send_fd, buf + insert_offset, len - insert_offset);
        if (s < 0) {
            log_error("sendall failed\n");
            cancel_connection(ev_data);
            return 1;
        }
    } else {
        /* Send normal buf */
        s = sendall(ev_data->send_fd, buf, len);
        if (s < 0) {
            log_error("sendall failed\n");
            cancel_connection(ev_data);
            return 1;
        }
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

        if (done) {
            free_connection_info(ev_data->conn_info);
            ev->data.ptr = NULL;
        }
    }

}

/* Handler for SIGINT */
void sigint_handler(int dummy) {
    sigint_received = true;
}

/* Initialize error page */
void init_error_page(char *error_page_file) {
    if (error_page_file == NULL) {
        error_page_len = sizeof(DEFAULT_ERROR_PAGE_STR);
        error_page_buf = malloc(error_page_len);
        if (error_page_buf == NULL) {
            perror("malloc");
            exit(EXIT_FAILURE);
        }
        memcpy(error_page_buf, DEFAULT_ERROR_PAGE_STR, error_page_len);
    } else {
        FILE *f = fopen(error_page_file, "r");
        if (f == NULL) {
            log_error("Failed to open error page file \"%s\"\n",
                    error_page_file);
            perror("fopen");
            exit(EXIT_FAILURE);
        }
        if (fseek(f, 0, SEEK_END) < 0) {
            perror("fseek");
            exit(EXIT_FAILURE);
        }
        if ((error_page_len = ftell(f)) < 0) {
            perror("ftell");
            exit(EXIT_FAILURE);
        }
        if (fseek(f, 0, SEEK_SET) < 0) {
            perror("fseek");
            exit(EXIT_FAILURE);
        }
        error_page_buf = malloc(error_page_len);
        if (error_page_buf == NULL) {
            perror("malloc");
            exit(EXIT_FAILURE);
        }
        if (fread(error_page_buf, 1, error_page_len, f) != error_page_len) {
            perror("fread");
            exit(EXIT_FAILURE);
        }
        if (fclose(f) == EOF) {
            log_error("Failed to close error page file\n");
            perror("fclose");
            exit(EXIT_FAILURE);
        }
    }
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
