#include "shim.h"

int connction_num = 0;
char *http_port_str, *server_http_port_str;

char *error_page_buf = NULL;
size_t error_page_len;

bool sigint_received = false;

int num_conn_infos = 0;// DEBUG

http_parser_settings parser_settings = {
    .on_message_begin = on_message_begin_cb,
    .on_url = on_url_cb,

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
    ev_data->state = HEADERS_COMPLETE;

    ev_data->page_match = find_matching_page((char *) ev_data->url->data,
            ev_data->url->len);
    log_dbg("page_match=\"%s\"\n", ev_data->page_match->name);

    copy_default_params(ev_data->page_match, &ev_data->default_params);

    return 0;
}

int on_message_complete_cb(http_parser *p) {
    log_trace("***MESSAGE COMPLETE***\n");
    struct event_data *ev_data = (struct event_data *) p->data;
    ev_data->state = MESSAGE_COMPLETE;
    return 0;
}

int on_url_cb(http_parser *p, const char *at, size_t length) {
    struct event_data *ev_data = (struct event_data *) p->data;
    ev_data->state = URL_COMPLETE;

    if (bytearray_append(ev_data->url, at, length) < 0) {
        cancel_connection(ev_data);
        log_warn("Cancelling request because out of memory\n");
        return -1;
    }
    log_trace("Url: \"%.*s\"\n", (int) ev_data->url->len, ev_data->url->data);

    return 0;
}

#if ENABLE_HEADER_FIELD_CHECK
int on_header_field_cb(http_parser *p, const char *at, size_t length) {
    //log_trace("Header field: %.*s\n", (int)length, at);
    if (length > MAX_HEADER_FIELD_LEN) {
        log_info("Blocked request because header field length %ld; "
                "max is %ld\n",
                length, (long ) MAX_HEADER_FIELD_LEN);
        struct event_data *ev_data = (struct event_data *) p->data;
        cancel_connection(ev_data);
        return -1;
    }
    return 0;
}
#endif

#if ENABLE_HEADER_VALUE_CHECK
int on_header_value_cb(http_parser *p, const char *at, size_t length) {
    //log_trace("Header value: %.*s\n", (int)length, at);
    if (length > MAX_HEADER_VALUE_LEN) {
        log_info("Blocked request because header value length %ld; "
                "max is %ld\n",
                length, (long ) MAX_HEADER_VALUE_LEN);
        struct event_data *ev_data = (struct event_data *) p->data;
        cancel_connection(ev_data);
        return -1;
    }
    return 0;
}
#endif

int on_body_cb(http_parser *p, const char *at, size_t length) {
    log_trace("Body: %.*s\n", (int)length, at);
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
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
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
        fprintf(stderr, "Could not bind\n");
        return -1;
    }

    freeaddrinfo(result);

    return sfd;
}

/* Create listening socket */
int create_and_connect(char *port) {
    int sockfd, rv;
    struct addrinfo hints, *servinfo, *p;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo("127.0.0.1", port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    // loop through all the results and connect to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol))
                == -1) {
            perror("socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("connect");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "client: failed to connect\n");
        return -1;
    }

    freeaddrinfo(servinfo); // all done with this structure

    return sockfd;
}

/* Free memory associated with event data */
void free_event_data(struct event_data *ev) {
    //log_trace("Freeing event data %p\n", ev);
    if (ev != NULL) {
        bytearray_free(ev->url);
        free(ev);
    }
}

/* Free memory and close sockets associated with connection structure */
void free_connection_info(struct connection_info *ci) {
    log_trace("Freeing conn info %p (%d total)\n", ci, --num_conn_infos);
    if (ci != NULL) {
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
        ev_data->state = URL_COMPLETE;
        ev_data->is_cancelled = false;
        ev_data->conn_info = conn_info;
        ev_data->page_match = NULL;
        ev_data->have_done_after_header_checks = false;

        if ((ev_data->url = new_bytearray()) == NULL) {
            free(ev_data);
            return NULL;
        }

        http_parser_init(&ev_data->parser, parser_type);
        ev_data->parser.data = ev_data;
    }

    return ev_data;
}

/* Initialize connection_info structure */
struct connection_info *init_conn_info(int infd, int outfd) {
    struct event_data *client_ev_data = NULL, *server_ev_data = NULL;
    struct connection_info *conn_info = NULL;
    num_conn_infos++;
    log_dbg("init_conn_info() (%d total)\n", num_conn_infos);

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

    return conn_info;

fail:
    num_conn_infos--;
    free(client_ev_data);
    free(server_ev_data);
    free(conn_info);
    return NULL;
}

/* Handle a new incoming connection */
void handle_new_connection(int efd, struct epoll_event *ev, int sfd) {
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
            log_dbg(
                    "Accepted connection on descriptor %d " "(host=%s, port=%s)\n",
                    infd, hbuf, sbuf);
        }

        /* Make the incoming socket non-blocking and add it to the
         list of fds to monitor. */
        s = make_socket_non_blocking(infd);
        if (s < 0) {
            fprintf(stderr, "Could not make new socket non-blocking\n");
            abort();
        }

        /* Create proxy socket to server */
        outfd = create_and_connect(server_http_port_str);
        if (outfd < 0) {
            abort();
        }

        s = make_socket_non_blocking(outfd);
        if (s < 0) {
            fprintf(stderr, "Could not make forward socket non-blocking\n");
            abort();
        }

        /* Allocate data */
        conn_info = init_conn_info(infd, outfd);
        if (conn_info == NULL) {
            puts("init_conn_info() failed");
            abort();
        }

        client_event.data.ptr = conn_info->client_ev_data;
        client_event.events = EPOLLIN | EPOLLET;

        server_event.data.ptr = conn_info->server_ev_data;
        server_event.events = EPOLLIN | EPOLLET;

        s = epoll_ctl(efd, EPOLL_CTL_ADD, infd, &client_event);
        if (s == -1) {
            perror("epoll_ctl");
            abort();
        }

        s = epoll_ctl(efd, EPOLL_CTL_ADD, outfd, &server_event);
        if (s == -1) {
            perror("epoll_ctl");
            abort();
        }
    }
}

/* Send a error page back on a socket */
int send_error_page(int sock) {
    if (sendall(sock, SIMPLE_HTTP_RESPONSE, sizeof(SIMPLE_HTTP_RESPONSE)) < 0) {
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
    if (!(ev_data->page_match->request_types & http_method)) {
        log_error("Request type %s not allowed\n", http_method_str(method));
        cancel_connection(ev_data);
    }
}

/* Find location and size of argument name and value */
static void parse_argument_name_value(char *arg, size_t arg_len, char **name,
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
            if (url_data_len >= 3
                    && (sscanf(url_data + 1, "%02x", &byte) == 1
                            || sscanf(url_data + 1, "%02X", &byte) == 1)
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


/* Calculates the number of decoded bytes are in a argument value */
size_t url_encode_buf_len(char *data, size_t len, struct event_data *ev_data) {
    size_t ret_len = len;
    size_t i;
    for (i = 0; i < len; i++) {
        if (*data == '%') {
            if (i + 2 < len && is_hex_digit(data[1]) && is_hex_digit(data[2])) {
                data += 3;
                ret_len -= 2;
            } else {
                log_warn("Invalid URL encoding found during length check\n");
                cancel_connection(ev_data);
            }
        }
    }
    return len;
}

/* Perform argument specific checks */
void check_single_arg(struct event_data *ev_data, char *arg, size_t len) {
    log_dbg("arg=\"%.*s\", len=%ld\n", (int) len, arg, len);

    if (len <= 0) {
        log_warn("Malformed argument\n");
        cancel_connection(ev_data);
    }

    char *name = arg, *value;
    size_t name_len, value_len; // Length of buffers

    parse_argument_name_value(arg, len, &name, &name_len, &value, &value_len);

    log_dbg("  name=\"%.*s\" len=%ld, value=\"%.*s\" len=%ld\n", (int) name_len,
            name, name_len, (int) value_len, value, value_len);

    struct page_conf *page_match = ev_data->page_match;
    struct params *param = find_matching_param(name, name_len,
            page_match->params, page_match->params_len, ev_data);

    if (param == NULL) {
        if (!page_match->params_allowed) {
            log_warn("Parameter sent when not allowed\n");
            cancel_connection(ev_data);
            return;
        } else {
            param = &ev_data->default_params;
        }
    }
    log_dbg("Using param \"%s\"\n", param->name ? param->name : "default");

    /* Enforce maximum parameter length */
#if ENABLE_PARAM_LEN_CHECK
    size_t url_decode_len = url_encode_buf_len(value, value_len, ev_data);
    if (url_decode_len > param->max_param_len) {
        log_warn("Length of parameter value \"%.*s\" %ld exceeds max %d\n",
                (int ) value_len, value, url_decode_len, param->max_param_len);
        cancel_connection(ev_data);
    }
#endif

    //@Todo(Travis) check whitelist
}

/* Check parameters passed in the URL */
void check_url_params(struct event_data *ev_data) {
    log_trace("Checking URL parameters\n");
    bytearray_t *url = ev_data->url;
    char *quest = memchr(url->data, '?', url->len);
    if (quest == NULL) {
        log_trace("URL has no parameters\n");
        return;
    }

    char *query = quest + 1;
    size_t query_len = url->len - (query - url->data);

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

/* Do checks that are possible after the header is received */
void do_after_header_checks(struct event_data *ev_data) {
#if ENABLE_REQUEST_TYPE_CHECK
    check_request_type(ev_data);
#endif

#if ENABLE_PARAM_CHECKS
    check_url_params(ev_data);
#endif
}

/* Handles incoming client requests.
 * Returns boolean indicated if connection is done */
int handle_client_event(struct epoll_event *ev) {
    int s;
    int done = 0;
    size_t nparsed;
    ssize_t count;
    char buf[READ_BUF_SIZE];

    struct event_data *ev_data = (struct event_data *) ev->data.ptr;

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

#ifdef PRINT_CONVERSATION
        /* Write the buffer to standard output */
        s = write(1, ">> ", 3);
        s = write(1, buf, count);
        if (s == -1) {
            perror("write");
        }
#endif

        nparsed = http_parser_execute(&ev_data->parser, &parser_settings, buf,
                count);

        log_dbg("Parsed %ld / %ld bytes\n", nparsed, count);

        if (ev_data->parser.upgrade) {
            /* Wants to upgrade connection */
            log_warn("HTTP upgrade not supported");
            done = 1;
            break;
        }

        if (!ev_data->have_done_after_header_checks
                        && ev_data->state >= HEADERS_COMPLETE) {
            do_after_header_checks(ev_data);
            ev_data->have_done_after_header_checks = true;
        }

        //@Todo(Travis) check POST parameters

        if (is_conn_cancelled(ev_data)) {
            if (send_error_page(ev_data->listen_fd)) {
                log_info("Failed to send error page.\n");
            }
            close(ev_data->listen_fd);
            close(ev_data->send_fd);
            ev_data->listen_fd = 0;
            ev_data->send_fd = 0;
            log_info("Closed_connection\n");
            done = 1;
            break;
        }

        s = sendall(ev_data->send_fd, buf, count);
        if (s < 0) {
            log_error("sendall failed\n");
            done = 1;
            break;
        }
    }

    return done;
}

/* Handle a server response event */
int handle_server_event(struct epoll_event *ev) {
    int s;
    int done = 0;

    while (1) {
        ssize_t count;
        char buf[READ_BUF_SIZE];

        count = read(((struct event_data *) ev->data.ptr)->listen_fd, buf,
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
            break;
        }

#ifdef PRINT_CONVERSATION
        /* Write the buffer to standard output */
        s = write(1, "<< ", 3);
        s = write(1, buf, count);
        if (s == -1) {
            perror("write");
        }
#endif

        s = sendall(((struct event_data *) ev->data.ptr)->send_fd, buf, count);
        if (s < 0) {
            done = 1;
            break;
        }
    }

    return done;
}

/* Handle epoll event */
void handle_event(int efd, struct epoll_event *ev, int sfd) {
    int done;

    if ((ev->events & EPOLLERR) || (ev->events & EPOLLHUP)
            || (!(ev->events & EPOLLIN))) {
        /* An error has occured on this fd, or the socket is not
         ready for reading (why were we notified then?) */
        fprintf(stderr, "epoll error\n");
        free_connection_info(((struct event_data *) (ev->data.ptr))->conn_info);
        return;

    } else if (sfd == ((struct event_data *) ev->data.ptr)->listen_fd) {
        /* We have a notification on the listening socket, which
         means one or more incoming connections. */
        handle_new_connection(efd, ev, sfd);
        return;

    } else if (ev->data.ptr != NULL) {
        /* We have data on the fd waiting to be read. Read and
         display it. We must read whatever data is available
         completely, as we are running in edge-triggered mode
         and won't get a notification again for the same
         data. */
        struct event_data *ev_data = (struct event_data *) ev->data.ptr;

        if (ev_data->type == CLIENT_LISTENER) {
            done = handle_client_event(ev);
        } else if (ev_data->type == SERVER_LISTENER) {
            done = handle_server_event(ev);
        } else {
            fprintf(stderr, "Invalid event_data type \"%d\"\n", ev_data->type);
            done = 1;
        }

        if (done) {
            free_connection_info(ev_data->conn_info);
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
}

int main(int argc, char *argv[]) {
    int sfd, s;
    int efd;
    struct epoll_event event;
    struct epoll_event *events;
    char *error_page_file = NULL;

    memset(&event, 0, sizeof(struct epoll_event));

    if (argc != 3 && argc != 4) {
        fprintf(stderr, "Usage: %s SHIM_PORT SERVER_PORT [ERROR_PAGE]\n", argv[0]);
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
        for (i = 0; i < n; i++) {
            handle_event(efd, &events[i], sfd);
        }
    }

    close(efd);
    free(events);
    free(event.data.ptr);
    free(error_page_buf);

    close(sfd);

    return EXIT_SUCCESS;
}
