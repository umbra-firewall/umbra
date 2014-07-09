#include "shim.h"

// Include dynamic configuration
#include "config_header.h"

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

/* Callbacks for HTTP requests and responses */

void cancel_connection(http_parser *p) {
    struct event_data *ev_data = (struct event_data *) p->data;
    ev_data->is_cancelled = true;
}

bool is_conn_cancelled(struct event_data *ev_data) {
    if (ev_data->is_cancelled) {
        return true;
    } else {
        return false;
    }
}

int on_message_begin_cb(http_parser* p) {
    log_trace("***MESSAGE BEGIN***\n");
    return 0;
}

int on_headers_complete_cb(http_parser* p) {
    log_trace("***HEADERS COMPLETE***\n");
    struct event_data *ev_data = (struct event_data *) p->data;
    ev_data->state = WAITING_FOR_BODY;
    return 0;
}

int on_message_complete_cb(http_parser* p) {
    log_trace("***MESSAGE COMPLETE***\n");
    struct event_data *ev_data = (struct event_data *) p->data;
    ev_data->state = MESSAGE_COMPLETE;
    return 0;
}

int on_url_cb(http_parser* p, const char* at, size_t length) {
    log_trace("Url: %.*s\n", (int)length, at);
    struct event_data *ev_data = (struct event_data *) p->data;
    ev_data->state = WAITING_FOR_HEADER;
    return 0;
}

int on_header_field_cb(http_parser* p, const char* at, size_t length) {
    //log_trace("Header field: %.*s\n", (int)length, at);
    if (length > MAX_HEADER_FIELD_LEN) {
        log_info("Blocked request because header field length %ld; "
                "max is %ld\n",
                length, (long ) MAX_HEADER_FIELD_LEN);
        cancel_connection(p);
    }
    return 0;
}

int on_header_value_cb(http_parser* p, const char* at, size_t length) {
    //log_trace("Header value: %.*s\n", (int)length, at);
    if (length > MAX_HEADER_VALUE_LEN) {
        log_info("Blocked request because header value length %ld; "
                "max is %ld\n",
                length, (long ) MAX_HEADER_VALUE_LEN);
        cancel_connection(p);
    }
    return 0;
}

int on_body_cb(http_parser* p, const char* at, size_t length) {
    log_trace("Body: %.*s\n", (int)length, at);
    return 0;
}

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

void free_connection_info(struct connection_info *ci) {
    log_dbg("Freeing conn info %p (%d total)\n", ci, --num_conn_infos);
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
            free(ci->client_ev_data);
        }
        if (ci->server_ev_data) {
            free(ci->server_ev_data);
        }

        free(ci);
    }
}

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

struct event_data *init_event_data(event_t type, int listen_fd, int send_fd,
        enum http_parser_type parser_type, struct connection_info *conn_info) {

    struct event_data *ev_data = calloc(1, sizeof(struct event_data));

    if (ev_data != NULL) {
        ev_data->type = type;
        ev_data->listen_fd = listen_fd;
        ev_data->send_fd = send_fd;
        ev_data->state = WAITING_FOR_HEADER;
        ev_data->is_cancelled = false;
        ev_data->conn_info = conn_info;

        http_parser_init(&ev_data->parser, parser_type);
        ev_data->parser.data = ev_data;
    }

    return ev_data;
}



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

int send_error_page(int sock) {
    if (sendall(sock, SIMPLE_HTTP_RESPONSE, sizeof(SIMPLE_HTTP_RESPONSE)) < 0) {
        return -1;
    }
    if (sendall(sock, error_page_buf, error_page_len) < 0) {
        return -1;
    }
    return 0;
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

        nparsed = http_parser_execute(&ev_data->parser, &parser_settings, buf, count);

        log_dbg("Parsed %ld / %ld bytes\n", nparsed, count);

        if (ev_data->parser.upgrade) {
            /* Wants to upgrade connection */
            log_warn("HTTP upgrade not supported");
            done = 1;
            break;
        } else if (is_conn_cancelled(ev_data)) {
            if (send_error_page(ev_data->listen_fd)) {
                log_info("Failed to send error page.\n");
            }
            close(ev_data->listen_fd);
            close(ev_data->send_fd);
            ev_data->listen_fd = 0;
            ev_data->send_fd = 0;
            log_info("Closed_connection");
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

void sigint_handler(int dummy) {
    sigint_received = true;
}

void init_structures(char *error_page_file) {
    /* Initialize error page foramt */
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
            log_error("Failed to open error page file \"%s\"\n", error_page_file);
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

    init_config_vars();
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
