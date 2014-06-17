#include "shim.h"

// Include dynamic configuration
#include "config_header.h"

int connction_num = 0;
char *http_port_str, *server_http_port_str;

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
    DBG_PRINT("Freeing conn info %p\n", ci);
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

void handle_new_connection(int efd, struct epoll_event *ev, int sfd) {
    int s;
    struct epoll_event client_event, server_event;
    struct event_data *client_event_data, *server_event_data;
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
            DBG_PRINT(
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
        client_event_data = calloc(1, sizeof(struct event_data));
        if (client_event_data == NULL) {
            perror("calloc");
            abort();
        }

        server_event_data = calloc(1, sizeof(struct event_data));
        if (server_event_data == NULL) {
            perror("calloc");
            abort();
        }

        conn_info = calloc(1, sizeof(struct connection_info));
        if (server_event_data == NULL) {
            perror("calloc");
            abort();
        }

        conn_info->client_ev_data = client_event_data;
        conn_info->server_ev_data = server_event_data;

        client_event_data->type = CLIENT_LISTENER;
        client_event_data->listen_fd = infd;
        client_event_data->send_fd = outfd;
        client_event_data->state = WAITING_FOR_HEADER;
        client_event_data->conn_info = conn_info;

        server_event_data->type = SERVER_LISTENER;
        server_event_data->listen_fd = outfd;
        server_event_data->send_fd = infd;
        server_event_data->state = WAITING_FOR_HEADER;
        server_event_data->conn_info = conn_info;

        client_event.data.ptr = client_event_data;
        client_event.events = EPOLLIN | EPOLLET;

        server_event.data.ptr = server_event_data;
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

int handle_client_event(struct epoll_event *ev) {
    int s;
    int done = 0;

    while (1) {
        ssize_t count;
        char buf[1024];

        count = read(((struct event_data *) ev->data.ptr)->listen_fd, buf,
                sizeof(buf));
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
        s = write(1, ">> ", 3);
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

int handle_server_event(struct epoll_event *ev) {
    int s;
    int done = 0;

    while (1) {
        ssize_t count;
        char buf[1024];

        count = read(((struct event_data *) ev->data.ptr)->listen_fd, buf,
                sizeof(buf));
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
    exit(0);
}

int main(int argc, char *argv[]) {
    int sfd, s;
    int efd;
    struct epoll_event event;
    struct epoll_event *events;

    memset(&event, 0, sizeof(struct epoll_event));

    if (argc != 3) {
        fprintf(stderr, "Usage: %s SHIM_PORT SERVER_PORT\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (signal(SIGINT, sigint_handler) < 0) {
        perror("signal");
        abort();
    }

    http_port_str = argv[1];
    server_http_port_str = argv[2];

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
    memset(&event, 0, sizeof(struct epoll_event));

    /* Buffer where events are returned */
    events = calloc(MAXEVENTS, sizeof(event));

    /* The event loop */
    while (1) {
        int n, i;

        /* Block indefinitely */
        n = epoll_wait(efd, events, MAXEVENTS, -1);
        for (i = 0; i < n; i++) {
            handle_event(efd, &events[i], sfd);
        }
    }

    free(events);

    close(sfd);

    return EXIT_SUCCESS;
}
