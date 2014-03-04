#include "shim.h"

int connction_num = 0;

int make_socket_non_blocking(int sfd)
{
    int flags, s;

    flags = fcntl(sfd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl");
        return -1;
    }

    flags |= O_NONBLOCK;
    s = fcntl (sfd, F_SETFL, flags);
    if (s == -1) {
        perror("fcntl");
        return -1;
    }

    return 0;
}

int create_and_bind(char *port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, sfd;
    int yes=1;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;     /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */
    hints.ai_flags = AI_PASSIVE;     /* All interfaces */

    s = getaddrinfo(NULL, port, &hints, &result);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror (s));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1) {
            continue;
        }

        if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        s = bind(sfd, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            /* We managed to bind successfully! */
            break;
        }

        close (sfd);
    }

    if (rp == NULL) {
        fprintf(stderr, "Could not bind\n");
        return -1;
    }

    freeaddrinfo(result);

    return sfd;
}

int create_and_connect(char *port)
{
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
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
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

void free_epoll_event_data(struct epoll_event *ev)
{
    if (ev != NULL) {
        struct event_data *data = (struct event_data *) ev->data.ptr;
        if (data->client_listen_fd != 0) {
            close(data->client_listen_fd);
        }
        if (data->server_connect_fd != 0) {
            close(data->server_connect_fd);
        }
        free(data);
    }
}

int sendall(int sockfd, const void *buf, size_t len)
{
    int sent_bytes;
    while (len > 0) {
        sent_bytes = send(sockfd, buf, len, 0);
        if (sent_bytes < 0) {
            perror("send");
            abort();
        }
        buf += sent_bytes;
        len -= sent_bytes;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    int sfd, s;
    int efd;
    struct epoll_event event;
    struct epoll_event *events;
    char *shim_port_str, *server_port_str;

    memset(&event, 0, sizeof(struct epoll_event));

    if (argc != 3) {
        fprintf(stderr, "Usage: %s SHIM_PORT SERVER_PORT \n", argv[0]);
        exit(EXIT_FAILURE);
    }

    shim_port_str = argv[1];
    server_port_str = argv[2];

    sfd = create_and_bind(shim_port_str);
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

    efd = epoll_create1(0);
    if (efd == -1) {
        perror("epoll_create");
        abort();
    }

    event.data.ptr = calloc(1, sizeof(struct event_data));
    if (event.data.ptr == NULL) {
        perror("calloc");
        abort();
    }

    ((struct event_data *) event.data.ptr)->client_listen_fd = sfd;

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
            if ((events[i].events & EPOLLERR) ||
                    (events[i].events & EPOLLHUP) ||
                    (!(events[i].events & EPOLLIN))) {
                /* An error has occured on this fd, or the socket is not
                   ready for reading (why were we notified then?) */
                fprintf(stderr, "epoll error\n");
                free_epoll_event_data(&events[i]);
                continue;

            } else if (sfd == ((struct event_data *) events[i].data.ptr)->client_listen_fd) {
                /* We have a notification on the listening socket, which
                   means one or more incoming connections. */
                while (1) {
                    struct sockaddr in_addr;
                    socklen_t in_len;
                    int infd, outfd;
                    char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

                    in_len = sizeof(in_addr);
                    infd = accept(sfd, &in_addr, &in_len);
                    if (infd == -1) {
                        if ((errno == EAGAIN) ||
                                (errno == EWOULDBLOCK)) {
                            /* We have processed all incoming
                               connections. */
                            break;
                        } else {
                            perror("accept");
                            break;
                        }
                    }

                    s = getnameinfo(&in_addr, in_len,
                                    hbuf, sizeof(hbuf),
                                    sbuf, sizeof(sbuf),
                                    NI_NUMERICHOST | NI_NUMERICSERV);
                    if (s == 0) {
                        printf("Accepted connection on descriptor %d "
                               "(host=%s, port=%s, i=%d)\n", infd, hbuf, sbuf, i);
                    }

                    /* Make the incoming socket non-blocking and add it to the
                       list of fds to monitor. */
                    s = make_socket_non_blocking(infd);
                    if (s < 0) {
                        abort();
                    }

                    /* Create proxy socket to server */
                    outfd = create_and_connect(server_port_str);
                    if (outfd < 0) {
                        abort();
                    }

                    /* Allocate data */
                    event.data.ptr = calloc(1, sizeof(struct event_data));
                    if (event.data.ptr == NULL) {
                        perror("calloc failed");
                        abort();
                    }

                    ((struct event_data *) event.data.ptr)->client_listen_fd = infd;
                    ((struct event_data *) event.data.ptr)->server_connect_fd = outfd;
                    event.events = EPOLLIN | EPOLLET;
                    s = epoll_ctl(efd, EPOLL_CTL_ADD, infd, &event);
                    if (s == -1) {
                        perror("epoll_ctl");
                        abort();
                    }
                    memset(&event, 0, sizeof(struct epoll_event));
                }
                continue;

            } else {
                /* We have data on the fd waiting to be read. Read and
                   display it. We must read whatever data is available
                   completely, as we are running in edge-triggered mode
                   and won't get a notification again for the same
                   data. */
                int done = 0;

                while (1) {
                    ssize_t count;
                    char buf[1024];

                    count = read(((struct event_data *) events[i].data.ptr)->client_listen_fd,
                                 buf, sizeof(buf));
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

                    /* Write the buffer to standard output */
                    s = write(1, buf, count);
                    if (s == -1) {
                        perror("write");
                        abort();
                    }

                    sendall(((struct event_data *) events[i].data.ptr)->server_connect_fd,
                            buf, count);
                }

                if (done) {
                    printf("Closed connection on descriptor %d\n",
                           ((struct event_data *) events[i].data.ptr)->client_listen_fd);

                    /* Closing the descriptor will make epoll remove it
                       from the set of descriptors which are monitored. */
                    free_epoll_event_data(&events[i]);
                }
            }
        }
    }

    free(events);

    close(sfd);

    return EXIT_SUCCESS;
}