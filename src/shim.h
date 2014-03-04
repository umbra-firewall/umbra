#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>

#define MAXEVENTS 256

/* Code adopted from https://banu.com/blog/2/how-to-use-epoll-a-complete-example-in-c/ */

struct event_data {
	int client_listen_fd;
	int server_connect_fd;
};


int make_socket_non_blocking(int sfd);
int create_and_bind(char *port);
int create_and_connect(char *port);
void free_epoll_event_data(struct epoll_event *ev);
int sendall(int sockfd, const void *buf, size_t len);
