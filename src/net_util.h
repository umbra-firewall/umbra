#ifndef NET_UTIL_H
#define NET_UTIL_H

/* Network functions */
int make_socket_non_blocking(int sfd);
int create_and_bind(char *port);
int create_and_connect(char *port);
int sendall(int sockfd, const void *buf, size_t len);

#endif
