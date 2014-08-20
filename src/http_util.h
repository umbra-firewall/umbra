#ifndef HTTP_UTIL_H
#define HTTP_UTIL_H

#include "shim_struct.h"
#include "http_parser.h"

/* HTTP_REQ_* definitions must be defined in same order as http_parser */
#define HTTP_REQ_DELETE (1 << 0)
#define HTTP_REQ_GET (1 << 1)
#define HTTP_REQ_HEAD (1 << 2)
#define HTTP_REQ_POST (1 << 3)
#define HTTP_REQ_PUT (1 << 4)
#define HTTP_REQ_CONNECT (1 << 5)
#define HTTP_REQ_OPTIONS (1 << 6)
#define HTTP_REQ_TRACE (1 << 7)
#define NUM_HTTP_REQ_TYPES 8


/* HTTP macros */
#define CRLF "\r\n"
#define LF "\n"

#define MAX_HTTP_REASON_PHRASE_LEN 200

#define HTTP_RESPONSE_OK \
    "HTTP/1.0 201 OK\r\n" \
    "Content-type: text/html\r\n" \
    "\r\n"

#define HTTP_RESPONSE_FORBIDDEN \
    "HTTP/1.0 403 Forbidden\r\n" \
    "Content-type: text/html\r\n" \
    "Cache-Control: no-cache, no-store, must-revalidate\r\n" \
    "Pragma: no-cache\r\n" \
    "Expires: 0\r\n" \
    "\r\n"

#define DEFAULT_ERROR_PAGE_STR \
    "<html>" \
    "<head>" \
    "<title>Action Not Allowed</title>" \
    "</head>" \
    "<body>" \
    "<h1>Action Not Allowed</h1>" \
    "This request has been blocked by the firewall shim. " \
    "Please contact your network administrator for more details." \
    "</body>" \
    "</html>"


/* Global variables */
extern char *error_page_buf;
extern size_t error_page_len;

struct event_data;
struct fd_ctx;

/* HTTP utility functions */
int send_error_page(struct fd_ctx *fd_ctx);
int http_parser_method_to_shim(enum http_method method);
int init_error_page(char *error_page_file);
bool str_to_url_encoded_memeq(const char *str, char *url_data,
        size_t url_data_len, bool *is_valid);
void print_headers(struct event_data *ev_data);
int send_http_headers(struct event_data *ev_data);
int get_http_response_phrase(struct event_data *ev_data, char *buf,
        size_t *phrase_len);

#endif
