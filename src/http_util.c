#include "shim.h"
#include "http_util.h"
#include "net_util.h"
#include "log.h"


char *error_page_buf = NULL;
size_t error_page_len;

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

/* Returns whether NUL terminated string and URL encoded buffer are equal.
 * Sets is_valid to false if the string is not valid URL encoding. */
bool str_to_url_encoded_memeq(const char *str, char *url_data,
        size_t url_data_len, bool *is_valid) {
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
                /* Invalid percent encoding */
                if (is_valid) {
                    *is_valid = false;
                }
                return false;
            }
        } else {
            return false;
        }
    }

    if (is_valid) {
        *is_valid = true;
    }
    return str == str_should_end && *str == '\0';
}

#ifdef DEBUG
void print_headers(struct event_data *ev_data) {
    /* Print header pairs saved in struct_array */
    int i;
    size_t len = ev_data->all_header_fields->len;
    log_dbg("All HTTP Headers:\n");
    for (i = 0; i < len; i++) {
        log_dbg("  %.*s: %.*s\n",
                (int) ev_data->all_header_fields->data[i]->len,
                ev_data->all_header_fields->data[i]->data,
                (int) ev_data->all_header_values->data[i]->len,
                ev_data->all_header_values->data[i]->data);
    }
}
#endif

/* Send HTTP headers based on stored fields and values */
int send_http_headers(struct event_data *ev_data) {
    log_dbg("Now modified headers\n");
#ifdef DEBUG
    print_headers(ev_data);
#endif

    int i, rc;
    char *send_buf = NULL;
    char *p;
    int header_len_estimate = 4; /* Account for first/last newlines */
    size_t send_buf_len = 0;
    size_t newline_len = strlen(ev_data->http_msg_newline);
    char reason_phrase[MAX_HTTP_REASON_PHRASE_LEN + 1];
    size_t phrase_len;

    log_trace("Preparing buffer with all headers to send\n");

    /* Assert that there are the same number of header fields and values */
    if (ev_data->all_header_fields->len != ev_data->all_header_values->len) {
        log_error("The number of header fields != number of values\n");
        goto error;
    }

    /* Account for field, value, colon, space, and newline */
    size_t len = ev_data->all_header_fields->len;
    for (i = 0; i < len; i++) {
        header_len_estimate += ev_data->all_header_fields->data[i]->len
                + ev_data->all_header_values->data[i]->len + 2 + newline_len;
    }

    /* Calculate space required */
    if (ev_data->type == CLIENT_LISTENER) {
        /* Example: GET / HTTP/1.1 */

        /* Account for first line bytes */
        size_t method_len = strlen(http_method_str(ev_data->parser.method));
        size_t url_len = ev_data->url->len;
        header_len_estimate += method_len + 2 + url_len + strlen("HTTP/1.1");
    } else { /* SERVER_LISTENER */
        /* Example: HTTP/1.1 200 OK */

        /* Account for first line bytes */
        if (ev_data->parser.status_code > 999) {
            log_error("Response status code too large: %u\n",
                    ev_data->parser.status_code);
        }

        /* Get Response phrase */
        if (get_http_response_phrase(ev_data, reason_phrase, &phrase_len) < 0) {
            log_error("Could not parse HTTP response reason phrase\n");
            goto error;
        }

        header_len_estimate += strlen("HTTP/1.1") + 5 + phrase_len;
    }

    /* Allocate send buffer */
    send_buf = malloc(header_len_estimate);
    if (send_buf == NULL) {
        perror("malloc");
        goto error;
    }
    p = send_buf;


    /* Add first line to send buffer */
    log_dbg("  Adding first line\n");
    if (ev_data->type == CLIENT_LISTENER) {
        rc = snprintf(p, header_len_estimate, "%s %.*s HTTP/%d.%d%s",
                http_method_str(ev_data->parser.method),
                (int) ev_data->url->len, ev_data->url->data,
                ev_data->parser.http_major, ev_data->parser.http_minor,
                ev_data->http_msg_newline);
        if (rc > header_len_estimate || rc < 0) {
            log_error("rc=%d, header_len_estimate=%d\n", rc, header_len_estimate);
            goto error;
        }
        p += rc;
        send_buf_len += rc;
        header_len_estimate -= rc;
    } else { /* SERVER_LISTENER */
        rc = snprintf(p, header_len_estimate, "HTTP/%d.%d %03u %.*s%s",
                ev_data->parser.http_major, ev_data->parser.http_minor,
                ev_data->parser.status_code, (int) phrase_len, reason_phrase,
                ev_data->http_msg_newline);
        if (rc > header_len_estimate || rc < 0) {
            log_error("rc=%d, header_len_estimate=%d\n", rc, header_len_estimate);
            goto error;
        }
        p += rc;
        send_buf_len += rc;
        header_len_estimate -= rc;
    }


    /* Add headers to send buffer */
    for (i = 0; i < len; i++) {
        if (header_len_estimate <= 0) {
            goto error;
        }
        log_dbg("  Adding header %d\n", i);
        /* Fields/values should be NUL terminated from check_header_pair() */
        rc = snprintf(p, header_len_estimate, "%s: %s%s",
                ev_data->all_header_fields->data[i]->data,
                ev_data->all_header_values->data[i]->data,
                ev_data->http_msg_newline);
        if (rc > header_len_estimate || rc < 0) {
            log_error("rc=%d, header_len_estimate=%d\n", rc,
                    header_len_estimate);
            goto error;
        }
        p += rc;
        send_buf_len += rc;
        header_len_estimate -= rc;
    }

    /* Add last newline */
    if (header_len_estimate < newline_len) {
        goto error;
    }
    memcpy(p, ev_data->http_msg_newline, newline_len);
    p += newline_len;
    send_buf_len += newline_len;
    header_len_estimate -= newline_len;

    /* Send buffer */
    log_trace("Sending header buffer\n");
    if (sendall(ev_data->send_fd, send_buf, send_buf_len) < 0) {
        goto error;
    }

    free(send_buf);
    return 0;

error:
    free(send_buf);
    cancel_connection(ev_data);
    return -1;
}

/* Writes HTTP response phrase to buf of length MAX_HTTP_REASON_PHRASE_LEN + 1.
 * Writes length of phrase to phrase_len.
 * Returns 0 on success, -1 otherwise. */
int get_http_response_phrase(struct event_data *ev_data, char *buf,
        size_t *phrase_len) {
    char http_version[20];
    unsigned int status;
    memset(buf, 0, MAX_HTTP_REASON_PHRASE_LEN + 1);

    if (phrase_len == NULL) {
        return -1;
    }

    int rc = sscanf(ev_data->headers_cache->data,
            "%s %u %" XSTR(MAX_HTTP_REASON_PHRASE_LEN) "[^\r\n]\n",
            http_version, &status, buf);
    if (rc != 3) {
        return -1;
    }

    *phrase_len = strlen(buf);

    return 0;
}
