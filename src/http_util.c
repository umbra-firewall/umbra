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
