#include <stddef.h>
#include "log.h"
#include "net_util.h"
#include "shim_struct.h"

#ifdef TRACE
int num_conn_infos = 0;
#endif

/* Initialize connection_info structure */
struct connection_info *init_conn_info(int infd, int outfd, bool in_is_tls,
        bool out_is_tls) {
    struct event_data *client_ev_data = NULL, *server_ev_data = NULL;
    struct connection_info *conn_info = NULL;
    struct fd_ctx *in_fd_ctx = NULL, *out_fd_ctx = NULL;
    log_trace("init_conn_info() (%d total)\n", ++num_conn_infos);

    conn_info = calloc(1, sizeof(struct connection_info));
    if (conn_info == NULL) {
        goto fail;
    }

    /* Incoming socket */
    if ((in_fd_ctx = init_fd_ctx(infd, in_is_tls, true)) == NULL) {
        goto fail;
    }

    /* Outgoing socket */
    if ((out_fd_ctx = init_fd_ctx(outfd, out_is_tls, false)) == NULL) {
        goto fail;
    }

    client_ev_data = init_event_data(CLIENT_LISTENER, in_fd_ctx, out_fd_ctx,
            HTTP_REQUEST, conn_info);
    if (client_ev_data == NULL) {
        goto fail;
    }

    server_ev_data = init_event_data(SERVER_LISTENER, out_fd_ctx, in_fd_ctx,
            HTTP_RESPONSE, conn_info);
    if (server_ev_data == NULL) {
        goto fail;
    }

    conn_info->client_ev_data = client_ev_data;
    conn_info->server_ev_data = server_ev_data;
    conn_info->page_match = NULL;

    return conn_info;

fail:
#ifdef TRACE
    num_conn_infos--;
#endif
    free_fd_ctx(in_fd_ctx);
    free_fd_ctx(out_fd_ctx);
    free(client_ev_data);
    free(server_ev_data);
    free(conn_info);
    return NULL;
}

/* Initializes given fd_ctx. Returns pointer to new fd_ctx on success, NULL
 * otherwise.
 */
struct fd_ctx *init_fd_ctx(int sock_fd, bool is_tls, bool is_server) {
    struct fd_ctx *fd_ctx = calloc(1, sizeof(struct fd_ctx));
    if (fd_ctx == NULL) {
        return NULL;
    }

    fd_ctx->sock_fd = sock_fd;
    fd_ctx->is_tls = is_tls;
    fd_ctx->is_server = is_server;

#if ENABLE_HTTPS
    fd_ctx->ssl = NULL;
    if (is_tls) {
        SSL_CTX *ssl_ctx = is_server ? ssl_ctx_server : ssl_ctx_client;
        /* Create SSL from socket */
        if ((fd_ctx->ssl = SSL_new(ssl_ctx)) == NULL) {
            log_ssl_error("SSL_new() failed\n");
            goto error;
        }

        /* Set to use socket */
        if (SSL_set_fd(fd_ctx->ssl, fd_ctx->sock_fd) == 0) {
            log_ssl_error("SSL_set_fd() failed\n");
            goto error;
        }

        /* Make initial SSL_accept (for server) or SSL_connect (for client) */
        const char *func_name = (is_server ? "SSL_accept" : "SSL_connect");
        int (*func)(SSL *) = (is_server ? SSL_accept : SSL_connect);
        int rc = 0;
        while (rc != 1) {
            rc = func(fd_ctx->ssl);
            if (rc <= 0) {
                /* Possible Failure */
                int err = SSL_get_error(fd_ctx->ssl, rc);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                    log_dbg("Other end wants %s for %s()\n",
                            err == SSL_ERROR_WANT_READ ? "READ" : "WRITE",
                            func_name);
                    continue;
                }
                log_ssl_error("%s() failed\n", func_name);
                goto error;
            }
        }

        log_trace("%s succeeded\n", func_name);
    }
#endif

    return fd_ctx;

#if ENABLE_HTTPS
error:
    SSL_free(fd_ctx->ssl);
    free(fd_ctx);
    return NULL;
#endif
}

/* Free memory associated with fd_ctx */
void free_fd_ctx(struct fd_ctx *fd_ctx) {
    if (fd_ctx == NULL) {
        return;
    }
#if ENABLE_HTTPS
    if (fd_ctx->ssl) {
        SSL_shutdown(fd_ctx->ssl);
        SSL_free(fd_ctx->ssl);
    }
#endif

    close_fd_if_valid(fd_ctx->sock_fd);

    free(fd_ctx);
}

/* Initialize event data structure */
struct event_data *init_event_data(event_t type, struct fd_ctx *listen_fd,
        struct fd_ctx *send_fd, enum http_parser_type parser_type,
        struct connection_info *conn_info) {

    log_trace("Initializing new event_data\n");
    struct event_data *ev_data = calloc(1, sizeof(struct event_data));

    if (ev_data == NULL) {
        return NULL;
    }

    ev_data->type = type;

#if ENABLE_SESSION_TRACKING
    ev_data->chunk_state = CHUNK_SZ;
#endif

    ev_data->listen_fd = listen_fd;
    ev_data->send_fd = send_fd;

    ev_data->conn_info = conn_info;
    ev_data->http_msg_newline = NULL;

    if ((ev_data->url = bytearray_new()) == NULL) {
        log_warn("Allocating new bytearray failed\n");
        goto error;
    }

    if ((ev_data->body = bytearray_new()) == NULL) {
        log_warn("Allocating new bytearray failed\n");
        goto error;
    }

    if ((ev_data->headers_cache = bytearray_new()) == NULL) {
        log_warn("Allocating new bytearray failed\n");
        goto error;
    }

#if ENABLE_SESSION_TRACKING
    ev_data->cookie_header_value_ref = NULL;
    ev_data->content_length_header_value_ref = NULL;

    if ((ev_data->cookie_name_array = struct_array_new()) == NULL) {
        log_warn("Allocating new struct array failed\n");
        goto error;
    }

    if ((ev_data->cookie_value_array = struct_array_new()) == NULL) {
        log_warn("Allocating new struct array failed\n");
        goto error;
    }

    if ((ev_data->chunk = bytearray_new()) == NULL) {
        log_warn("Allocating new bytearray failed\n");
        goto error;
    }

    ev_data->content_original_length = -1;
#endif

    if ((ev_data->header_field = bytearray_new()) == NULL) {
        log_warn("Allocating new bytearray failed\n");
        goto error;
    }

    if ((ev_data->header_value = bytearray_new()) == NULL) {
        log_warn("Allocating new bytearray failed\n");
        goto error;
    }

    if ((ev_data->all_header_fields = struct_array_new()) == NULL) {
        goto error;
    }

    if ((ev_data->all_header_values = struct_array_new()) == NULL) {
        goto error;
    }

    /* Initialize HTTP parser */
    http_parser_init(&ev_data->parser, parser_type);
    ev_data->parser.data = ev_data;

    return ev_data;

error:
    bytearray_free(ev_data->url);
    bytearray_free(ev_data->body);

    bytearray_free(ev_data->headers_cache);

#if ENABLE_SESSION_TRACKING
    struct_array_free(ev_data->cookie_name_array, true);
    struct_array_free(ev_data->cookie_value_array, true);
#endif

    bytearray_free(ev_data->header_field);
    bytearray_free(ev_data->header_value);

    struct_array_free(ev_data->all_header_fields, true);
    struct_array_free(ev_data->all_header_values, true);

    free(ev_data);
    return NULL;
}

/* Reset state of event_data structure. This should return its state after being
 * initialized with the exception of bytearrays, which should just be
 * cleared. */
void reset_event_data(struct event_data *ev) {
    if (ev == NULL) {
        return;
    }

    http_parser_init(&ev->parser, ev->parser.type);

    ev->http_msg_newline = NULL;

#if ENABLE_SESSION_TRACKING
    ev->chunk_state = CHUNK_SZ;
#endif

    bytearray_clear(ev->url);
    bytearray_clear(ev->body);
    bytearray_clear(ev->headers_cache);

#if ENABLE_SESSION_TRACKING
    ev->cookie_header_value_ref = NULL;
    ev->content_length_header_value_ref = NULL;

    struct_array_clear(ev->cookie_name_array, true);
    struct_array_clear(ev->cookie_value_array, true);
    bytearray_clear(ev->chunk);

    ev->content_original_length = -1;
#endif

    bytearray_clear(ev->header_field);
    bytearray_clear(ev->header_value);

    struct_array_clear(ev->all_header_fields, true);
    struct_array_clear(ev->all_header_values, true);

    ev->is_cancelled = false;
    ev->msg_begun = false;
    ev->headers_complete = false;
    ev->msg_complete = false;
    ev->just_visited_header_field = false;
    ev->got_eagain = false;
    ev->sent_js_snippet = false;
    ev->headers_have_been_sent = false;

#if ENABLE_SESSION_TRACKING
    ev->content_length_specified = false;
    ev->chunked_encoding_specified = false;
    ev->on_last_chunk = false;
    ev->found_shim_session_cookie = false;
#endif

#if ENABLE_CSRF_PROTECTION
    ev->found_csrf_correct_token = false;
#endif
}

/* Reset state of connection structure (including its event_data structures) */
void reset_connection_info(struct connection_info *ci) {
    log_trace("Reseting connection info of %p\n", ci);

    if (ci == NULL) {
        return;
    }

    ci->session = NULL;
    ci->page_match = NULL;

    reset_event_data(ci->client_ev_data);
    reset_event_data(ci->server_ev_data);
}

/* Free memory associated with event data */
void free_event_data(struct event_data *ev) {
    log_trace("Freeing event data %p\n", ev);

    if (ev == NULL) {
        return;
    }

    bytearray_free(ev->url);
    bytearray_free(ev->body);
    bytearray_free(ev->headers_cache);

#if ENABLE_SESSION_TRACKING
    struct_array_free(ev->cookie_name_array, true);
    struct_array_free(ev->cookie_value_array, true);
    bytearray_free(ev->chunk);
#endif

    bytearray_free(ev->header_field);
    bytearray_free(ev->header_value);

    struct_array_free(ev->all_header_fields, true);
    struct_array_free(ev->all_header_values, true);

    free(ev);
}

/* Free memory and close sockets associated with connection structure */
void free_connection_info(struct connection_info *ci) {
    if (ci != NULL) {
        log_trace("Freeing conn info %p (%d total)\n", ci, --num_conn_infos);
        if (ci->client_ev_data) {
            /* Free fd_ctx's here because both event_data's reference both and
             * we want to avoid a double free.
             */
            free_fd_ctx(ci->client_ev_data->listen_fd);
            free_fd_ctx(ci->client_ev_data->send_fd);

            free_event_data(ci->client_ev_data);
        }
        free_event_data(ci->server_ev_data);

        free(ci);
    } else {
        log_trace("Freeing NULL conn info (%d total)\n", num_conn_infos);
    }
}

/* Copy default param fields in page_conf struct to params struct */
void copy_default_params(struct page_conf *page_conf, struct params *params) {
    params->max_param_len = page_conf->max_param_len;
    params->whitelist = page_conf->whitelist;
}

/* Set connection to cancelled state */
void cancel_connection(struct event_data *ev_data) {
    log_trace("Cancelling connection\n.");
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
