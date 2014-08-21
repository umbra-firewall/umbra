#include <stddef.h>
#include "log.h"
#include "shim_struct.h"

#ifdef TRACE
int num_conn_infos = 0;
#endif

/* Initialize connection_info structure */
struct connection_info *init_conn_info(int infd, int outfd) {
    struct event_data *client_ev_data = NULL, *server_ev_data = NULL;
    struct connection_info *conn_info = NULL;
    log_trace("init_conn_info() (%d total)\n", ++num_conn_infos);

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
    conn_info->page_match = NULL;

    return conn_info;

fail:
#ifdef TRACE
    num_conn_infos--;
#endif
    free(client_ev_data);
    free(server_ev_data);
    free(conn_info);
    return NULL;
}

/* Initialize event data structure */
struct event_data *init_event_data(event_t type, int listen_fd, int send_fd,
        enum http_parser_type parser_type, struct connection_info *conn_info) {

    log_trace("Initializing new event_data\n");
    struct event_data *ev_data = calloc(1, sizeof(struct event_data));

    if (ev_data == NULL) {
        return NULL;
    }

    ev_data->type = type;
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

    bytearray_clear(ev->url);
    bytearray_clear(ev->body);
    bytearray_clear(ev->headers_cache);

#if ENABLE_SESSION_TRACKING
    ev->cookie_header_value_ref = NULL;
    ev->content_length_header_value_ref = NULL;

    struct_array_clear(ev->cookie_name_array, true);
    struct_array_clear(ev->cookie_value_array, true);
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
