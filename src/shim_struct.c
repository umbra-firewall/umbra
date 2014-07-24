#include <stddef.h>
#include "log.h"
#include "shim_struct.h"


/* Initialize connection_info structure */
struct connection_info *init_conn_info(int infd, int outfd) {
    struct event_data *client_ev_data = NULL, *server_ev_data = NULL;
    struct connection_info *conn_info = NULL;
#ifdef TRACE
    log_trace("init_conn_info() (%d total)\n", ++num_conn_infos);
#endif

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

    struct event_data *ev_data = calloc(1, sizeof(struct event_data));

    if (ev_data != NULL) {
        ev_data->type = type;
        ev_data->listen_fd = listen_fd;
        ev_data->send_fd = send_fd;
        ev_data->conn_info = conn_info;

        if ((ev_data->url = bytearray_new()) == NULL) {
            log_warn("Allocating new bytearray failed\n");
            goto error;
        }

        if ((ev_data->body = bytearray_new()) == NULL) {
            log_warn("Allocating new bytearray failed\n");
            goto error;
        }

#if ENABLE_SESSION_TRACKING
        if ((ev_data->cookie = bytearray_new()) == NULL) {
            log_warn("Allocating new bytearray failed\n");
            goto error;
        }
#endif

#if ENABLE_HEADERS_TRACKING
        if ((ev_data->header_field = bytearray_new()) == NULL) {
            log_warn("Allocating new bytearray failed\n");
            goto error;
        }

        if ((ev_data->header_value = bytearray_new()) == NULL) {
            log_warn("Allocating new bytearray failed\n");
            goto error;
        }

        ev_data->header_value_loc = NULL;
#endif

        http_parser_init(&ev_data->parser, parser_type);
        ev_data->parser.data = ev_data;
    }

    return ev_data;

error:
    bytearray_free(ev_data->url);
    bytearray_free(ev_data->body);

#if ENABLE_SESSION_TRACKING
    bytearray_free(ev_data->cookie);
#endif

#if ENABLE_HEADERS_TRACKING
    bytearray_free(ev_data->header_field);
    bytearray_free(ev_data->header_value);
#endif

    free(ev_data);
    return NULL;
}

/* Free memory associated with event data */
void free_event_data(struct event_data *ev) {
    //log_trace("Freeing event data %p\n", ev);
    if (ev != NULL) {
        bytearray_free(ev->url);
        bytearray_free(ev->body);

#if ENABLE_SESSION_TRACKING
        bytearray_free(ev->cookie);
#endif

#if ENABLE_HEADERS_TRACKING
        bytearray_free(ev->header_field);
        bytearray_free(ev->header_value);
#endif

        free(ev);
    }
}

/* Free memory and close sockets associated with connection structure */
void free_connection_info(struct connection_info *ci) {
    if (ci != NULL) {
#ifdef TRACE
        log_trace("Freeing conn info %p (%d total)\n", ci, --num_conn_infos);
#endif
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
#ifdef TRACE
        log_trace("Freeing NULL conn info (%d total)\n", num_conn_infos);
#endif
    }
}

/* Copy default param fields in page_conf struct to params struct */
void copy_default_params(struct page_conf *page_conf, struct params *params) {
    params->max_param_len = page_conf->max_param_len;
    params->whitelist = page_conf->whitelist;
}
