#include "http_callbacks.h"
#include "shim.h"
#include "config.h"
#include "log.h"

int on_message_begin_cb(http_parser *p) {
    log_trace("***MESSAGE BEGIN***\n");
    struct event_data *ev_data = (struct event_data *) p->data;
    ev_data->msg_begun = true;
    return 0;
}

int on_headers_complete_cb(http_parser *p) {
    struct event_data *ev_data = (struct event_data *) p->data;
    ev_data->headers_complete = true;

#if ENABLE_HEADERS_TRACKING
    /* Check last header pair */
    if (ev_data->header_field->len != 0) {
        check_header_pair(ev_data);

        /* We are done with tracking headers */
        bytearray_clear(ev_data->header_field);
        bytearray_clear(ev_data->header_value);
    }
#endif

    log_trace("***HEADERS COMPLETE***\n");

    if (ev_data->type == CLIENT_LISTENER) {
        do_client_header_complete_checks(ev_data);
    }

    return 0;
}

int on_message_complete_cb(http_parser *p) {
    log_trace("***MESSAGE COMPLETE***\n");
    struct event_data *ev_data = (struct event_data *) p->data;
    ev_data->msg_complete = true;

#if ENABLE_PARAM_CHECKS
    /* Check POST parameters, use http_parser macro */
    if (ev_data->type == CLIENT_LISTENER && p->method == HTTP_POST) {
        check_buffer_params(ev_data->body, false, ev_data);
    }
#endif

#if ENABLE_CSRF_PROTECTION
    struct page_conf *page_match = ev_data->conn_info->page_match;
    if (ev_data->type == CLIENT_LISTENER
            && page_match->receives_csrf_form_action
            && !ev_data->found_csrf_correct_token) {
        bool post_allowed = !ENABLE_REQUEST_TYPE_CHECK
                || (page_match->request_types & HTTP_REQ_POST);
        bool get_allowed = !ENABLE_REQUEST_TYPE_CHECK
                || (page_match->request_types & HTTP_REQ_GET);
        bool is_self_ref = page_match->has_csrf_form
                && page_match->receives_csrf_form_action;
        bool ignore_self_ref = is_self_ref && post_allowed && get_allowed
                && p->method == HTTP_GET;
        if (ignore_self_ref) {
            log_trace("Skipping CSRF check because self-referencing form\n");
        } else {
            log_warn("Page configured to receive CSRF form action, but no CSRF "
                    "token parameter found\n");
            cancel_connection(ev_data);
            return -1;
        }
    }
#endif

    return 0;
}

int on_url_cb(http_parser *p, const char *at, size_t length) {
    struct event_data *ev_data = (struct event_data *) p->data;

    log_trace("Method: %s\n", http_method_str(p->method));

    if (update_bytearray(ev_data->url, at, length, ev_data) < 0) {
        return -1;
    }
    log_trace("Url: \"%.*s\"\n", (int) ev_data->url->len, ev_data->url->data);

    return 0;
}

int on_status_cb(http_parser *p, const char *at, size_t length) {
    log_trace("Status: %.*s\n", (int)length, at);
    return 0;
}

#if ENABLE_HEADER_FIELD_CHECK
int on_header_field_cb(http_parser *p, const char *at, size_t length) {
    //log_trace("Header field: %.*s\n", (int)length, at);
    struct event_data *ev_data = (struct event_data *) p->data;

#if ENABLE_HEADER_FIELD_LEN_CHECK
    if (ev_data->type == CLIENT_LISTENER && length > MAX_HEADER_FIELD_LEN) {
        log_info("Blocked request because header field length %zd; "
                "max is %ld\n",
                length, (long ) MAX_HEADER_FIELD_LEN);
        cancel_connection(ev_data);
        return -1;
    }
#endif

#if ENABLE_HEADERS_TRACKING
    update_http_header_pair(ev_data, true, at, length);
#endif

    return 0;
}
#endif


#if ENABLE_HEADER_VALUE_CHECK
int on_header_value_cb(http_parser *p, const char *at, size_t length) {
    //log_trace("Header value: %.*s\n", (int)length, at);
    struct event_data *ev_data = (struct event_data *) p->data;

#if ENABLE_HEADER_VALUE_LEN_CHECK
    if (ev_data->type == CLIENT_LISTENER && length > MAX_HEADER_VALUE_LEN) {
        log_info("Blocked request because header value length %zd; "
                "max is %ld\n",
                length, (long ) MAX_HEADER_VALUE_LEN);
        cancel_connection(ev_data);
        return -1;
    }
#endif

#if ENABLE_HEADERS_TRACKING
    update_http_header_pair(ev_data, false, at, length);
#endif

    return 0;
}
#endif

int on_body_cb(http_parser *p, const char *at, size_t length) {
#if ENABLE_PARAM_CHECKS
    if (p->method == HTTP_POST) { /* Use http_parser macro */
        struct event_data *ev_data = (struct event_data *) p->data;
        if (update_bytearray(ev_data->body, at, length, ev_data) < 0) {
            return -1;
        }
        log_trace("POST Body: \"%.*s\"\n", (int) ev_data->body->len, ev_data->body->data);
    }
#endif
    return 0;
}
