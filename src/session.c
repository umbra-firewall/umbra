#include <ctype.h>
#include "session.h"
#include "log.h"

#if ENABLE_SESSION_TRACKING
struct session current_sessions[MAX_NUM_SESSIONS];

time_t current_time, next_session_expiration_time;
#endif

/* Session tracking functions */
#if ENABLE_SESSION_TRACKING

/* Find session associated with cookie */
#if ENABLE_SESSION_TRACKING
void find_session_from_cookie(struct event_data *ev_data) {
    /* Cookie should be NUL terminated from check_header_pair(),
     * so C string functions can be used. */

    if (ev_data->cookie_header_value_ref == NULL) {;
        log_trace("No Cookie header found; so no SESSION_ID\n");
        return;
    }

    char *sess_id = extract_sessid_parse_cookie(
            ev_data->cookie_header_value_ref->data,
            ev_data->cookie_header_value_ref->len, ev_data);
    ev_data->found_shim_session_cookie = (sess_id != NULL);

    if (!ev_data->found_shim_session_cookie) {
        log_trace("SESSION_ID not found in HTTP request\n");
        return;
    }

    size_t sess_id_len = strlen(sess_id);
    if (sess_id_len != SHIM_SESSID_LEN) {
        log_warn("Found SESSION_ID with length %zd instead of expected %d\n",
                sess_id_len, SHIM_SESSID_LEN);
        cancel_connection(ev_data);
    }

    ev_data->conn_info->session = search_session(sess_id);

    /* Renew expiration if session exists */
    if (ev_data->conn_info->session) {
        renew_session(ev_data->conn_info->session);
    }

#ifdef DEBUG
    if (ev_data->conn_info->session) {
        log_trace("Found existing session \"%s\"\n",
                ev_data->conn_info->session->session_id);
    } else {
        log_trace("Could not find existing existing session\n");
    }
#endif
}
#endif

/* Returns value of session id given a NUL terminated string with the Cookie
 * header value. Also populates the struct_array of cookies. */
char *extract_sessid_parse_cookie(char *cookie_header_value,
        size_t cookie_header_len, struct event_data *ev_data) {
    char *ret = NULL;

    bytearray_t *cookie = bytearray_new();
    if (cookie == NULL) {
        goto error;
    }

    if (update_bytearray(cookie, cookie_header_value, cookie_header_len + 1,
            ev_data) < 0) {
        goto error;
    }

    char *tok = strtok(cookie_header_value, ";");
    log_dbg("Cookie pieces:\n");

    /* Examine each query parameter */
    while (tok  != NULL) {
        bytearray_t *ba = bytearray_new_copy(tok, strlen(tok));
        if (ba == NULL) {
            goto error;
        }

        tok = strstr(tok, SHIM_SESSID_NAME "=");
        if (tok) {
            tok += SHIM_SESSID_NAME_STRLEN + 1;
            if (*tok == '"') {
                tok++;
            }
            ret = tok;
            bytearray_free(ba);
        } else {
            /* Only add to array if not SHIM_SESSID */
            int rc = add_cookie_name_value(ev_data, ba);
            bytearray_free(ba);
            if (rc < 0) {
                goto error;
            }
        }
        tok = strtok(NULL, ";");
    }

    bytearray_free(cookie);
    return ret;

error:
    bytearray_free(cookie);
    cancel_connection(ev_data);
    return NULL;
}

/* Adds cookie name/value string to to cookie name/value arrays */
int add_cookie_name_value(struct event_data *ev_data, bytearray_t *piece) {
    char *name = NULL, *value = NULL;
    size_t name_len = 0, value_len = 0;
    bytearray_t *na = NULL, *va = NULL;

    if ((na = bytearray_new()) == NULL) {
        goto error;
    }
    if ((va = bytearray_new()) == NULL) {
        goto error;
    }

    if (bytearray_nul_terminate(piece) < 0) {
        goto error;
    }

    char *eq = strchr(piece->data, '=');
    char *term;
    if (eq == NULL) {
        term = piece->data + piece->len;
    } else {
        term = eq;
    }

    /* Find cookie name (first non-whitespace character) */
    name = piece->data;
    while (name != term) {
        if (!isspace(*name)) {
            break;
        }
        name++;
    }
    if (name == term) {
        log_warn("Could not find cookie name\n");
        goto error;
    }
    name_len = term - name;

    if (bytearray_append(na, name, name_len) < 0) {
        goto error;
    }

    /* Find cookie value */
    if (eq != NULL) {
        value = eq + 1;
        bool found_quote = (*value == '"');
        if (found_quote) {
            /* Value has quotes */
            value++;
            if (value >= piece->data + piece->len) {
                log_warn("Cookie piece ended too soon\n");
                goto error;
            }
            char *second_quote = strchr(value, '"');
            if (second_quote == NULL) {
                log_warn("Cookie piece had only one quote; must have 0 or 2\n");
                goto error;
            }
            value_len = second_quote - value;
        } else {
            /* Value does not have quotes */
            if (*value == '\0') {
                value_len = 0;
            } else {
                char *last_chr = piece->data + piece->len - 1;
                while (last_chr != value) {
                    if (!isspace(*last_chr)) {
                        break;
                    }
                    last_chr--;
                }
                value_len = last_chr - value + 1;
            }
        }

        if (bytearray_append(va, value, value_len) < 0) {
            goto error;
        }
    }


    if (struct_array_add(ev_data->cookie_name_array, na) < 0) {
        goto error;
    }
    na = NULL;

    if (struct_array_add(ev_data->cookie_value_array, va) < 0) {
        goto error;
    }
    va = NULL;

    log_dbg("  %.*s=%.*s\n", (int) name_len, name,
            (int) value_len, value);

    return 0;

error:
    bytearray_free(na);
    bytearray_free(va);
    cancel_connection(ev_data);
    return -1;
}

/* Returns session structure associated with connection. If one does not exists,
 * then a new one is created. NULL is returned if the maximum number of sessions
 * exist already. */
struct session *get_conn_session(struct connection_info *conn_info) {
    if (conn_info->session == NULL) {
        conn_info->session = new_session();
    }
    return conn_info->session;
}

/* Create a new session and returns the session structure. Returns NULL on
 * error. */
struct session *new_session() {
    log_trace("Creating new session\n");

    struct session *sess = NULL;
    struct session *oldest_sess = NULL;
    int i;

    /* Find first free entry */
    for (i = 0; i < MAX_NUM_SESSIONS; i++) {
        if (is_session_entry_clear(&current_sessions[i])) {
            sess = &current_sessions[i];
            break;
        } else if (oldest_sess == NULL
                || oldest_sess->expires_at > current_sessions[i].expires_at) {
            /* Keep track of oldest session, in case the session table is
             * full */
            oldest_sess = &current_sessions[i];
        }
    }

    /* No free entry found */
    if (sess == NULL) {
        if (oldest_sess == NULL) {
            log_warn("Could not find oldests session to evict\n");
            return NULL;
        }
        log_trace("Evicting oldest session %s\n", oldest_sess->session_id);
        clear_session(oldest_sess);
        sess = oldest_sess;
    }

    sess->expires_at = next_session_expiration_time;
    char rand_bytes[SHIM_SESSID_RAND_BYTES];
    if (fill_rand_bytes(rand_bytes, SHIM_SESSID_RAND_BYTES) < 0) {
        goto error;
    }

    for (i = 0; i < SHIM_SESSID_RAND_BYTES; i++) {
        sprintf(sess->session_id + 2 * i, "%02hhX", rand_bytes[i]);
    }

    return sess;

error:
    memset(sess, 0, sizeof(struct session));
    return NULL;
}

/* Clear session (clears entry in array) */
void clear_session(struct session *sess) {
    memset(sess, 0, sizeof(struct session));
}

/* Returns whether session entry is ununsed */
bool is_session_entry_clear(struct session *sess) {
    return sess->session_id[0] == 0;
}

/* Sets expiration time to next session expiration time */
void renew_session(struct session *sess) {
    sess->expires_at = next_session_expiration_time;
}

/* Tries to find session with given sess_id. Returns NULL if none is found. */
struct session *search_session(char *sess_id) {
    int i;
    for (i = 0; i < MAX_NUM_SESSIONS; i++) {
        if (strcmp(sess_id, current_sessions[i].session_id) == 0) {
            return &current_sessions[i];
        }
    }

    return NULL;
}

/* Returns whether a session is expired */
bool is_session_expired(struct session *s) {
    return current_time >= s->expires_at;
}

/* Clears all entries that have expired */
void expire_sessions() {
    struct session *sess;
    int i;

    for (i = 0; i < MAX_NUM_SESSIONS; i++) {
        sess = &current_sessions[i];
        if (!is_session_entry_clear(sess) && is_session_expired(sess)) {
            log_trace("Expiring session \"%s\"\n", sess->session_id);
            clear_session(sess);
        }
    }
}

int get_num_active_sessions() {
    int num_sessions = 0, i;

    for (i = 0; i < MAX_NUM_SESSIONS; i++) {
        if (!is_session_entry_clear(&current_sessions[i])) {
            num_sessions++;
        }
    }
    return num_sessions;
}

/* Writes Set-Cookie header to buf. Returns the length of the cookie header
 * on success, -1 otherwise. */
int populate_set_cookie_header_value(char *buf, size_t buf_len,
        struct event_data *ev_data) {
    struct session *sess = get_conn_session(ev_data->conn_info);
    if (sess == NULL) {
        log_error("Could not allocate new session\n");
        cancel_connection(ev_data);
        return -1;
    }
    char *token = sess->session_id;
    log_dbg("Sending SESSION_ID: %s\n", token);

    int output_len = snprintf(buf, buf_len, SET_COOKIE_HEADER_VALUE_FORMAT,
            token);

    return output_len;
}

/* Add session Set-Cookie header. Returns 0 on success, -1 otherwise. */
int add_set_cookie_header(struct event_data *ev_data) {
    bytearray_t *header_value = NULL;
    bytearray_t *header_field = NULL;

    char set_cookie_header_value[ESTIMATED_SET_COOKIE_HEADER_VALUE_LEN + 10];

    int set_cookie_header_value_len = populate_set_cookie_header_value(
            set_cookie_header_value, sizeof(set_cookie_header_value), ev_data);
    if (set_cookie_header_value_len < 0) {
        goto error;
    }

    /* Create header value */
    header_value = bytearray_new();
    if (header_value == NULL) {
        goto error;
    }

    if (update_bytearray(header_value, set_cookie_header_value,
            set_cookie_header_value_len, ev_data) < 0) {
        goto error;
    }

    /* Create header field */
    header_field = bytearray_new();
    if (header_field == NULL) {
        goto error;
    }

    if (update_bytearray(header_field, SET_COOKIE_HEADER_FIELD,
            SET_COOKIE_HEADER_FIELD_STRLEN, ev_data) < 0) {
        goto error;
    }

    /* Add Set-Cookie field and value */
    if (struct_array_add(ev_data->all_header_fields, header_field) < 0) {
        goto error;
    }
    header_field = NULL;
    if (struct_array_add(ev_data->all_header_values, header_value) < 0) {
        goto error;
    }
    header_value = NULL;

    return 0;

error:
    if (header_value) {
        bytearray_free(header_value);
    }
    cancel_connection(ev_data);
    return -1;
}

/* Updates stored Content-Length. Returns -1 on failure */
int update_original_content_length(struct event_data *ev_data) {
    if (!ev_data->content_length_specified) {
        return -1;
    }

    if (sscanf(ev_data->content_length_header_value_ref->data, "%lld",
            &ev_data->content_original_length) != 1) {
        log_error("Could not read Content-Length value: %.*s\n",
                (int) ev_data->content_length_header_value_ref->len,
                ev_data->content_length_header_value_ref->data);
        return -1;
    }

    return 0;
}

/* If Content-Length header specified, then returns the Content-Length an
 * a long long. Otherwise, returns -1. */
long long get_original_content_length(struct event_data *ev_data) {
    return ev_data->content_original_length;
}

/* Modify Content-Length header for changes in body length.
 * Returns 0 on success, -1 otherwise. */
int set_new_content_length(struct event_data *ev_data) {
    if (!ev_data->content_length_specified) {
        log_dbg("Not changing Content-Length header because it was not sent\n");
        return 0;
    }

    size_t additional_length = 0;

    /* Account for JS snippet length that is to be sent. */
    if (ev_data->type == SERVER_LISTENER
            && ev_data->conn_info->page_match->has_csrf_form) {
        log_dbg("  Accounting for JS snippet len %zd\n",
                INSERT_HIDDEN_TOKEN_JS_STRLEN);
        additional_length += INSERT_HIDDEN_TOKEN_JS_STRLEN;
    }

    if (ev_data->type == CLIENT_LISTENER
            && ev_data->parser.method == HTTP_POST) {
        // @Todo(Travis) Account for modifying POST parameters
        additional_length += 0;
    }


    if (additional_length == 0) {
        log_trace("Not changing Content-Length that was found\n");
    } else {
        log_trace("Replacing Content-Length: original=%s\n",
                ev_data->content_length_header_value_ref->data);
        /* Read original value */
        long long original_len = get_original_content_length(ev_data);
        if (original_len < 0) {
            goto error;
        }

        long long new_len = original_len + additional_length;

        /* Write new value to string */
        char new_len_buf[ev_data->content_length_header_value_ref->len + 10];
        int new_len_buf_len = snprintf(new_len_buf, sizeof(new_len_buf),
                "%lld", new_len);
        if (new_len_buf_len < 0) {
            log_error("Could not write new calculated Content-Length "
                    "to buffer\n");
            goto error;
        }

        /* Write new value to bytearray */
        if (bytearray_clear(ev_data->content_length_header_value_ref) < 0) {
            goto error;
        }
        if (bytearray_append(ev_data->content_length_header_value_ref,
                new_len_buf, new_len_buf_len) < 0) {
            goto error;
        }

        /* Other functions expect headers to be NUL terminated */
        if (bytearray_nul_terminate(ev_data->content_length_header_value_ref)
                < 0) {
            goto error;
        }

        log_trace("  Replacing Content-Length: new=%s\n",
                ev_data->content_length_header_value_ref->data);
    }

    return 0;

error:
    cancel_connection(ev_data);
    return -1;
}

/* Removes SHIM_SESSID part of cookie */
int remove_shim_sessid_cookie(struct event_data *ev_data) {
    int i;

    bytearray_t *c = ev_data->cookie_header_value_ref;

    if (ev_data->type != CLIENT_LISTENER || c == NULL) {
        return 0;
    }

    log_trace("Removing shim session ID from cookie header value\n");

    if (ev_data->cookie_name_array->len != ev_data->cookie_value_array->len) {
        log_error("Number of cookie names != values\n");
        goto error;
    }

    if (ev_data->cookie_name_array->len <= 0) {
        log_dbg("Removing Cookie header; only has SHIM_SESSID\n");

        int cookie_idx = struct_array_find_element_idx(
                ev_data->all_header_values, c);
        if (cookie_idx < 0) {
            log_error("Could not find cookie_value in array\n");
            goto error;
        }

        if (struct_array_remove_element(ev_data->all_header_fields, cookie_idx,
                true) < 0) {
            log_error("Failed to remove Cookie header\n");
            goto error;
        }
        if (struct_array_remove_element(ev_data->all_header_values,
                                cookie_idx, true) < 0) {
            log_error("Failed to remove Cookie header\n");
            goto error;
        }
    } else {
        /* Build new cookie */

        if (bytearray_clear(c) < 0) {
            goto error;
        }

        /* Add first cookie */
        if (add_cookie_piece(c, 0, ev_data) < 0) {
            goto error;
        }

        /* Add rest of cookies */
        for (i = 1; i < ev_data->cookie_name_array->len; i++) {
            /* Add color delimeter */
            if (bytearray_append(c, "; ", 2) < 0) {
                goto error;
            }

            if (add_cookie_piece(c, i, ev_data) < 0) {
                goto error;
            }
        }

        /* Other functions expect headers to be NUL terminated */
        if (bytearray_nul_terminate(c) < 0) {
            goto error;
        }

        log_dbg("New cookie: \"%s\"\n", c->data);
    }

    return 0;

error:
    cancel_connection(ev_data);
    return -1;
}

/* Add ith cookie in cookie name/value arrays to bytearray.
 * Returns 0 on success, -1 otherwise.
 */
int add_cookie_piece(bytearray_t *c, int i, struct event_data *ev_data) {
    if (c == NULL) {
        return -1;
    }

    if (bytearray_append_ba(c, ev_data->cookie_name_array->data[i]) < 0) {
        return -1;
    }

    /* Only add cookie value and equals sign if value is non-empty */
    if (ev_data->cookie_value_array->data[i]->len > 0) {
        if (bytearray_append(c, "=", 1) < 0) {
            return -1;
        }
        if (bytearray_append_ba(c, ev_data->cookie_value_array->data[i]) < 0) {
            return -1;
        }
    }

    return 0;
}

#endif /* ENABLE_SESSION_TRACKING */
