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

    char *sess_id = extract_sessid_cookie_value(ev_data->cookie->data);
    if (sess_id == NULL) {
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
 * header value. */
char *extract_sessid_cookie_value(char *cookie_header_value) {
    char *tok = strtok(cookie_header_value, ";");

    /* Examine each query parameter */
    while (tok  != NULL) {
        tok = strstr(tok, SHIM_SESSID_NAME "=");
        if (tok) {
            tok += SHIM_SESSID_NAME_STRLEN + 1;
            if (*tok == '"') {
                tok++;
            }
            return tok;
        }
        tok = strtok(NULL, ";");
    }

    return NULL;
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
int populate_set_cookie_header(char *buf, size_t buf_len,
        struct event_data *ev_data) {
    struct session *sess = get_conn_session(ev_data->conn_info);
    if (sess == NULL) {
        log_error("Could not allocate new session\n");
        cancel_connection(ev_data);
        return -1;
    }
    char *token = sess->session_id;
    log_dbg("Sending SESSION_ID: %s\n", token);

    int output_len = snprintf(buf, buf_len, SET_COOKIE_HEADER_FORMAT, token);

    return output_len;
}

#endif /* ENABLE_SESSION_TRACKING */
