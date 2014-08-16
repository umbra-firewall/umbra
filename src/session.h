#ifndef SESSION_H
#define SESSION_H

#include "shim.h"
#include "http_util.h"
#include "config.h"

/* Session macros */
#define SHIM_SESSID_NAME "SHIM_SESSID"
#define SHIM_SESSID_NAME_STRLEN (sizeof(SHIM_SESSID_NAME) - 1)
#define SHIM_SESSID_RAND_BYTES 10
#define SHIM_SESSID_LEN (2 * SHIM_SESSID_RAND_BYTES)

#define SET_COOKIE_HEADER_FIELD "Set-Cookie"
#define SET_COOKIE_HEADER_FIELD_STRLEN (sizeof(SET_COOKIE_HEADER_FIELD) - 1)
#define SET_COOKIE_HEADER_VALUE_FORMAT \
        SHIM_SESSID_NAME "=%s; " \
        "max-age=" XSTR(SESSION_LIFE_SECONDS) "; " \
        "path=/"

#define ESTIMATED_SET_COOKIE_HEADER_VALUE_LEN \
    (sizeof(SET_COOKIE_HEADER_VALUE_FORMAT) + SHIM_SESSID_LEN)

#define MAX_HTTP_RESPONSE_HEADERS_SIZE 8096

#define COOKIE_HEADER "Cookie"
#define COOKIE_HEADER_STRLEN (sizeof(COOKIE_HEADER) - 1)

#define CONTENT_LENGTH_HEADER "Content-Length"
#define CONTENT_LENGTH_HEADER_STRLEN \
    (sizeof(CONTENT_LENGTH_HEADER) - 1)

#define TRANSFER_ENCODING_HEADER "Transfer-Encoding"
#define TRANSFER_ENCODING_HEADER_STRLEN \
    (sizeof(TRANSFER_ENCODING_HEADER) - 1)

#define TE_HEADER "TE"
#define TE_HEADER_STRLEN (sizeof(TE_HEADER) - 1)

#define CONTENT_ENCODING_HEADER "Content-Encoding"
#define CONTENT_ENCODING_HEADER_STRLEN \
    (sizeof(CONTENT_ENCODING_HEADER) - 1)



#define CSRF_TOKEN_NAME "_umbra_csrf_token"
#define CSRF_TOKEN_NAME_LEN (sizeof(CSRF_TOKEN_NAME) - 1)

#define INSERT_HIDDEN_TOKEN_JS_FORMAT \
    "\n<script>" \
    "var input = document.createElement(\"input\");" \
    "input.setAttribute(\"type\", \"hidden\");" \
    "input.setAttribute(\"name\", \"" CSRF_TOKEN_NAME "\");" \
    "input.setAttribute(\"value\", \"%s\");" \
    "var forms = document.getElementsByTagName('form');" \
    "for (var i = 0, length = forms.length; i < length; i ++) {" \
    "  forms[i].appendChild(input);" \
    "}" \
    "</script>\n"
#define INSERT_HIDDEN_TOKEN_JS_STRLEN \
    (sizeof(INSERT_HIDDEN_TOKEN_JS_FORMAT) + SHIM_SESSID_LEN - 3)


struct session {
    char session_id[SHIM_SESSID_LEN + 1];
    time_t expires_at;
};

/* Global variables */
extern struct session current_sessions[MAX_NUM_SESSIONS];
extern time_t current_time;
extern time_t next_session_expiration_time;


/* Session functions */

struct event_data;
struct connection_info;

void find_session_from_cookie(struct event_data *ev_data);
char *extract_sessid_parse_cookie(char *cookie_header_value,
        size_t cookie_header_len, struct event_data *ev_data);
int add_cookie_name_value(struct event_data *ev_data, bytearray_t *cp);
struct session *get_conn_session(struct connection_info *conn_info);
struct session *new_session();
bool is_session_entry_clear(struct session *sess);
void renew_session(struct session *sess);
void clear_session(struct session *sess);
struct session *search_session(char *sess_id);
void expire_sessions();
bool is_session_expired(struct session *s);
int get_num_active_sessions();
int add_set_cookie_header(struct event_data *ev_data);
int set_new_content_length(struct event_data *ev_data);
int remove_shim_sessid_cookie(struct event_data *ev_data);
int add_cookie_piece(bytearray_t *c, int i, struct event_data *ev_data);

#endif
