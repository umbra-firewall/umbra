/**
 * Copyright 2015 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <stdio.h>
#include "shim.h"
#include "config.h"
#include "config_printer.h"

#define TAB_SIZE 4

#define print_str_macro(macro) printf("%s = \"%s\"\n", (#macro), (macro))
#define print_int_macro(macro) printf("%s = %d\n", (#macro), (macro))
#define print_bool_macro(macro) printf("%s = %s\n", (#macro), (macro) ? "true" : "false")

#define print_str_arr(var) { printf("%s = {\n", #var); \
    int i; \
    for (i = 0; i < sizeof(var) / sizeof(*var); i++) { \
        printf("    \"%s\",\n", var[i]); \
    } \
    printf("}\n"); \
    }

static void print_indent(int depth) {
    int i;
    for (i = 0; i < depth * TAB_SIZE; i++) {
        printf(" ");
    }
}

#define print_http_req_part(REQ) \
        if (r & HTTP_REQ_##REQ) { \
            printf(#REQ "|"); \
        }

static void print_http_req_field(int r) {
    printf("|");
    print_http_req_part(HEAD);
    print_http_req_part(GET);
    print_http_req_part(POST);
    print_http_req_part(PUT);
    print_http_req_part(DELETE);
    print_http_req_part(TRACE);
    print_http_req_part(CONNECT);
}

void print_whitelist(const char *w) {
    int i;
    for (i = 0; i < WHITELIST_PARAM_LEN; i++) {
        printf("%02hhx", w[i]);
        if (i % 4 == 3) {
            printf(" ");
        }
    }
}

static void print_whitelist2(const char *w) {
    int i;
    for (i = 0; i < 256; i++) {
        if (whitelist_char_allowed(w, i)) {
            printf("%02hhx ", i);
        }
    }
}

#define printf_indent(depth, args...) print_indent(depth); printf(args)

#define print_str_field(item) printf_indent(depth + 1, "." #item " = \"%.*s\"\n", \
        WHITELIST_PARAM_LEN, p->item)
#define print_whitelist_field(item) printf_indent(depth + 1, "." #item " = "); \
        print_whitelist(p->item) ; printf("\n")
#define print_whitelist2_field(item) printf_indent(depth + 1, "." #item " = "); \
        print_whitelist2(p->item) ; printf("\n")
#define print_int_field(item) printf_indent(depth + 1, "." #item " = %d\n", \
        p->item)
#define print_http_req_field(item) printf_indent(depth + 1, "." #item " = "); \
        print_http_req_field(p->item); printf("\n")
#define print_bool_field(item) printf_indent(depth + 1, "." #item " = %s\n", \
        p->item ? "TRUE" : "FALSE")

static void print_params(struct params *p, int depth) {
    printf_indent(depth, "\"%s\" {\n", p->name);
    print_whitelist_field(whitelist);
    print_whitelist2_field(whitelist);
    print_int_field(max_param_len);
    printf_indent(depth, "}\n");
}

static void print_page_conf(struct page_conf *p, int depth) {
    int i;

    printf_indent(depth, "\"%s\" {\n", p->name);

    print_http_req_field(request_types);
    print_bool_field(restrict_params);
    print_bool_field(has_csrf_form);
    print_bool_field(receives_csrf_form_action);
    print_bool_field(requires_login);

    print_whitelist_field(whitelist);
    print_whitelist2_field(whitelist);
    print_int_field(max_param_len);

    print_int_field(params_len);
    printf_indent(depth + 1, ".params = {\n");
    for (i = 0; i < p->params_len; i++) {
        print_params(&p->params[i], depth + 2);
    }
    printf_indent(depth + 1, "},\n");

    printf_indent(depth, "},\n\n");
}

void print_configuration() {
    int i;
    init_config_vars();

    printf("** Global Config **\n");
    print_int_macro(MAX_HEADER_FIELD_LEN);
    print_int_macro(MAX_HEADER_VALUE_LEN);
    print_int_macro(MAX_NUM_SESSIONS);
    print_int_macro(SESSION_LIFE_SECONDS);

    printf("\n** Enable Config **\n");
    print_bool_macro(ENABLE_HEADER_FIELD_LEN_CHECK);
    print_bool_macro(ENABLE_HEADER_VALUE_LEN_CHECK);
    print_bool_macro(ENABLE_REQUEST_TYPE_CHECK);
    print_bool_macro(ENABLE_PARAM_CHECKS);
    print_bool_macro(ENABLE_PARAM_LEN_CHECK);
    print_bool_macro(ENABLE_PARAM_WHITELIST_CHECK);
    print_bool_macro(ENABLE_URL_DIRECTORY_TRAVERSAL_CHECK);
    print_bool_macro(ENABLE_CSRF_PROTECTION);
    print_bool_macro(ENABLE_SESSION_TRACKING);
    print_bool_macro(ENABLE_HTTPS);
    print_bool_macro(ENABLE_AUTHENTICATION_CHECK);

    printf("\n** Global Page Defaults **\n");
    print_page_conf(&default_page_conf, 0);

    puts("");

    printf("** Page-specific Config**\n");
    for (i = 0; i < PAGES_CONF_LEN; i++) {
        print_page_conf(&pages_conf[i], 0);
    }
}
