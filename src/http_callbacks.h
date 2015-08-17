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

#ifndef HTTP_CALLBACKS_H
#define HTTP_CALLBACKS_H

#include <stddef.h>
#include "http_parser.h"

/* HTTP parser callbacks */
int on_message_begin_cb(http_parser *p);
int on_headers_complete_cb(http_parser *p);
int on_message_complete_cb(http_parser *p);
int on_url_cb(http_parser *p, const char *at, size_t length);
int on_status_cb(http_parser *p, const char *at, size_t length);
int on_header_field_cb(http_parser *p, const char *at, size_t length);
int on_header_value_cb(http_parser *p, const char *at, size_t length);
int on_body_cb(http_parser *p, const char *at, size_t length);

#endif
