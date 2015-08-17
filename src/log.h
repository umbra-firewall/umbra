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

#ifndef SHIM_LOG_H
#define SHIM_LOG_H

#include <stdio.h>

/* Logging macros */

#ifdef DEBUG
#define log_trace(args...) fprintf(stdout, "[trace] " args); fflush(stdout)
#define log_dbg(args...) fprintf(stdout, "[ dbg ] " args); fflush(stdout)
#define TRACE
#else
#define log_trace(msg, args...) ;
#define log_dbg(msg, args...) ;
#endif

#define log_warn(args...) fprintf(stdout, "[warn ] " args); fflush(stdout)
#define log_info(args...) fprintf(stdout, "[info ] " args); fflush(stdout)
#define log_error(args...) fprintf(stdout, "[error] " args); fflush(stdout)
#define log_ssl_error(args...) fprintf(stdout, "[error] " args); \
    ERR_print_errors_fp(stdout); fflush(stdout)

#endif
