#ifndef SHIM_LOG_H
#define SHIM_LOG_H

#include <stdio.h>

/* Logging macros */

#ifdef DEBUG
#define log_trace(args...) fprintf(stdout, "[trace] " args); fflush(stdout)
#define log_dbg(args...) fprintf(stdout, "[ dbg ] " args); fflush(stdout)
#else
#define log_trace(msg, args...) ;
#define log_dbg(msg, args...) ;
#endif

#define log_warn(args...) fprintf(stdout, "[warn ] " args); fflush(stdout)
#define log_info(args...) fprintf(stdout, "[info ] " args); fflush(stdout)
#define log_error(args...) fprintf(stdout, "[error] " args); fflush(stdout)

#endif
