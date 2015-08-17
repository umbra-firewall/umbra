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

#include <stdio.h>
#include <time.h>

static FILE *fp_trace;

void
__attribute__ ((constructor))
trace_begin(void) {
    fp_trace = stdout;
}

void
__attribute__ ((destructor))
trace_end(void) {
    if (fp_trace != NULL) {
        fclose(fp_trace);
    }
}

void __cyg_profile_func_enter(void *func, void *caller) {
    if (fp_trace != NULL) {
        fprintf(fp_trace, "e %p %p %lu\n", func, caller, time(NULL));
        fflush(fp_trace);
    }
}

void __cyg_profile_func_exit(void *func, void *caller) {
    if (fp_trace != NULL) {
        fprintf(fp_trace, "x %p %p %lu\n", func, caller, time(NULL));
        fflush(fp_trace);
    }
}
