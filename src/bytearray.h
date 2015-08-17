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

#ifndef BYTEARRAY_H
#define BYTEARRAY_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>

#define DEFAULT_BYTEARRAY_ALLOC 2048

typedef struct {
    char *data;
    size_t len;
    size_t _alloc_len;
} bytearray_t;

bytearray_t* bytearray_new();
bytearray_t* bytearray_new_copy(char *data, size_t len);
void bytearray_free(bytearray_t *ba);
int bytearray_append(bytearray_t *ba, const char *data, size_t len);
int bytearray_append_ba(bytearray_t *ba, bytearray_t *to_append);
int bytearray_nul_terminate(bytearray_t *ba);
int bytearray_truncate_front(bytearray_t *ba, size_t trunc_amt);
int bytearray_truncate_back(bytearray_t *ba, size_t trunc_amt);
int bytearray_clear(bytearray_t *ba);

#endif
