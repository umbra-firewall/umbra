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

#ifndef STRUCT_ARRAY
#define STRUCT_ARRAY

#include <stdbool.h>
#include "bytearray.h"

#define DATATYPE bytearray_t *
#define DEFAULT_ARRAY_LEN 1

typedef struct {
    DATATYPE *data;
    size_t len;
    size_t _alloc_len;
} struct_array_t;

typedef bool (*is_found_t)(DATATYPE);

struct_array_t *struct_array_new();
void struct_array_free(struct_array_t *sa, bool free_members);
int struct_array_add(struct_array_t *sa, DATATYPE item);
int struct_array_clear(struct_array_t *sa, bool free_members);
void struct_array_foreach(struct_array_t *sa, void (*func)(DATATYPE));
int struct_array_remove_element(struct_array_t *sa, int index,
        bool free_element);
int struct_array_find_element_idx(struct_array_t *sa, DATATYPE item);
int struct_array_find_element_idx_lambda(struct_array_t *sa, is_found_t is_found);

#endif
