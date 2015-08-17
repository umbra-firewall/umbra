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
#include "log.h"
#include "struct_array.h"


/* Returns newly allocated struct_array or NULL on error */
struct_array_t *struct_array_new() {
    struct_array_t *sa = calloc(1, sizeof(struct_array_t));
    if (sa == NULL) {
        perror("calloc");
        return NULL;
    }

    sa->data = calloc(DEFAULT_ARRAY_LEN, sizeof(DATATYPE));
    if (sa->data == NULL) {
        perror("calloc");
        free(sa);
        return NULL;
    }
    sa->len = 0;
    sa->_alloc_len = DEFAULT_ARRAY_LEN;

    return sa;
}

/* Frees each member of struct_array then frees struct_array */
void struct_array_free(struct_array_t *sa, bool free_members) {
    if (sa == NULL) {
        return;
    }

    if (free_members) {
        struct_array_foreach(sa, bytearray_free);
    }

    memset(sa->data, 0, sa->_alloc_len * sizeof(DATATYPE));
    free(sa->data);

    memset(sa, 0, sizeof(struct_array_t));
    free(sa);
}

/* Appends item to struct_array */
int struct_array_add(struct_array_t *sa, DATATYPE item) {
    DATATYPE *new_data;

    if (sa == NULL) {
        log_dbg("Tried to append NULL array\n");
        return -1;
    }

    size_t new_len = sa->len + 1;
    if (new_len > sa->_alloc_len) {
        /* Realloc more space */
        sa->_alloc_len = new_len;
        new_data = realloc(sa->data, sa->_alloc_len * sizeof(DATATYPE));
        if (new_data == NULL) {
            perror("realloc");
            return -1;
        }
        sa->data = new_data;
    }
    sa->data[sa->len] = item;
    sa->len = new_len;

    return 0;
}

/* For each element in struct_array, runs function */
void struct_array_foreach(struct_array_t *sa, void (*func)(DATATYPE)) {
    int i;

    if (sa == NULL) {
        return;
    }

    for (i = 0; i < sa->len; i++) {
        func(sa->data[i]);
    }
}

/* Removes all elements from struct_array, optionally freeing each member */
int struct_array_clear(struct_array_t *sa, bool free_members) {
    if (sa == NULL) {
        log_dbg("Tried to clear NULL array\n");
        return -1;
    }

    if (free_members) {
        struct_array_foreach(sa, bytearray_free);
    }

    memset(sa->data, 0, sa->_alloc_len * sizeof(DATATYPE));
    sa->len = 0;

    return 0;
}

/* Removes element at index from struct_array */
int struct_array_remove_element(struct_array_t *sa, int index,
        bool free_element) {
    if (sa == NULL) {
        log_dbg("Tried to clear NULL array\n");
        return -1;
    }

    if (index < 0 || index >= sa->len) {
        log_error("Index %d is out of bounds; length=%zd\n", index, sa->len);
    }

    if (free_element) {
        bytearray_free(sa->data[index]);
    }

    if (sa->len > 1) {
        void *to = sa->data + index;
        void *from = sa->data + index + 1;
        size_t len = (sa->len - index - 1) * sizeof(DATATYPE);
        memmove(to, from, len);
    }

    sa->len--;

    return 0;
}

/* Returns index of first element such that item == elemeent or -1 if
 * none is found
 */
int struct_array_find_element_idx(struct_array_t *sa, DATATYPE item) {
    int i;

    if (sa == NULL) {
        log_dbg("Tried to clear NULL array\n");
        return -1;
    }

    for (i = 0; i < sa->len; i++) {
        if (sa->data[i] == item) {
            return i;
        }
    }

    return -1;
}

/* Returns index of first element such that is_found returns true or -1 if
 * none is found
 */
int struct_array_find_element_idx_lambda(struct_array_t *sa, is_found_t is_found) {
    int i;

    if (sa == NULL) {
        log_dbg("Tried to clear NULL array\n");
        return -1;
    }

    for (i = 0; i < sa->len; i++) {
        if (is_found(sa->data[i])) {
            return i;
        }
    }

    return -1;
}
