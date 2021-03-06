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

#include "log.h"
#include "bytearray.h"

bytearray_t* bytearray_new() {
    bytearray_t *ba = calloc(1, sizeof(bytearray_t));
    if (ba == NULL) {
        perror("calloc");
        return NULL;
    }

    ba->data = calloc(1, DEFAULT_BYTEARRAY_ALLOC);
    if (ba->data == NULL) {
        free(ba);
        perror("calloc");
        return NULL;
    }

    ba->len = 0;
    ba->_alloc_len = DEFAULT_BYTEARRAY_ALLOC;

    return ba;
}

bytearray_t* bytearray_new_copy(char *data, size_t len) {
    bytearray_t *ba = bytearray_new();
    if (ba == NULL) {
        return NULL;
    }

    if (bytearray_append(ba, data, len) < 0) {
        bytearray_free(ba);
        return NULL;
    }

    return ba;
}

void bytearray_free(bytearray_t *ba) {
    if (ba == NULL) {
        return;
    }

    free(ba->data);
    free(ba);
}

int bytearray_append(bytearray_t *ba, const char *data, size_t len) {
    char *new_data;

    if (ba == NULL) {
        log_warn("Tried to append NULL bytearray\n");
        return -1;
    }

    size_t new_len = ba->len + len;
    if (new_len > ba->_alloc_len) {
        /* Realloc more space */
        ba->_alloc_len = new_len;
        new_data = realloc(ba->data, ba->_alloc_len);
        if (new_data == NULL) {
            perror("realloc");
            return -1;
        }
        ba->data = new_data;
    }
    memcpy(ba->data + ba->len, data, len);
    ba->len = new_len;

    return 0;
}

int bytearray_append_ba(bytearray_t *ba, bytearray_t *to_append) {
    if (to_append == NULL) {
        log_warn("Tried to append NULL bytearray\n");
        return -1;
    }

    return bytearray_append(ba, to_append->data, to_append->len);
}

int bytearray_nul_terminate(bytearray_t *ba) {
    int rc = 0;
    if (ba == NULL) {
        log_error("Tried to NUL terminate NULL bytearray\n");
        return -1;
    }

    if ((rc = bytearray_append(ba, "\0", 1)) < 0) {
        return rc;
    }

    ba->len--;

    return rc;
}

static int bytearray_truncate(bytearray_t *ba, size_t trunc_amt, int from_back) {
    if (ba == NULL) {
        log_error("Tried to truncate NULL bytearray\n");
        return -1;
    }
    if (trunc_amt > ba->len) {
        log_error("Tried to truncate bytearray by more than size\n");
        return -1;
    }

    size_t new_len = ba->len - trunc_amt;
    if (!from_back) {
        memmove(ba->data, ba->data + trunc_amt, new_len);
    }
    ba->len = new_len;
    return 0;
}

int bytearray_truncate_front(bytearray_t *ba, size_t trunc_amt) {
    return bytearray_truncate(ba, trunc_amt, 0);
}

int bytearray_truncate_back(bytearray_t *ba, size_t trunc_amt) {
    return bytearray_truncate(ba, trunc_amt, 1);
}

int bytearray_clear(bytearray_t *ba) {
    if (ba == NULL) {
        log_error("Tried to clear NULL bytearray\n");
        return -1;
    }

    ba->len = 0;
    return 0;
}
