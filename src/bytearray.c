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

void bytearray_free(bytearray_t *ba) {
    if (ba == NULL) {
        fprintf(stderr, "Tried to free null bytearray\n");
        return;
    }

    free(ba->data);
    free(ba);
}

int bytearray_append(bytearray_t *ba, const char *data, size_t len) {
    char *new_data;

    if (ba == NULL) {
        fprintf(stderr, "Tried to append null bytearray\n");
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

static int bytearray_truncate(bytearray_t *ba, size_t trunc_amt, int from_back) {
    if (ba == NULL) {
        fprintf(stderr, "Tried to truncate null bytearray\n");
        return -1;
    }
    if (trunc_amt > ba->len) {
        fprintf(stderr, "Tried to truncate bytearray by more than size\n");
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
        fprintf(stderr, "Tried to truncate null bytearray\n");
        return -1;
    }

    ba->len = 0;
    return 0;
}
