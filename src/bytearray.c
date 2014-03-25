#include "bytearray.h"

bytearray_t* new_bytearray() {
    bytearray_t *ba = calloc(1, sizeof(bytearray_t));
    if (ba  == NULL) {
        perror("calloc");
        abort();
    }

    ba->data = calloc(1, DEFAULT_BYTEARRAY_ALLOC);
    if (ba->data == NULL) {
        free(ba);
        perror("calloc");
        abort();
    }
    ba->len = 0;
    ba->_alloc_len = DEFAULT_BYTEARRAY_ALLOC;

    return ba;
}

void bytearray_free(bytearray_t *ba) {
    if (ba == NULL) {
        fprintf(stderr, "Tried to free null bytearray\n");
        abort();
    }

    free(ba->data);
    free(ba);
}

void bytearray_append(bytearray_t *ba, uint8_t *data, size_t len) {
    if (ba == NULL) {
        fprintf(stderr, "Tried to append null bytearray\n");
        abort();
    }

    size_t new_len = ba->len + len;
    if (new_len > ba->_alloc_len) {
        /* Realloc more space */
        ba->_alloc_len = new_len;
        ba->data = realloc(ba->data, ba->_alloc_len);
        if (ba->data == NULL) {
            perror("realloc");
            abort();
        }
    }

    memcpy(ba->data + ba->len, data, len);
}

static void bytearray_truncate(bytearray_t *ba, size_t trunc_amt, int from_back) {
    if (ba == NULL) {
        fprintf(stderr, "Tried to truncate null bytearray\n");
        abort();
    }
    if (trunc_amt > ba->len) {
        fprintf(stderr, "Tried to truncate bytearray by more than size\n");
        abort();
    }

    size_t new_len = ba->len - trunc_amt;
    if (!from_back) {
        memmove(ba->data, ba->data + trunc_amt, new_len);
    }
    ba->len = new_len;
}

void bytearray_truncate_front(bytearray_t *ba, size_t trunc_amt) {
    bytearray_truncate(ba, trunc_amt, 0);
}

void bytearray_truncate_back(bytearray_t *ba, size_t trunc_amt) {
    bytearray_truncate(ba, trunc_amt, 1);
}
