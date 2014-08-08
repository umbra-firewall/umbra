#include <stdlib.h>
#include "log.h"
#include "struct_array.h"


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

void struct_array_free(struct_array_t *sa, bool free_members) {
    if (sa == NULL) {
        log_dbg("Tried to free NULL array\n");
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

void struct_array_foreach(struct_array_t *sa, void (*func)(DATATYPE)) {
    int i;

    if (sa == NULL) {
        return;
    }

    for (i = 0; i < sa->len; i++) {
        func(sa->data[i]);
    }
}

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
