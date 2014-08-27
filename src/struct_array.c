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
