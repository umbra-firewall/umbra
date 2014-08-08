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

struct_array_t *struct_array_new();
void struct_array_free(struct_array_t *sa, bool free_members);
int struct_array_add(struct_array_t *sa, DATATYPE item);
int struct_array_clear(struct_array_t *sa, bool free_members);
void struct_array_foreach(struct_array_t *sa, void (*func)(DATATYPE));

#endif
