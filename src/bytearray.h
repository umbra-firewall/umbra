#ifndef BYTEARRAY_H
#define BYTEARRAY_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>

#define DEFAULT_BYTEARRAY_ALLOC 2048

typedef struct {
    uint8_t *data;
    size_t len;
    size_t _alloc_len;
} bytearray_t;

bytearray_t* new_bytearray();
void bytearray_free(bytearray_t *ba);
int bytearray_append(bytearray_t *ba, uint8_t *data, size_t len);
void bytearray_truncate_front(bytearray_t *ba, size_t trunc_amt);
void bytearray_truncate_back(bytearray_t *ba, size_t trunc_amt);

#endif
