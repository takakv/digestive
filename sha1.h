#include "types.h"

#ifndef SHA1_H
#define SHA1_H

#define SHA1_HASH_SIZE 20

// Hold context information during hashing operations.
typedef struct SHAstate {
    uint digest[5];
    byte buffer[64];
    int buffer_len;
} SHA1_CTX;

void get_sha1(const char* input);

#endif
