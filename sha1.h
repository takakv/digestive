#include "types.h"

#ifndef SHA1_H
#define SHA1_H

#define SHA1_HASH_SIZE 20

// Hold context information during hashing operations.
typedef struct SHAstate {
    uint digest[5];
    byte buffer[64];
    int block_count;
} SHA1_CTX;

int SHA1_get_digest(byte *message_digest, const char *input);

#endif
