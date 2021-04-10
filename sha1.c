#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <endian.h>
#include <assert.h>
#include "sha1.h"

typedef u_int32_t uint;
typedef u_int64_t ulong;
typedef u_int8_t byte;

const int hash_bits = 160;
const int hash_bytes = hash_bits / 8;

// Initial hash values in Big Endian.
const uint h0 = 0x67452301UL;
const uint h1 = 0xefcdab89UL;
const uint h2 = 0x98badcfeUL;
const uint h3 = 0x10325476UL;
const uint h4 = 0xc3d2e1f0UL;

// Context.
typedef struct SHAstate {
    uint state[5];
    byte block[64];
} SHA_CTX;

void SHA_Init(SHA_CTX *ctx)
{
    ctx->state[0] = h0;
    ctx->state[1] = h1;
    ctx->state[2] = h2;
    ctx->state[3] = h3;
    ctx->state[4] = h4;
}

void get_bytes(byte *byte_array, ulong value)
{
    const int count = sizeof byte_array;
    for (int i = 0; i < count; ++i)
        byte_array[i] = (value >> ((count * 8) - (i * 8))) & 0xff;
}

// Rotate left.
uint rotl(uint value, uint bits)
{
    assert (bits < 32);
    return (value << bits) | (value >> (-bits & 31));
}

// Combine 4 bytes into a 32bit word.
uint wordify(byte b1, byte b2, byte b3, byte b4)
{
    uint combined = b1 << 24 | b2 << 16 | b3 << 8 | b4;
    return combined;
}

const char *get_sha1(const char *input)
{
    // Create hash context.
    SHA_CTX ctx;
    SHA_Init(&ctx);

    /* DEBUG
#if __BYTE_ORDER == __LITTLE_ENDIAN
    printf("Little endian machine\n");
#endif
     */

    ulong length_bytes = strlen(input);
    ulong length_bits = length_bytes * 8;

    // Use calloc to avoid having to manually set zero bits.
    byte *message = (byte *) calloc(64, sizeof(byte));
    strcpy((char *) message, input);

    // Append bit "1" to message.
    message[length_bytes] = 0x80;

    // Get length bytes
    byte bytes[8];
    get_bytes(bytes, length_bits);

    // Append message length to message.
    for (int i = 7; i >= 0; --i) message[64 - 1 - i] = bytes[i];

    // Break message into words.
    // Need to combine 4 bytes into one to represent 32bit word.
    uint words[80];
    for (int i = 0; i < 16; ++i)
    {
        words[i] = wordify(message[0 + (i * 4)],
                           message[1 + (i * 4)],
                           message[2 + (i * 4)],
                           message[3 + (i * 4)]);
    }

    for (int i = 16; i < 80; ++i)
    {
        words[i] = rotl(words[i - 6] ^ words[i - 28] ^ words[i - 32], 2);
    }

    uint a = h0;
    uint b = h1;
    uint c = h2;
    uint d = h3;
    uint e = h4;
}

