#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include <limits.h>
#include <endian.h>
#include "sha1.h"

// Initial hash values in Big Endian.
const uint h0 = 0x67452301UL;
const uint h1 = 0xefcdab89UL;
const uint h2 = 0x98badcfeUL;
const uint h3 = 0x10325476UL;
const uint h4 = 0xc3d2e1f0UL;

// Create new context.
void SHA_Init(SHA1_CTX *ctx)
{
    ctx->digest[0] = h0;
    ctx->digest[1] = h1;
    ctx->digest[2] = h2;
    ctx->digest[3] = h3;
    ctx->digest[4] = h4;
    ctx->block_count = 0;
}

// Get bytes in Little or Big Endian. This implementation is Little Endian specific!
void get_bytes(byte *byte_array, uint count, ulong value, bool big_endian)
{
    assert(__BYTE_ORDER == __LITTLE_ENDIAN);
    // Shift the values as many bites as needed for each byte.
    // Ex, if we need to get 8 bytes (64 bits), the first byte gets shifted right by 56 bits,
    // the second by 48 bits, ...
    // If we want to get the bytes in Big Endian format, we just reverse the byte order.
    for (int i = 0; i < count; ++i)
        byte_array[big_endian ? count - 1 - i : i] = (value >> (count * 8 - (i + 1) * 8));
}

// Rotate word bits left by a shift count.
// The shift count must be smaller than the word size!
uint rotl(uint word, uint bits)
{
    assert (bits < 32);
    return (word << bits) | (word >> (-bits & 31));
}

// Pad the message so that the total message length is a multiple of 512 bits.
int SHA1_pre_process(byte **output, const char *input, SHA1_CTX *ctx)
{
    ulong length_bytes = strlen(input);
    // This limit is simply for my own programmer's convenience to avoid
    // dealing with type boundaries, and not a limitation of SHA1.
    if (length_bytes >= INT_MAX) {
        printf("Input too big!");
        return ERROR;
    }
    ulong length_bits = length_bytes * 8;

    // Calculate the number of 512 bit blocks needed to store the message.
    // 64 bits are reserved for storing the message length.
    // k represents the padding bits count + 1.
    int k;
    for (k = 448 - (int) length_bits; k < 0; k += 512);
    int block_count = ((int) length_bits + k) / 512 + 1;

    // Using calloc avoids me having to manually set zero bits.
    byte *message = (byte *) calloc(64 * block_count, sizeof(byte));
    if (message == NULL) return ERROR;

    strcpy((char *) message, input);

    // Append bit "1" to the message.
    message[length_bytes] = 0x80;

    // Get length bytes
    byte bytes[8];
    get_bytes(bytes, 8, length_bits, true);

    // Append message length to message.
    for (int i = 7; i >= 0; --i) message[64 * block_count - 1 - i] = bytes[i];

    *output = message;
    ctx->block_count = block_count;
    return SUCCESS;
}

void SHA1_process(SHA1_CTX *ctx)
{
    // Divide the buffer into 32 bit words.
    // I store words in 4 bytes wide unsigned integers.
    // 16 words of 4 bytes make up the 512 bits long bitstream.
    uint words[80];
    for (int i = 0; i < 16; ++i)
    {
        // As I store the bits as an array of bytes, that is,
        // each element of the array represents 8 consecutive bits,
        // I need to concatenate 4 bytes in order to represent a 32 bit word.
        words[i] = ctx->buffer[i * 4] << 24;
        words[i] |= ctx->buffer[i * 4 + 1] << 16;
        words[i] |= ctx->buffer[i * 4 + 2] << 8;
        words[i] |= ctx->buffer[i * 4 + 3];
    }

    // Message scheduling.
    for (int i = 16; i < 80; ++i)
        words[i] = rotl(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1);

    // Hash value initialisation.
    uint a = ctx->digest[0];
    uint b = ctx->digest[1];
    uint c = ctx->digest[2];
    uint d = ctx->digest[3];
    uint e = ctx->digest[4];

    uint f, k;

    for (int i = 0; i < 80; ++i)
    {
        if (i < 20)
        {
            f = d ^ (b & (c ^ d));
            k = 0x5a827999UL;
        }
        else if (i < 40)
        {
            f = b ^ c ^ d;
            k = 0x6ed9eba1UL;
        }
        else if (i < 60)
        {
            f = (b & c) | ((b | c) & d);
            k = 0x8f1bbcdcUL;
        }
        else
        {
            f = b ^ c ^ d;
            k = 0xca62c1d6;
        }

        uint temp = rotl(a, 5) + f + e + k + words[i];
        e = d;
        d = c;
        c = rotl(b, 30);
        b = a;
        a = temp;
    }
    ctx->digest[0] += a;
    ctx->digest[1] += b;
    ctx->digest[2] += c;
    ctx->digest[3] += d;
    ctx->digest[4] += e;
}

int SHA1_get_digest(byte *message_digest, const char *input)
{
    // Create hash context.
    SHA1_CTX ctx;
    SHA_Init(&ctx);

    // Pad the message.
    byte *message = NULL;
    if (SHA1_pre_process(&message, input, &ctx) != SUCCESS) return ERROR;

    // Split message into 512 bit blocks and process each of them.
    for (int i = 0; i < ctx.block_count; ++i)
    {
        if (!memcpy(ctx.buffer, message + (i * 64), 64)) return ERROR;
        SHA1_process(&ctx);
    }

    // Assemble the hash.
    for (int i = 0; i < SHA1_HASH_SIZE; ++i)
        message_digest[i] = ctx.digest[i >> 2] >> 8 * (3 - (i & 0x03));

    free(message);
    return SUCCESS;
}

