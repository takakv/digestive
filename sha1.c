#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <endian.h>
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

void get_bytes(byte *byte_array, ulong value)
{
    const int count = sizeof byte_array;
    for (int i = 0; i < count; ++i)
        byte_array[i] = (value >> ((count * 8) - (i * 8))) & 0xff;
}

const char *get_sha1(const char *input)
{
    /* DEBUG
#if __BYTE_ORDER == __LITTLE_ENDIAN
    printf("Little endian machine\n");
#endif
     */

    ulong length_bytes = strlen(input);
    ulong length_bits = length_bytes * 8;

    // Use calloc to avoid having to manually set zero bits.
    byte *message = (byte *) calloc(512, sizeof(byte));
    strcpy((char *) message, input);

    // Append bit "1" to message.
    message[length_bytes] = 0x80;

    // Get length bytes
    byte bytes[8];
    get_bytes(bytes, length_bits);

    // Append message length to message.
    for (int i = 7; i >= 0; --i) message[64 - 1 - i] = bytes[i];

    /* DEBUG
    for (int i = 0; i < 64; ++i) printf("%x ", message[i]);
    */
}

