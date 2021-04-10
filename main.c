#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha1.h"

#define CHUNK 500

char *read_stdin()
{
    char *input = NULL;
    char buffer[CHUNK];
    size_t input_len = 0, temp_len;
    do
    {
        fgets(buffer, CHUNK, stdin);

        // Remove trailing newline.
        buffer[strcspn(buffer, "\n")] = 0;

        temp_len = strlen(buffer);
        input = realloc(input, input_len + temp_len + 1);
        strcpy(input + input_len, buffer);
        input_len += temp_len;
    }
    while (temp_len == CHUNK - 1 && buffer[CHUNK - 2] != '\n');
    return input;
}

int main()
{
    char *input = read_stdin();

    byte message_digest[SHA1_HASH_SIZE];
    if (SHA1_get_digest(message_digest, input) == ERROR)
    {
        // Feel free to commit better error handling.
        printf("Something went wrong.");
        free(input);
        return 1;
    }

    free(input);

    // Print the hash.
    for (int i = 0; i < SHA1_HASH_SIZE; ++i) printf("%02x", message_digest[i]);

    return 0;
}
