#ifndef GYROJET_SECRET_H
#define GYROJET_SECRET_H

#include <stddef.h>

#define GYROJET_SECRET_ENTROPY_BYTES 64

#define GYROJET_SECRET_ENTROPY_BITS \
    (GYROJET_SECRET_ENTROPY_BYTES * 8)

#define GYROJET_SECRET_ALPHABET \
    "0123456789abcdefghijklmnopqrstuvwxyzBCDEFGHIJKLMNOPQRSTUVWXYZ"

#define GYROJET_SECRET_ALPHABET_SIZE \
    (sizeof(GYROJET_SECRET_ALPHABET) - 1)

#define GYROJET_SECRET_TEXT_SIZE 87

#define GYROJET_SECRET_BUFFER_SIZE \
    (GYROJET_SECRET_TEXT_SIZE + 1)

int gyrojet_secret_generate(
    char *output,
    size_t output_size
);

#endif
