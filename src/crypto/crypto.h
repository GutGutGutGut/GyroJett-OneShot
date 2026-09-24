#ifndef GYROJET_CRYPTO_H
#define GYROJET_CRYPTO_H

#include <stddef.h>

#define GYROJET_CRYPTO_SHARED_SECRET_SIZE 32

int gyrojet_crypto_init(void);

void gyrojet_crypto_cleanup(void);

int gyrojet_crypto_random(
void *buffer,
size_t size
);

void gyrojet_crypto_secure_zero(
void *buffer,
size_t size
);

#endif

