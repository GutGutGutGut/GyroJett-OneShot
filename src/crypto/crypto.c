#define _POSIX_C_SOURCE 200809L

#include "crypto.h"

#include <openssl/rand.h>

#include <stddef.h>

int gyrojet_crypto_init(void)
{
return 0;
}

void gyrojet_crypto_cleanup(void)
{
}

int gyrojet_crypto_random(
void *buffer,
size_t size
)
{
if (buffer == NULL && size != 0)
return -1;

if (size == 0)
    return 0;

if (RAND_bytes(
        buffer,
        (int)size
    ) != 1) {

    return -1;
}

return 0;


}

void gyrojet_crypto_secure_zero(
void *buffer,
size_t size
)
{
if (buffer == NULL)
return;


volatile unsigned char *ptr = buffer;

while (size > 0) {
    *ptr = 0;
    ++ptr;
    --size;
}


}
