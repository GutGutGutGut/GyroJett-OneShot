#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>

int crypto_init(void);

int crypto_encrypt_file(
    const char *input,
    const char *output,
    const char *recipient
);

int crypto_decrypt_file(
    const char *input,
    const char *output
);

int crypto_sign_file(
    const char *input,
    const char *output
);

int crypto_verify_file(
    const char *input
);

void crypto_cleanup(void);

#endif
