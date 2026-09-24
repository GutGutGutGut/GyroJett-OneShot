#define _POSIX_C_SOURCE 200809L

#include "secret.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>

int gyrojet_secret_derive_key(
    const char *secret,
    unsigned char key[GYROJET_SESSION_KEY_SIZE]
)
{
    static const unsigned char info[] =
        "GyroJett-OneShot2 session key v1";

    if (secret == NULL || key == NULL)
        return -1;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(
        EVP_PKEY_HKDF,
        NULL
    );

    if (ctx == NULL)
        return -1;

    int result = -1;

    if (EVP_PKEY_derive_init(ctx) != 1)
        goto cleanup;

    if (EVP_PKEY_CTX_set_hkdf_md(
            ctx,
            EVP_sha256()
        ) != 1) {
        goto cleanup;
    }

    size_t secret_size = strlen(secret);

      if (secret_size > INT_MAX)
       goto cleanup;

        if (EVP_PKEY_CTX_set1_hkdf_key(
         ctx,
          (const unsigned char *)secret,
           (int)secret_size
             ) != 1) {
        goto cleanup;
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(
            ctx,
            info,
            sizeof(info) - 1
        ) != 1) {
        goto cleanup;
    }

    size_t key_size = GYROJET_SESSION_KEY_SIZE;

    if (EVP_PKEY_derive(
            ctx,
            key,
            &key_size
        ) != 1) {
        goto cleanup;
    }

    if (key_size != GYROJET_SESSION_KEY_SIZE)
        goto cleanup;

    result = 0;

cleanup:
    EVP_PKEY_CTX_free(ctx);

    return result;
}

int gyrojet_secret_generate(
    char *output,
    size_t output_size
)
{
    if (output == NULL)
        return -1;

    if (output_size < GYROJET_SECRET_BUFFER_SIZE)
        return -1;

    unsigned char random_data[GYROJET_SECRET_ENTROPY_BYTES];

    int fd = open(
        "/dev/urandom",
        O_RDONLY
    );

    if (fd < 0)
        return -1;

    size_t received = 0;

    while (received < sizeof(random_data)) {
        ssize_t result = read(
            fd,
            random_data + received,
            sizeof(random_data) - received
        );

        if (result < 0) {
            if (errno == EINTR)
                continue;

            close(fd);
            return -1;
        }

        if (result == 0) {
            close(fd);
            return -1;
        }

        received += (size_t)result;
    }

    close(fd);

    size_t output_position = 0;

    for (;;) {
        unsigned int remainder = 0;
        int non_zero = 0;

        for (size_t i = 0; i < sizeof(random_data); ++i) {
            unsigned int value =
                (remainder << 8) | random_data[i];

            random_data[i] =
                (unsigned char)(value / GYROJET_SECRET_ALPHABET_SIZE);

            remainder =
                value % GYROJET_SECRET_ALPHABET_SIZE;

            if (random_data[i] != 0)
                non_zero = 1;
        }

        if (output_position >= output_size - 1)
            return -1;

        output[output_position++] =
            GYROJET_SECRET_ALPHABET[remainder];

        if (!non_zero)
            break;
    }

    output[output_position] = '\0';

    for (size_t i = 0; i < output_position / 2; ++i) {
        char temporary = output[i];

        output[i] =
            output[output_position - 1 - i];

        output[output_position - 1 - i] =
            temporary;
    }

    return 0;
}
