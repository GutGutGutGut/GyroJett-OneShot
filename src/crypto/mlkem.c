#include "mlkem.h"

#include <openssl/evp.h>

int gyrojet_mlkem_generate_keypair(
unsigned char public_key[GYROJET_MLKEM_PUBLIC_KEY_SIZE],
unsigned char private_key[GYROJET_MLKEM_PRIVATE_KEY_SIZE]
)
{
if (public_key == NULL || private_key == NULL)
return -1;


EVP_PKEY *key = EVP_PKEY_Q_keygen(
    NULL,
    NULL,
    "ML-KEM-768"
);

if (key == NULL)
    return -1;

size_t public_size =
    GYROJET_MLKEM_PUBLIC_KEY_SIZE;

size_t private_size =
    GYROJET_MLKEM_PRIVATE_KEY_SIZE;

int result = 0;

if (EVP_PKEY_get_raw_public_key(
        key,
        public_key,
        &public_size
    ) != 1) {

    result = -1;
    goto cleanup;
}

if (EVP_PKEY_get_raw_private_key(
        key,
        private_key,
        &private_size
    ) != 1) {

    result = -1;
    goto cleanup;
}

if (public_size != GYROJET_MLKEM_PUBLIC_KEY_SIZE ||
    private_size != GYROJET_MLKEM_PRIVATE_KEY_SIZE) {

    result = -1;
}


cleanup:
EVP_PKEY_free(key);


return result;


}

int gyrojet_mlkem_encapsulate(
const unsigned char public_key[GYROJET_MLKEM_PUBLIC_KEY_SIZE],
unsigned char ciphertext[GYROJET_MLKEM_CIPHERTEXT_SIZE],
unsigned char shared_secret[GYROJET_MLKEM_SHARED_SECRET_SIZE]
)
{
if (public_key == NULL ||
ciphertext == NULL ||
shared_secret == NULL) {


    return -1;
}

EVP_PKEY *key = NULL;
EVP_PKEY_CTX *context = NULL;

int result = -1;

key = EVP_PKEY_new_raw_public_key_ex(
    NULL,
    "ML-KEM-768",
    NULL,
    public_key,
    GYROJET_MLKEM_PUBLIC_KEY_SIZE
);

if (key == NULL)
    goto cleanup;

context = EVP_PKEY_CTX_new(
    key,
    NULL
);

if (context == NULL)
    goto cleanup;

if (EVP_PKEY_encapsulate_init(
        context,
        NULL
    ) != 1) {

    goto cleanup;
}

size_t ciphertext_size =
    GYROJET_MLKEM_CIPHERTEXT_SIZE;

size_t secret_size =
    GYROJET_MLKEM_SHARED_SECRET_SIZE;

if (EVP_PKEY_encapsulate(
        context,
        ciphertext,
        &ciphertext_size,
        shared_secret,
        &secret_size
    ) != 1) {

    goto cleanup;
}

if (ciphertext_size !=
        GYROJET_MLKEM_CIPHERTEXT_SIZE ||
    secret_size !=
        GYROJET_MLKEM_SHARED_SECRET_SIZE) {

    goto cleanup;
}

result = 0;


cleanup:
EVP_PKEY_CTX_free(context);
EVP_PKEY_free(key);


return result;


}

int gyrojet_mlkem_decapsulate(
const unsigned char private_key[GYROJET_MLKEM_PRIVATE_KEY_SIZE],
const unsigned char ciphertext[GYROJET_MLKEM_CIPHERTEXT_SIZE],
unsigned char shared_secret[GYROJET_MLKEM_SHARED_SECRET_SIZE]
)
{
if (private_key == NULL ||
ciphertext == NULL ||
shared_secret == NULL) {


    return -1;
}

EVP_PKEY *key = NULL;
EVP_PKEY_CTX *context = NULL;

int result = -1;

key = EVP_PKEY_new_raw_private_key_ex(
    NULL,
    "ML-KEM-768",
    NULL,
    private_key,
    GYROJET_MLKEM_PRIVATE_KEY_SIZE
);

if (key == NULL)
    goto cleanup;

context = EVP_PKEY_CTX_new(
    key,
    NULL
);

if (context == NULL)
    goto cleanup;

if (EVP_PKEY_decapsulate_init(
        context,
        NULL
    ) != 1) {

    goto cleanup;
}

size_t secret_size =
    GYROJET_MLKEM_SHARED_SECRET_SIZE;

if (EVP_PKEY_decapsulate(
        context,
        shared_secret,
        &secret_size,
        ciphertext,
        GYROJET_MLKEM_CIPHERTEXT_SIZE
    ) != 1) {

    goto cleanup;
}

if (secret_size !=
    GYROJET_MLKEM_SHARED_SECRET_SIZE) {

    goto cleanup;
}

result = 0;


cleanup:
EVP_PKEY_CTX_free(context);
EVP_PKEY_free(key);


return result;


}

