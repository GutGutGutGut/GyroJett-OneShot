#include "x25519.h"

#include <openssl/evp.h>

static int
gyrojet_x25519_load_private(
const unsigned char private_key[GYROJET_X25519_PRIVATE_KEY_SIZE],
EVP_PKEY **result
)
{
if (private_key == NULL || result == NULL)
return -1;


*result = EVP_PKEY_new_raw_private_key_ex(
    NULL,
    "X25519",
    NULL,
    private_key,
    GYROJET_X25519_PRIVATE_KEY_SIZE
);

return *result != NULL ? 0 : -1;


}

static int
gyrojet_x25519_load_public(
const unsigned char public_key[GYROJET_X25519_PUBLIC_KEY_SIZE],
EVP_PKEY **result
)
{
if (public_key == NULL || result == NULL)
return -1;


*result = EVP_PKEY_new_raw_public_key_ex(
    NULL,
    "X25519",
    NULL,
    public_key,
    GYROJET_X25519_PUBLIC_KEY_SIZE
);

return *result != NULL ? 0 : -1;


}

int gyrojet_x25519_generate_keypair(
unsigned char public_key[GYROJET_X25519_PUBLIC_KEY_SIZE],
unsigned char private_key[GYROJET_X25519_PRIVATE_KEY_SIZE]
)
{
if (public_key == NULL || private_key == NULL)
return -1;


EVP_PKEY *key = EVP_PKEY_Q_keygen(
    NULL,
    NULL,
    "X25519"
);

if (key == NULL)
    return -1;

size_t public_size = GYROJET_X25519_PUBLIC_KEY_SIZE;
size_t private_size = GYROJET_X25519_PRIVATE_KEY_SIZE;

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

if (public_size != GYROJET_X25519_PUBLIC_KEY_SIZE ||
    private_size != GYROJET_X25519_PRIVATE_KEY_SIZE) {

    result = -1;
}


cleanup:
EVP_PKEY_free(key);


return result;


}

int gyrojet_x25519_shared_secret(
const unsigned char private_key[GYROJET_X25519_PRIVATE_KEY_SIZE],
const unsigned char peer_public_key[GYROJET_X25519_PUBLIC_KEY_SIZE],
unsigned char shared_secret[GYROJET_X25519_SHARED_SECRET_SIZE]
)
{
if (private_key == NULL ||
peer_public_key == NULL ||
shared_secret == NULL) {


    return -1;
}

EVP_PKEY *private_pkey = NULL;
EVP_PKEY *public_pkey = NULL;
EVP_PKEY_CTX *context = NULL;

int result = -1;

if (gyrojet_x25519_load_private(
        private_key,
        &private_pkey
    ) < 0) {

    goto cleanup;
}

if (gyrojet_x25519_load_public(
        peer_public_key,
        &public_pkey
    ) < 0) {

    goto cleanup;
}

context = EVP_PKEY_CTX_new(
    private_pkey,
    NULL
);

if (context == NULL)
    goto cleanup;

if (EVP_PKEY_derive_init(context) != 1)
    goto cleanup;

if (EVP_PKEY_derive_set_peer(
        context,
        public_pkey
    ) != 1) {

    goto cleanup;
}

size_t secret_size =
    GYROJET_X25519_SHARED_SECRET_SIZE;

if (EVP_PKEY_derive(
        context,
        shared_secret,
        &secret_size
    ) != 1) {

    goto cleanup;
}

if (secret_size !=
    GYROJET_X25519_SHARED_SECRET_SIZE) {

    goto cleanup;
}

result = 0;


cleanup:
EVP_PKEY_CTX_free(context);
EVP_PKEY_free(public_pkey);
EVP_PKEY_free(private_pkey);


return result;


}

