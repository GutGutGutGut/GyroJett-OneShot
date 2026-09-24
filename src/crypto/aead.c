#include "aead.h"

#include <openssl/evp.h>

#include <limits.h>
#include <stddef.h>

static int gyrojet_aead_size_to_int(
    size_t size,
    int *result
)
{
    if (result == NULL)
        return -1;

    if (size > INT_MAX)
        return -1;

    *result = (int)size;

    return 0;
}

int gyrojet_aead_encrypt(
    const unsigned char key[GYROJET_AEAD_KEY_SIZE],
    const unsigned char nonce[GYROJET_AEAD_NONCE_SIZE],
    const unsigned char *plaintext,
    size_t plaintext_size,
    const unsigned char *associated_data,
    size_t associated_data_size,
    unsigned char *ciphertext,
    unsigned char tag[GYROJET_AEAD_TAG_SIZE]
)
{
    if (key == NULL ||
        nonce == NULL ||
        ciphertext == NULL ||
        tag == NULL) {
        return -1;
    }

    if (plaintext == NULL && plaintext_size != 0)
        return -1;

    if (associated_data == NULL && associated_data_size != 0)
        return -1;

    int plaintext_len;
    int aad_len;

    if (gyrojet_aead_size_to_int(
            plaintext_size,
            &plaintext_len
        ) != 0) {
        return -1;
    }

    if (gyrojet_aead_size_to_int(
            associated_data_size,
            &aad_len
        ) != 0) {
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL)
        return -1;

    int result = -1;
    int written = 0;
    int total = 0;

    if (EVP_EncryptInit_ex(
            ctx,
            EVP_aes_256_gcm(),
            NULL,
            NULL,
            NULL
        ) != 1) {
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_SET_IVLEN,
            GYROJET_AEAD_NONCE_SIZE,
            NULL
        ) != 1) {
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(
            ctx,
            NULL,
            NULL,
            key,
            nonce
        ) != 1) {
        goto cleanup;
    }

    if (aad_len > 0) {
        if (EVP_EncryptUpdate(
                ctx,
                NULL,
                &written,
                associated_data,
                aad_len
            ) != 1) {
            goto cleanup;
        }
    }

    if (plaintext_len > 0) {
        if (EVP_EncryptUpdate(
                ctx,
                ciphertext,
                &written,
                plaintext,
                plaintext_len
            ) != 1) {
            goto cleanup;
        }

        total = written;
    }

    if (EVP_EncryptFinal_ex(
            ctx,
            ciphertext + total,
            &written
        ) != 1) {
        goto cleanup;
    }

    total += written;

    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_GET_TAG,
            GYROJET_AEAD_TAG_SIZE,
            tag
        ) != 1) {
        goto cleanup;
    }

    if ((size_t)total != plaintext_size)
        goto cleanup;

    result = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);

    return result;
}

int gyrojet_aead_decrypt(
    const unsigned char key[GYROJET_AEAD_KEY_SIZE],
    const unsigned char nonce[GYROJET_AEAD_NONCE_SIZE],
    const unsigned char *ciphertext,
    size_t ciphertext_size,
    const unsigned char *associated_data,
    size_t associated_data_size,
    const unsigned char tag[GYROJET_AEAD_TAG_SIZE],
    unsigned char *plaintext
)
{
    if (key == NULL ||
        nonce == NULL ||
        tag == NULL ||
        plaintext == NULL) {
        return -1;
    }

    if (ciphertext == NULL && ciphertext_size != 0)
        return -1;

    if (associated_data == NULL && associated_data_size != 0)
        return -1;

    int ciphertext_len;
    int aad_len;

    if (gyrojet_aead_size_to_int(
            ciphertext_size,
            &ciphertext_len
        ) != 0) {
        return -1;
    }

    if (gyrojet_aead_size_to_int(
            associated_data_size,
            &aad_len
        ) != 0) {
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL)
        return -1;

    int result = -1;
    int written = 0;
    int total = 0;

    if (EVP_DecryptInit_ex(
            ctx,
            EVP_aes_256_gcm(),
            NULL,
            NULL,
            NULL
        ) != 1) {
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_SET_IVLEN,
            GYROJET_AEAD_NONCE_SIZE,
            NULL
        ) != 1) {
        goto cleanup;
    }

    if (EVP_DecryptInit_ex(
            ctx,
            NULL,
            NULL,
            key,
            nonce
        ) != 1) {
        goto cleanup;
    }

    if (aad_len > 0) {
        if (EVP_DecryptUpdate(
                ctx,
                NULL,
                &written,
                associated_data,
                aad_len
            ) != 1) {
            goto cleanup;
        }
    }

    if (ciphertext_len > 0) {
        if (EVP_DecryptUpdate(
                ctx,
                plaintext,
                &written,
                ciphertext,
                ciphertext_len
            ) != 1) {
            goto cleanup;
        }

        total = written;
    }

    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_SET_TAG,
            GYROJET_AEAD_TAG_SIZE,
            (void *)tag
        ) != 1) {
        goto cleanup;
    }

    if (EVP_DecryptFinal_ex(
            ctx,
            plaintext + total,
            &written
        ) != 1) {
        goto cleanup;
    }

    total += written;

    if ((size_t)total != ciphertext_size)
        goto cleanup;

    result = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);

    return result;
}
