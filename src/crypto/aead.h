#ifndef GYROJET_AEAD_H
#define GYROJET_AEAD_H

#include <stddef.h>

#define GYROJET_AEAD_KEY_SIZE   32
#define GYROJET_AEAD_NONCE_SIZE 12
#define GYROJET_AEAD_TAG_SIZE   16

int gyrojet_aead_encrypt(
    const unsigned char key[GYROJET_AEAD_KEY_SIZE],
    const unsigned char nonce[GYROJET_AEAD_NONCE_SIZE],
    const unsigned char *plaintext,
    size_t plaintext_size,
    const unsigned char *associated_data,
    size_t associated_data_size,
    unsigned char *ciphertext,
    unsigned char tag[GYROJET_AEAD_TAG_SIZE]
);

int gyrojet_aead_decrypt(
    const unsigned char key[GYROJET_AEAD_KEY_SIZE],
    const unsigned char nonce[GYROJET_AEAD_NONCE_SIZE],
    const unsigned char *ciphertext,
    size_t ciphertext_size,
    const unsigned char *associated_data,
    size_t associated_data_size,
    const unsigned char tag[GYROJET_AEAD_TAG_SIZE],
    unsigned char *plaintext
);

#endif
