#ifndef GYROJET_MLKEM_H
#define GYROJET_MLKEM_H

#include <stddef.h>

#define GYROJET_MLKEM_PUBLIC_KEY_SIZE 1184
#define GYROJET_MLKEM_PRIVATE_KEY_SIZE 2400
#define GYROJET_MLKEM_CIPHERTEXT_SIZE 1088
#define GYROJET_MLKEM_SHARED_SECRET_SIZE 32

int gyrojet_mlkem_generate_keypair(
unsigned char public_key[GYROJET_MLKEM_PUBLIC_KEY_SIZE],
unsigned char private_key[GYROJET_MLKEM_PRIVATE_KEY_SIZE]
);

int gyrojet_mlkem_encapsulate(
const unsigned char public_key[GYROJET_MLKEM_PUBLIC_KEY_SIZE],
unsigned char ciphertext[GYROJET_MLKEM_CIPHERTEXT_SIZE],
unsigned char shared_secret[GYROJET_MLKEM_SHARED_SECRET_SIZE]
);

int gyrojet_mlkem_decapsulate(
const unsigned char private_key[GYROJET_MLKEM_PRIVATE_KEY_SIZE],
const unsigned char ciphertext[GYROJET_MLKEM_CIPHERTEXT_SIZE],
unsigned char shared_secret[GYROJET_MLKEM_SHARED_SECRET_SIZE]
);

#endif

