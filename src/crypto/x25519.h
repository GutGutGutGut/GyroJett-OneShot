#ifndef GYROJET_X25519_H
#define GYROJET_X25519_H

#include <stddef.h>

#define GYROJET_X25519_PUBLIC_KEY_SIZE 32
#define GYROJET_X25519_PRIVATE_KEY_SIZE 32
#define GYROJET_X25519_SHARED_SECRET_SIZE 32

int gyrojet_x25519_generate_keypair(
unsigned char public_key[GYROJET_X25519_PUBLIC_KEY_SIZE],
unsigned char private_key[GYROJET_X25519_PRIVATE_KEY_SIZE]
);

int gyrojet_x25519_shared_secret(
const unsigned char private_key[GYROJET_X25519_PRIVATE_KEY_SIZE],
const unsigned char peer_public_key[GYROJET_X25519_PUBLIC_KEY_SIZE],
unsigned char shared_secret[GYROJET_X25519_SHARED_SECRET_SIZE]
);

#endif

