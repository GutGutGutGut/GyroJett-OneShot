#ifndef GYROJET_IDENTITY_H
#define GYROJET_IDENTITY_H

#include <stddef.h>

#include "../crypto/mlkem.h"
#include "../crypto/x25519.h"

#define GYROJET_IDENTITY_ID_SIZE 32

#define GYROJET_PREKEY_ID_SIZE 4

#define GYROJET_SIGNATURE_SIZE 64

typedef struct {
    unsigned char public_key[
        GYROJET_X25519_PUBLIC_KEY_SIZE
    ];

    unsigned char private_key[
        GYROJET_X25519_PRIVATE_KEY_SIZE
    ];
} gyrojet_x25519_keypair_t;

typedef struct {
    unsigned char public_key[
        GYROJET_MLKEM_PUBLIC_KEY_SIZE
    ];

    unsigned char private_key[
        GYROJET_MLKEM_PRIVATE_KEY_SIZE
    ];
} gyrojet_mlkem_keypair_t;

typedef struct {
    gyrojet_x25519_keypair_t identity_key;

    gyrojet_x25519_keypair_t signed_prekey;

    unsigned char signed_prekey_signature[
        GYROJET_SIGNATURE_SIZE
    ];

    unsigned char signed_prekey_id[
        GYROJET_PREKEY_ID_SIZE
    ];

    gyrojet_mlkem_keypair_t pq_signed_prekey;

    unsigned char pq_signed_prekey_signature[
        GYROJET_SIGNATURE_SIZE
    ];

    unsigned char pq_signed_prekey_id[
        GYROJET_PREKEY_ID_SIZE
    ];
} gyrojet_identity_t;

int gyrojet_identity_generate(
    gyrojet_identity_t *identity
);

void gyrojet_identity_clear(
    gyrojet_identity_t *identity
);

#endif
