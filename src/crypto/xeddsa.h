#ifndef GYROJET_XEDDSA_H
#define GYROJET_XEDDSA_H

#include <stddef.h>

#define GYROJET_XEDDSA_PRIVATE_KEY_SIZE 32
#define GYROJET_XEDDSA_PUBLIC_KEY_SIZE 32
#define GYROJET_XEDDSA_SIGNATURE_SIZE 64
#define GYROJET_XEDDSA_RANDOM_SIZE 64

int gyrojet_xeddsa_init(void);

int gyrojet_xeddsa_sign(
    const unsigned char private_key[
        GYROJET_XEDDSA_PRIVATE_KEY_SIZE
    ],
    const unsigned char *message,
    size_t message_size,
    const unsigned char random[
        GYROJET_XEDDSA_RANDOM_SIZE
    ],
    unsigned char signature[
        GYROJET_XEDDSA_SIGNATURE_SIZE
    ]
);

int gyrojet_xeddsa_verify(
    const unsigned char public_key[
        GYROJET_XEDDSA_PUBLIC_KEY_SIZE
    ],
    const unsigned char *message,
    size_t message_size,
    const unsigned char signature[
        GYROJET_XEDDSA_SIGNATURE_SIZE
    ]
);

int gyrojet_xeddsa_x25519_public_key(
    const unsigned char private_key[
        GYROJET_XEDDSA_PRIVATE_KEY_SIZE
    ],
    unsigned char public_key[
        GYROJET_XEDDSA_PUBLIC_KEY_SIZE
    ]
);

#endif
