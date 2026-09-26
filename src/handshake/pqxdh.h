#ifndef GYROJET_PQXDH_H
#define GYROJET_PQXDH_H

#include <stddef.h>
#include <stdint.h>

#include "../identity/identity.h"

#define GYROJET_PQXDH_SHARED_SECRET_SIZE 32
#define GYROJET_PQXDH_ASSOCIATED_DATA_SIZE 64

typedef struct {
    unsigned char identity_public_key[
        GYROJET_X25519_PUBLIC_KEY_SIZE
    ];

    unsigned char ephemeral_public_key[
        GYROJET_X25519_PUBLIC_KEY_SIZE
    ];

    unsigned char pq_ciphertext[
        GYROJET_MLKEM_CIPHERTEXT_SIZE
    ];

    unsigned char signed_prekey_id[
        GYROJET_PREKEY_ID_SIZE
    ];

    unsigned char pq_signed_prekey_id[
        GYROJET_PREKEY_ID_SIZE
    ];
} gyrojet_pqxdh_message_t;

typedef struct {
    unsigned char shared_secret[
        GYROJET_PQXDH_SHARED_SECRET_SIZE
    ];

    unsigned char associated_data[
        GYROJET_PQXDH_ASSOCIATED_DATA_SIZE
    ];

    size_t associated_data_size;
} gyrojet_pqxdh_result_t;

int gyrojet_pqxdh_init(void);

int gyrojet_pqxdh_initiate(
    const gyrojet_identity_t *local_identity,
    const gyrojet_identity_t *remote_identity,
    gyrojet_pqxdh_message_t *message,
    gyrojet_pqxdh_result_t *result
);

int gyrojet_pqxdh_accept(
    const gyrojet_identity_t *local_identity,
    const gyrojet_pqxdh_message_t *message,
    gyrojet_pqxdh_result_t *result
);

void gyrojet_pqxdh_message_clear(
    gyrojet_pqxdh_message_t *message
);

void gyrojet_pqxdh_result_clear(
    gyrojet_pqxdh_result_t *result
);

#endif
