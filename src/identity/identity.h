#ifndef GYROJET_IDENTITY_H
#define GYROJET_IDENTITY_H

#include <stddef.h>

#include "../crypto/mlkem.h"
#include "../crypto/x25519.h"
#include "../crypto/xeddsa.h"

#define GYROJET_IDENTITY_ID_SIZE 32
#define GYROJET_PREKEY_ID_SIZE 4

#define GYROJET_IDENTITY_SIGNATURE_SIZE \
    GYROJET_XEDDSA_SIGNATURE_SIZE

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
    /*
     * Long-term X25519 identity key.
     *
     * Também é utilizada pelo XEdDSA para autenticar
     * os prekeys.
     */
    gyrojet_x25519_keypair_t identity_key;

    /*
     * Classical signed prekey.
     */
    gyrojet_x25519_keypair_t signed_prekey;

    unsigned char signed_prekey_signature[
        GYROJET_IDENTITY_SIGNATURE_SIZE
    ];

    unsigned char signed_prekey_id[
        GYROJET_PREKEY_ID_SIZE
    ];

    /*
     * Post-quantum signed prekey.
     */
    gyrojet_mlkem_keypair_t pq_signed_prekey;

    unsigned char pq_signed_prekey_signature[
        GYROJET_IDENTITY_SIGNATURE_SIZE
    ];

    unsigned char pq_signed_prekey_id[
        GYROJET_PREKEY_ID_SIZE
    ];

} gyrojet_identity_t;

/*
 * Gera uma identidade completa.
 *
 * A função gera:
 *
 * - identidade X25519
 * - signed prekey X25519
 * - assinatura XEdDSA do signed prekey
 * - ID do signed prekey
 * - ML-KEM-768 signed prekey
 * - assinatura XEdDSA do ML-KEM signed prekey
 * - ID do PQ signed prekey
 *
 * Retorna:
 *   0  sucesso
 *  -1  erro
 */
int gyrojet_identity_generate(
    gyrojet_identity_t *identity
);

/*
 * Limpa toda a identidade da memória.
 */
void gyrojet_identity_clear(
    gyrojet_identity_t *identity
);

#endif
