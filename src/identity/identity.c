#include "identity.h"

#include "../crypto/crypto.h"
#include "../crypto/mlkem.h"
#include "../crypto/x25519.h"
#include "../crypto/xeddsa.h"

#include <stddef.h>

static int gyrojet_identity_random_id(
    unsigned char id[GYROJET_PREKEY_ID_SIZE]
)
{
    if (id == NULL)
        return -1;

    return gyrojet_crypto_random(
        id,
        GYROJET_PREKEY_ID_SIZE
    );
}

static int gyrojet_identity_sign_prekey(
    const unsigned char identity_private_key[
        GYROJET_X25519_PRIVATE_KEY_SIZE
    ],
    const unsigned char *prekey_public_key,
    size_t prekey_public_key_size,
    unsigned char signature[
        GYROJET_IDENTITY_SIGNATURE_SIZE
    ]
)
{
    unsigned char random[
        GYROJET_XEDDSA_RANDOM_SIZE
    ];

    if (identity_private_key == NULL ||
        prekey_public_key == NULL ||
        signature == NULL) {
        return -1;
    }

    if (gyrojet_crypto_random(
            random,
            sizeof(random)
        ) != 0) {
        return -1;
    }

    const int result = gyrojet_xeddsa_sign(
        identity_private_key,
        prekey_public_key,
        prekey_public_key_size,
        random,
        signature
    );

    /*
     * A aleatoriedade usada pela assinatura não deve
     * permanecer na memória.
     */
    gyrojet_crypto_secure_zero(
        random,
        sizeof(random)
    );

    return result;
}

int gyrojet_identity_generate(
    gyrojet_identity_t *identity
)
{
    if (identity == NULL)
        return -1;

    /*
     * Começamos com uma estrutura completamente limpa.
     */
    gyrojet_identity_clear(identity);

    /*
     * 1. Gera a identidade X25519.
     */
    if (gyrojet_x25519_generate_keypair(
            identity->identity_key.public_key,
            identity->identity_key.private_key
        ) != 0) {
        gyrojet_identity_clear(identity);
        return -1;
    }

    /*
     * 2. Gera o signed prekey X25519.
     */
    if (gyrojet_x25519_generate_keypair(
            identity->signed_prekey.public_key,
            identity->signed_prekey.private_key
        ) != 0) {
        gyrojet_identity_clear(identity);
        return -1;
    }

    /*
     * 3. ID do signed prekey.
     */
    if (gyrojet_identity_random_id(
            identity->signed_prekey_id
        ) != 0) {
        gyrojet_identity_clear(identity);
        return -1;
    }

    /*
     * 4. A identidade assina a chave pública do
     * signed prekey usando XEdDSA.
     *
     * O protocolo PQXDH assina o EncodeEC(SPK).
     */
    if (gyrojet_identity_sign_prekey(
            identity->identity_key.private_key,
            identity->signed_prekey.public_key,
            GYROJET_X25519_PUBLIC_KEY_SIZE,
            identity->signed_prekey_signature
        ) != 0) {
        gyrojet_identity_clear(identity);
        return -1;
    }

    /*
     * 5. Gera o signed prekey pós-quântico ML-KEM-768.
     */
    if (gyrojet_mlkem_generate_keypair(
            identity->pq_signed_prekey.public_key,
            identity->pq_signed_prekey.private_key
        ) != 0) {
        gyrojet_identity_clear(identity);
        return -1;
    }

    /*
     * 6. ID do PQ signed prekey.
     */
    if (gyrojet_identity_random_id(
            identity->pq_signed_prekey_id
        ) != 0) {
        gyrojet_identity_clear(identity);
        return -1;
    }

    /*
     * 7. A identidade também assina a chave pública
     * ML-KEM do PQ signed prekey.
     *
     * O PQXDH especifica uma assinatura da identidade
     * sobre EncodeKEM(PQSPK).
     */
    if (gyrojet_identity_sign_prekey(
            identity->identity_key.private_key,
            identity->pq_signed_prekey.public_key,
            GYROJET_MLKEM_PUBLIC_KEY_SIZE,
            identity->pq_signed_prekey_signature
        ) != 0) {
        gyrojet_identity_clear(identity);
        return -1;
    }

    return 0;
}

void gyrojet_identity_clear(
    gyrojet_identity_t *identity
)
{
    if (identity == NULL)
        return;

    gyrojet_crypto_secure_zero(
        identity,
        sizeof(*identity)
    );
}
