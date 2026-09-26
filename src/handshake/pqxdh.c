#define _POSIX_C_SOURCE 200809L

#include "pqxdh.h"

#include "../crypto/crypto.h"
#include "../crypto/mlkem.h"
#include "../crypto/x25519.h"
#include "../crypto/xeddsa.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <stddef.h>
#include <string.h>

#define GYROJET_PQXDH_DOMAIN \
    "GyroJett-OneShot2_CURVE25519_SHA-256_MLKEM-768"

#define GYROJET_PQXDH_DOMAIN_SIZE \
    (sizeof(GYROJET_PQXDH_DOMAIN) - 1)

#define GYROJET_PQXDH_F_SIZE 32

static int gyrojet_pqxdh_kdf(
    const unsigned char *key_material,
    size_t key_material_size,
    unsigned char output[
        GYROJET_PQXDH_SHARED_SECRET_SIZE
    ]
)
{
    if (key_material == NULL ||
        output == NULL) {
        return -1;
    }

    /*
     * PQXDH:
     *
     * HKDF-IKM = F || KM
     *
     * F = 32 bytes 0xff para Curve25519.
     *
     * HKDF salt = 32 bytes zero.
     */

    if (key_material_size >
        SIZE_MAX - GYROJET_PQXDH_F_SIZE) {
        return -1;
    }

    const size_t ikm_size =
        GYROJET_PQXDH_F_SIZE +
        key_material_size;

    unsigned char ikm[
        GYROJET_PQXDH_F_SIZE +
        4 * GYROJET_X25519_SHARED_SECRET_SIZE
    ];

    unsigned char salt[32];

    memset(
        ikm,
        0,
        sizeof(ikm)
    );

    memset(
        salt,
        0,
        sizeof(salt)
    );

    memset(
        ikm,
        0xff,
        GYROJET_PQXDH_F_SIZE
    );

    memcpy(
        ikm + GYROJET_PQXDH_F_SIZE,
        key_material,
        key_material_size
    );

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(
        EVP_PKEY_HKDF,
        NULL
    );

    if (ctx == NULL) {
        gyrojet_crypto_secure_zero(
            ikm,
            sizeof(ikm)
        );

        gyrojet_crypto_secure_zero(
            salt,
            sizeof(salt)
        );

        return -1;
    }

    int result = -1;

    if (EVP_PKEY_derive_init(ctx) != 1)
        goto cleanup;

    if (EVP_PKEY_CTX_set_hkdf_md(
            ctx,
            EVP_sha256()
        ) != 1) {
        goto cleanup;
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(
            ctx,
            salt,
            (int)sizeof(salt)
        ) != 1) {
        goto cleanup;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(
            ctx,
            ikm,
            (int)ikm_size
        ) != 1) {
        goto cleanup;
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(
            ctx,
            (unsigned char *)GYROJET_PQXDH_DOMAIN,
            (int)GYROJET_PQXDH_DOMAIN_SIZE
        ) != 1) {
        goto cleanup;
    }

    size_t output_size =
        GYROJET_PQXDH_SHARED_SECRET_SIZE;

    if (EVP_PKEY_derive(
            ctx,
            output,
            &output_size
        ) != 1) {
        goto cleanup;
    }

    if (output_size !=
        GYROJET_PQXDH_SHARED_SECRET_SIZE) {
        goto cleanup;
    }

    result = 0;

cleanup:

    if (result != 0) {
        gyrojet_crypto_secure_zero(
            output,
            GYROJET_PQXDH_SHARED_SECRET_SIZE
        );
    }

    EVP_PKEY_CTX_free(ctx);

    gyrojet_crypto_secure_zero(
        ikm,
        sizeof(ikm)
    );

    gyrojet_crypto_secure_zero(
        salt,
        sizeof(salt)
    );

    return result;
}

static int gyrojet_pqxdh_verify_prekeys(
    const gyrojet_identity_t *remote_identity
)
{
    if (remote_identity == NULL)
        return -1;

    if (gyrojet_xeddsa_verify(
            remote_identity->identity_key.public_key,
            remote_identity->signed_prekey.public_key,
            GYROJET_X25519_PUBLIC_KEY_SIZE,
            remote_identity->signed_prekey_signature
        ) != 0) {
        return -1;
    }

    if (gyrojet_xeddsa_verify(
            remote_identity->identity_key.public_key,
            remote_identity->pq_signed_prekey.public_key,
            GYROJET_MLKEM_PUBLIC_KEY_SIZE,
            remote_identity->pq_signed_prekey_signature
        ) != 0) {
        return -1;
    }

    return 0;
}

int gyrojet_pqxdh_init(void)
{
    return gyrojet_crypto_init();
}

int gyrojet_pqxdh_initiate(
    const gyrojet_identity_t *local_identity,
    const gyrojet_identity_t *remote_identity,
    gyrojet_pqxdh_message_t *message,
    gyrojet_pqxdh_result_t *result
)
{
    if (local_identity == NULL ||
        remote_identity == NULL ||
        message == NULL ||
        result == NULL) {
        return -1;
    }

    memset(
        message,
        0,
        sizeof(*message)
    );

    memset(
        result,
        0,
        sizeof(*result)
    );

    unsigned char ephemeral_private[
        GYROJET_X25519_PRIVATE_KEY_SIZE
    ];

    unsigned char dh1[
        GYROJET_X25519_SHARED_SECRET_SIZE
    ];

    unsigned char dh2[
        GYROJET_X25519_SHARED_SECRET_SIZE
    ];

    unsigned char dh3[
        GYROJET_X25519_SHARED_SECRET_SIZE
    ];

    unsigned char pq_secret[
        GYROJET_MLKEM_SHARED_SECRET_SIZE
    ];

    unsigned char key_material[
        4 * GYROJET_X25519_SHARED_SECRET_SIZE
    ];

    unsigned char signing_public_key[
        GYROJET_X25519_PUBLIC_KEY_SIZE
    ];

    memset(ephemeral_private, 0, sizeof(ephemeral_private));
    memset(dh1, 0, sizeof(dh1));
    memset(dh2, 0, sizeof(dh2));
    memset(dh3, 0, sizeof(dh3));
    memset(pq_secret, 0, sizeof(pq_secret));
    memset(key_material, 0, sizeof(key_material));
    memset(signing_public_key, 0, sizeof(signing_public_key));

    int result_code = -1;

    /*
     * O iniciador verifica primeiro os prekeys
     * autenticados pelo identity key remoto.
     */
    if (gyrojet_pqxdh_verify_prekeys(
            remote_identity
        ) < 0) {
        goto cleanup;
    }

    /*
     * Gera EK_A.
     */
    if (gyrojet_x25519_generate_keypair(
            message->ephemeral_public_key,
            ephemeral_private
        ) < 0) {
        goto cleanup;
    }

    /*
     * Copia IK_A.
     */
    memcpy(
        message->identity_public_key,
        local_identity->identity_key.public_key,
        GYROJET_X25519_PUBLIC_KEY_SIZE
    );

    /*
     * Identificadores dos prekeys usados.
     */
    memcpy(
        message->signed_prekey_id,
        remote_identity->signed_prekey_id,
        GYROJET_PREKEY_ID_SIZE
    );

    memcpy(
        message->pq_signed_prekey_id,
        remote_identity->pq_signed_prekey_id,
        GYROJET_PREKEY_ID_SIZE
    );

    /*
     * DH1 = DH(IK_A, SPK_B)
     */
    if (gyrojet_x25519_shared_secret(
            local_identity->identity_key.private_key,
            remote_identity->signed_prekey.public_key,
            dh1
        ) < 0) {
        goto cleanup;
    }

    /*
     * DH2 = DH(EK_A, IK_B)
     */
    if (gyrojet_x25519_shared_secret(
            ephemeral_private,
            remote_identity->identity_key.public_key,
            dh2
        ) < 0) {
        goto cleanup;
    }

    /*
     * DH3 = DH(EK_A, SPK_B)
     */
    if (gyrojet_x25519_shared_secret(
            ephemeral_private,
            remote_identity->signed_prekey.public_key,
            dh3
        ) < 0) {
        goto cleanup;
    }

    /*
     * PQKEM-ENC(PQSPK_B)
     */
    if (gyrojet_mlkem_encapsulate(
            remote_identity->pq_signed_prekey.public_key,
            message->pq_ciphertext,
            pq_secret
        ) < 0) {
        goto cleanup;
    }

    /*
     * DH1 || DH2 || DH3 || SS_PQ
     */
    memcpy(
        key_material,
        dh1,
        sizeof(dh1)
    );

    memcpy(
        key_material + sizeof(dh1),
        dh2,
        sizeof(dh2)
    );

    memcpy(
        key_material + sizeof(dh1) + sizeof(dh2),
        dh3,
        sizeof(dh3)
    );

    memcpy(
        key_material +
        sizeof(dh1) +
        sizeof(dh2) +
        sizeof(dh3),
        pq_secret,
        sizeof(pq_secret)
    );

    if (gyrojet_pqxdh_kdf(
            key_material,
            sizeof(key_material),
            result->shared_secret
        ) < 0) {
        goto cleanup;
    }

    /*
     * AD = IK_A || IK_B
     */
    memcpy(
        result->associated_data,
        local_identity->identity_key.public_key,
        GYROJET_X25519_PUBLIC_KEY_SIZE
    );

    memcpy(
        result->associated_data +
        GYROJET_X25519_PUBLIC_KEY_SIZE,
        remote_identity->identity_key.public_key,
        GYROJET_X25519_PUBLIC_KEY_SIZE
    );

    result->associated_data_size =
        GYROJET_PQXDH_ASSOCIATED_DATA_SIZE;

    result_code = 0;

cleanup:

    gyrojet_crypto_secure_zero(
        ephemeral_private,
        sizeof(ephemeral_private)
    );

    gyrojet_crypto_secure_zero(
        dh1,
        sizeof(dh1)
    );

    gyrojet_crypto_secure_zero(
        dh2,
        sizeof(dh2)
    );

    gyrojet_crypto_secure_zero(
        dh3,
        sizeof(dh3)
    );

    gyrojet_crypto_secure_zero(
        pq_secret,
        sizeof(pq_secret)
    );

    gyrojet_crypto_secure_zero(
        key_material,
        sizeof(key_material)
    );

    gyrojet_crypto_secure_zero(
        signing_public_key,
        sizeof(signing_public_key)
    );

    if (result_code != 0) {
        gyrojet_pqxdh_message_clear(message);
        gyrojet_pqxdh_result_clear(result);
    }

    return result_code;
}

int gyrojet_pqxdh_accept(
    const gyrojet_identity_t *local_identity,
    const gyrojet_pqxdh_message_t *message,
    gyrojet_pqxdh_result_t *result
)
{
    if (local_identity == NULL ||
        message == NULL ||
        result == NULL) {
        return -1;
    }

    memset(
        result,
        0,
        sizeof(*result)
    );

    unsigned char dh1[
        GYROJET_X25519_SHARED_SECRET_SIZE
    ];

    unsigned char dh2[
        GYROJET_X25519_SHARED_SECRET_SIZE
    ];

    unsigned char dh3[
        GYROJET_X25519_SHARED_SECRET_SIZE
    ];

    unsigned char pq_secret[
        GYROJET_MLKEM_SHARED_SECRET_SIZE
    ];

    unsigned char key_material[
        4 * GYROJET_X25519_SHARED_SECRET_SIZE
    ];

    memset(dh1, 0, sizeof(dh1));
    memset(dh2, 0, sizeof(dh2));
    memset(dh3, 0, sizeof(dh3));
    memset(pq_secret, 0, sizeof(pq_secret));
    memset(key_material, 0, sizeof(key_material));

    int result_code = -1;

    /*
     * Verifica se a mensagem usa o signed prekey
     * atualmente ativo.
     */
    if (memcmp(
            message->signed_prekey_id,
            local_identity->signed_prekey_id,
            GYROJET_PREKEY_ID_SIZE
        ) != 0) {
        goto cleanup;
    }

    if (memcmp(
            message->pq_signed_prekey_id,
            local_identity->pq_signed_prekey_id,
            GYROJET_PREKEY_ID_SIZE
        ) != 0) {
        goto cleanup;
    }

    /*
     * DH1 = DH(SPK_B, IK_A)
     */
    if (gyrojet_x25519_shared_secret(
            local_identity->signed_prekey.private_key,
            message->identity_public_key,
            dh1
        ) < 0) {
        goto cleanup;
    }

    /*
     * DH2 = DH(IK_B, EK_A)
     */
    if (gyrojet_x25519_shared_secret(
            local_identity->identity_key.private_key,
            message->ephemeral_public_key,
            dh2
        ) < 0) {
        goto cleanup;
    }

    /*
     * DH3 = DH(SPK_B, EK_A)
     */
    if (gyrojet_x25519_shared_secret(
            local_identity->signed_prekey.private_key,
            message->ephemeral_public_key,
            dh3
        ) < 0) {
        goto cleanup;
    }

    /*
     * PQKEM-DEC(PQSPK_B, CT)
     */
    if (gyrojet_mlkem_decapsulate(
            local_identity->pq_signed_prekey.private_key,
            message->pq_ciphertext,
            pq_secret
        ) < 0) {
        goto cleanup;
    }

    /*
     * DH1 || DH2 || DH3 || SS_PQ
     */
    memcpy(
        key_material,
        dh1,
        sizeof(dh1)
    );

    memcpy(
        key_material + sizeof(dh1),
        dh2,
        sizeof(dh2)
    );

    memcpy(
        key_material + sizeof(dh1) + sizeof(dh2),
        dh3,
        sizeof(dh3)
    );

    memcpy(
        key_material +
        sizeof(dh1) +
        sizeof(dh2) +
        sizeof(dh3),
        pq_secret,
        sizeof(pq_secret)
    );

    if (gyrojet_pqxdh_kdf(
            key_material,
            sizeof(key_material),
            result->shared_secret
        ) < 0) {
        goto cleanup;
    }

    /*
     * AD = IK_A || IK_B
     */
    memcpy(
        result->associated_data,
        message->identity_public_key,
        GYROJET_X25519_PUBLIC_KEY_SIZE
    );

    memcpy(
        result->associated_data +
        GYROJET_X25519_PUBLIC_KEY_SIZE,
        local_identity->identity_key.public_key,
        GYROJET_X25519_PUBLIC_KEY_SIZE
    );

    result->associated_data_size =
        GYROJET_PQXDH_ASSOCIATED_DATA_SIZE;

    result_code = 0;

cleanup:

    gyrojet_crypto_secure_zero(
        dh1,
        sizeof(dh1)
    );

    gyrojet_crypto_secure_zero(
        dh2,
        sizeof(dh2)
    );

    gyrojet_crypto_secure_zero(
        dh3,
        sizeof(dh3)
    );

    gyrojet_crypto_secure_zero(
        pq_secret,
        sizeof(pq_secret)
    );

    gyrojet_crypto_secure_zero(
        key_material,
        sizeof(key_material)
    );

    if (result_code != 0)
        gyrojet_pqxdh_result_clear(result);

    return result_code;
}

void gyrojet_pqxdh_message_clear(
    gyrojet_pqxdh_message_t *message
)
{
    if (message == NULL)
        return;

    gyrojet_crypto_secure_zero(
        message,
        sizeof(*message)
    );
}

void gyrojet_pqxdh_result_clear(
    gyrojet_pqxdh_result_t *result
)
{
    if (result == NULL)
        return;

    gyrojet_crypto_secure_zero(
        result,
        sizeof(*result)
    );
}
