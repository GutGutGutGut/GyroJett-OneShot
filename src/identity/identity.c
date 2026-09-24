#include "identity.h"

#include "../crypto/crypto.h"

#include <string.h>

int gyrojet_identity_generate(
    gyrojet_identity_t *identity
)
{
    if (identity == NULL)
        return -1;

    memset(
        identity,
        0,
        sizeof(*identity)
    );

    if (gyrojet_x25519_generate_keypair(
            identity->identity_key.public_key,
            identity->identity_key.private_key
        ) != 0) {

        gyrojet_identity_clear(identity);
        return -1;
    }

    if (gyrojet_x25519_generate_keypair(
            identity->signed_prekey.public_key,
            identity->signed_prekey.private_key
        ) != 0) {

        gyrojet_identity_clear(identity);
        return -1;
    }

    if (gyrojet_mlkem_generate_keypair(
            identity->pq_signed_prekey.public_key,
            identity->pq_signed_prekey.private_key
        ) != 0) {

        gyrojet_identity_clear(identity);
        return -1;
    }

    if (gyrojet_crypto_random(
            identity->signed_prekey_id,
            sizeof(identity->signed_prekey_id)
        ) != 0) {

        gyrojet_identity_clear(identity);
        return -1;
    }

    if (gyrojet_crypto_random(
            identity->pq_signed_prekey_id,
            sizeof(identity->pq_signed_prekey_id)
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
