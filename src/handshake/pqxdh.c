#include "pqxdh.h"

#include "../crypto/crypto.h"
#include "../crypto/mlkem.h"
#include "../crypto/x25519.h"

#include <string.h>

int gyrojet_pqxdh_init(void)
{
return gyrojet_crypto_init();
}

int gyrojet_pqxdh_run_test(
gyrojet_pqxdh_result_t *result
)
{
if (result == NULL)
return -1;

memset(
    result,
    0,
    sizeof(*result)
);

unsigned char alice_private[
    GYROJET_X25519_PRIVATE_KEY_SIZE
];

unsigned char alice_public[
    GYROJET_X25519_PUBLIC_KEY_SIZE
];

unsigned char bob_private[
    GYROJET_X25519_PRIVATE_KEY_SIZE
];

unsigned char bob_public[
    GYROJET_X25519_PUBLIC_KEY_SIZE
];

unsigned char alice_dh[
    GYROJET_X25519_SHARED_SECRET_SIZE
];

unsigned char bob_dh[
    GYROJET_X25519_SHARED_SECRET_SIZE
];

unsigned char bob_mlkem_public[
    GYROJET_MLKEM_PUBLIC_KEY_SIZE
];

unsigned char bob_mlkem_private[
    GYROJET_MLKEM_PRIVATE_KEY_SIZE
];

unsigned char ciphertext[
    GYROJET_MLKEM_CIPHERTEXT_SIZE
];

unsigned char alice_mlkem_secret[
    GYROJET_MLKEM_SHARED_SECRET_SIZE
];

unsigned char bob_mlkem_secret[
    GYROJET_MLKEM_SHARED_SECRET_SIZE
];

if (gyrojet_x25519_generate_keypair(
        alice_public,
        alice_private
    ) < 0) {

    return -1;
}

if (gyrojet_x25519_generate_keypair(
        bob_public,
        bob_private
    ) < 0) {

    return -1;
}

if (gyrojet_x25519_shared_secret(
        alice_private,
        bob_public,
        alice_dh
    ) < 0) {

    return -1;
}

if (gyrojet_x25519_shared_secret(
        bob_private,
        alice_public,
        bob_dh
    ) < 0) {

    return -1;
}

if (memcmp(
        alice_dh,
        bob_dh,
        sizeof(alice_dh)
    ) != 0) {

    return -1;
}

if (gyrojet_mlkem_generate_keypair(
        bob_mlkem_public,
        bob_mlkem_private
    ) < 0) {

    return -1;
}

if (gyrojet_mlkem_encapsulate(
        bob_mlkem_public,
        ciphertext,
        alice_mlkem_secret
    ) < 0) {

    return -1;
}

if (gyrojet_mlkem_decapsulate(
        bob_mlkem_private,
        ciphertext,
        bob_mlkem_secret
    ) < 0) {

    return -1;
}

if (memcmp(
        alice_mlkem_secret,
        bob_mlkem_secret,
        sizeof(alice_mlkem_secret)
    ) != 0) {

    return -1;
}

/*
 * This is intentionally only a primitive
 * interoperability test.
 *
 * It is NOT the final PQXDH KDF.
 */

memcpy(
    result->shared_secret,
    alice_mlkem_secret,
    sizeof(result->shared_secret)
);

result->associated_data_size = 0;

gyrojet_crypto_secure_zero(
    alice_private,
    sizeof(alice_private)
);

gyrojet_crypto_secure_zero(
    bob_private,
    sizeof(bob_private)
);

gyrojet_crypto_secure_zero(
    alice_dh,
    sizeof(alice_dh)
);

gyrojet_crypto_secure_zero(
    bob_dh,
    sizeof(bob_dh)
);

gyrojet_crypto_secure_zero(
    bob_mlkem_private,
    sizeof(bob_mlkem_private)
);

gyrojet_crypto_secure_zero(
    alice_mlkem_secret,
    sizeof(alice_mlkem_secret)
);

gyrojet_crypto_secure_zero(
    bob_mlkem_secret,
    sizeof(bob_mlkem_secret)
);

return 0;

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

