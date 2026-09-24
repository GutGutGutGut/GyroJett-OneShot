#include "xeddsa.h"

#include <xeddsa.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Limpa uma região de memória sem permitir que o compilador
 * elimine a operação.
 */
static void gyrojet_xeddsa_secure_zero(
    void *buffer,
    size_t size
)
{
    if (buffer == NULL)
        return;

    volatile unsigned char *ptr = buffer;

    while (size > 0) {
        *ptr = 0;
        ++ptr;
        --size;
    }
}

int gyrojet_xeddsa_init(void)
{
    const int result = xeddsa_init();

    if (result < 0)
        return -1;

    return 0;
}

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
)
{
    unsigned char signing_key[
        GYROJET_XEDDSA_PRIVATE_KEY_SIZE
    ];

    if (private_key == NULL ||
        message == NULL ||
        random == NULL ||
        signature == NULL) {
        return -1;
    }

    if (message_size > UINT32_MAX)
        return -1;

    /*
     * XEdDSA exige que a chave usada para assinatura
     * tenha o sign bit Ed25519 definido como zero.
     *
     * priv_force_sign() ajusta a representação privada
     * sem alterar a chave Curve25519 correspondente.
     */
    priv_force_sign(
        signing_key,
        private_key,
        false
    );

    ed25519_priv_sign(
        signature,
        signing_key,
        message,
        (uint32_t)message_size,
        random
    );

    gyrojet_xeddsa_secure_zero(
        signing_key,
        sizeof(signing_key)
    );

    return 0;
}

int gyrojet_xeddsa_verify(
    const unsigned char public_key[
        GYROJET_XEDDSA_PUBLIC_KEY_SIZE
    ],
    const unsigned char *message,
    size_t message_size,
    const unsigned char signature[
        GYROJET_XEDDSA_SIGNATURE_SIZE
    ]
)
{
    unsigned char ed25519_public[
        GYROJET_XEDDSA_PUBLIC_KEY_SIZE
    ];

    if (public_key == NULL ||
        message == NULL ||
        signature == NULL) {
        return -1;
    }

    if (message_size > UINT32_MAX)
        return -1;

    /*
     * A chave pública X25519 não contém o sign bit.
     *
     * XEdDSA utiliza a convenção de sign bit zero,
     * portanto a conversão é feita com false.
     */
    curve25519_pub_to_ed25519_pub(
        ed25519_public,
        public_key,
        false
    );

    const int result = ed25519_verify(
        signature,
        ed25519_public,
        message,
        (uint32_t)message_size
    );

    gyrojet_xeddsa_secure_zero(
        ed25519_public,
        sizeof(ed25519_public)
    );

    if (result != 0)
        return -1;

    return 0;
}

int gyrojet_xeddsa_x25519_public_key(
    const unsigned char private_key[
        GYROJET_XEDDSA_PRIVATE_KEY_SIZE
    ],
    unsigned char public_key[
        GYROJET_XEDDSA_PUBLIC_KEY_SIZE
    ]
)
{
    if (private_key == NULL ||
        public_key == NULL) {
        return -1;
    }

    priv_to_curve25519_pub(
        public_key,
        private_key
    );

    return 0;
}
