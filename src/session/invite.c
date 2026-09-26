#define _POSIX_C_SOURCE 200809L

#include "invite.h"

#include "../crypto/crypto.h"

#include <stdio.h>
#include <string.h>

static int gyrojet_invite_validate_onion(
    const char *onion
)
{
    if (onion == NULL)
        return -1;

    const size_t length = strlen(onion);

    /*
     * v3 Onion Service:
     *
     * 56 caracteres + ".onion"
     */
    if (length != 62)
        return -1;

    if (strcmp(
            onion + 56,
            ".onion"
        ) != 0) {
        return -1;
    }

    for (size_t i = 0; i < 56; i++) {
        const char c = onion[i];

        /*
         * Base32 sem padding.
         */
        if (!(
            (c >= 'a' && c <= 'z') ||
            (c >= '2' && c <= '7')
        )) {
            return -1;
        }
    }

    return 0;
}

int gyrojet_invite_create(
    const char *onion_address,
    const char *secret,
    char *output,
    size_t output_size
)
{
    if (onion_address == NULL ||
        secret == NULL ||
        output == NULL) {
        return -1;
    }

    if (gyrojet_invite_validate_onion(
            onion_address
        ) < 0) {
        return -1;
    }

    const size_t secret_length = strlen(secret);

    if (secret_length == 0)
        return -1;

    const int written = snprintf(
        output,
        output_size,
        GYROJET_INVITE_PREFIX "%s/%s",
        onion_address,
        secret
    );

    if (written < 0)
        return -1;

    if ((size_t)written >= output_size)
        return -1;

    return 0;
}

int gyrojet_invite_parse(
    const char *invite,
    char *onion_address,
    size_t onion_size,
    char *secret,
    size_t secret_size
)
{
    if (invite == NULL ||
        onion_address == NULL ||
        secret == NULL) {
        return -1;
    }

    const size_t prefix_length = strlen(
        GYROJET_INVITE_PREFIX
    );

    if (strncmp(
            invite,
            GYROJET_INVITE_PREFIX,
            prefix_length
        ) != 0) {
        return -1;
    }

    const char *payload =
        invite + prefix_length;

    const char *separator = strchr(
        payload,
        '/'
    );

    if (separator == NULL)
        return -1;

    const size_t onion_length =
        (size_t)(separator - payload);

    if (onion_length != 62)
        return -1;

    if (onion_length + 1 > onion_size)
        return -1;

    memcpy(
        onion_address,
        payload,
        onion_length
    );

    onion_address[onion_length] = '\0';

    if (gyrojet_invite_validate_onion(
            onion_address
        ) < 0) {
        gyrojet_crypto_secure_zero(
            onion_address,
            onion_size
        );

        return -1;
    }

    const char *secret_start =
        separator + 1;

    const size_t secret_length =
        strlen(secret_start);

    if (secret_length == 0 ||
        secret_length + 1 > secret_size) {
        gyrojet_crypto_secure_zero(
            onion_address,
            onion_size
        );

        return -1;
    }

    memcpy(
        secret,
        secret_start,
        secret_length
    );

    secret[secret_length] = '\0';

    return 0;
}

int gyrojet_invite_copy_clipboard(
    const char *invite
)
{
    if (invite == NULL)
        return -1;

    const size_t length = strlen(invite);

    /*
     * OSC 52:
     *
     * ESC ] 52 ; c ; BASE64 BEL
     *
     * A codificação Base64 é feita sem depender
     * de ferramentas externas.
     */
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    const size_t encoded_size =
        ((length + 2U) / 3U) * 4U;

    /*
     * Limite deliberado para evitar alocação
     * desnecessariamente grande.
     */
    if (length > GYROJET_INVITE_MAX_SIZE ||
        encoded_size > 512U) {
        return -1;
    }

    char encoded[513];
    size_t input = 0;
    size_t output = 0;

    while (input < length) {
        const unsigned int a =
            (unsigned char)invite[input++];

        const unsigned int b =
            input < length
                ? (unsigned char)invite[input++]
                : 0U;

        const unsigned int c =
            input < length
                ? (unsigned char)invite[input++]
                : 0U;

        const unsigned int value =
            (a << 16U) |
            (b << 8U) |
            c;

        encoded[output++] =
            alphabet[(value >> 18U) & 0x3FU];

        encoded[output++] =
            alphabet[(value >> 12U) & 0x3FU];

        encoded[output++] =
            input - 1U < length
                ? alphabet[(value >> 6U) & 0x3FU]
                : '=';

        encoded[output++] =
            input < length
                ? alphabet[value & 0x3FU]
                : '=';
    }

    encoded[output] = '\0';

    printf(
        "\033]52;c;%s\a",
        encoded
    );

    fflush(stdout);

    gyrojet_crypto_secure_zero(
        encoded,
        sizeof(encoded)
    );

    return 0;
}
