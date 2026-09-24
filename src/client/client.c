#define _POSIX_C_SOURCE 200809L

#include "client.h"

#include "../crypto/aead.h"
#include "../crypto/crypto.h"
#include "../network/connection.h"
#include "../network/socks5.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>

#define GYROJET_FRAME_MAX_SIZE 4096

static int gyrojet_client_recv_all(
    gyrojet_connection_t *connection,
    void *buffer,
    size_t size
)
{
    if (connection == NULL)
        return -1;

    unsigned char *output = buffer;
    size_t received = 0;

    while (received < size) {
        ssize_t result = gyrojet_connection_recv(
            connection,
            output + received,
            size - received
        );

        if (result < 0)
            return -1;

        if (result == 0)
            return -1;

        received += (size_t)result;
    }

    return 0;
}

int gyrojet_client_connect(
    const char *onion_address,
    unsigned short port,
    const unsigned char session_key[
        GYROJET_CLIENT_SESSION_KEY_SIZE
    ]
)
{
    if (onion_address == NULL ||
        session_key == NULL) {
        return -1;
    }

    gyrojet_connection_t connection = {
        .fd = -1
    };

    printf(
        "\nConectando a %s:%u...\n",
        onion_address,
        port
    );

    if (gyrojet_socks5_connect(
            onion_address,
            port,
            &connection
        ) < 0) {

        fprintf(
            stderr,
            "GyroJett: não foi possível estabelecer a conexão.\n"
        );

        return -1;
    }

    printf("✓ Conexão estabelecida.\n");

    uint32_t network_length;

    if (gyrojet_client_recv_all(
            &connection,
            &network_length,
            sizeof(network_length)
        ) != 0) {

        fprintf(
            stderr,
            "GyroJett: erro ao receber tamanho da mensagem.\n"
        );

        gyrojet_connection_close(&connection);

        return -1;
    }

    uint32_t message_size = ntohl(network_length);

    if (message_size > GYROJET_FRAME_MAX_SIZE) {
        fprintf(
            stderr,
            "GyroJett: mensagem excede o tamanho máximo.\n"
        );

        gyrojet_connection_close(&connection);

        return -1;
    }

    unsigned char nonce[
        GYROJET_AEAD_NONCE_SIZE
    ];

    unsigned char ciphertext[
        GYROJET_FRAME_MAX_SIZE
    ];

    unsigned char tag[
        GYROJET_AEAD_TAG_SIZE
    ];

    unsigned char plaintext[
        GYROJET_FRAME_MAX_SIZE + 1
    ];

    if (gyrojet_client_recv_all(
            &connection,
            nonce,
            sizeof(nonce)
        ) != 0) {
        fprintf(
            stderr,
            "GyroJett: erro ao receber nonce.\n"
        );

        gyrojet_connection_close(&connection);

        return -1;
    }

    if (gyrojet_client_recv_all(
            &connection,
            ciphertext,
            message_size
        ) != 0) {
        fprintf(
            stderr,
            "GyroJett: erro ao receber ciphertext.\n"
        );

        gyrojet_connection_close(&connection);

        return -1;
    }

    if (gyrojet_client_recv_all(
            &connection,
            tag,
            sizeof(tag)
        ) != 0) {
        fprintf(
            stderr,
            "GyroJett: erro ao receber tag.\n"
        );

        gyrojet_connection_close(&connection);

        return -1;
    }

    if (gyrojet_aead_decrypt(
            session_key,
            nonce,
            ciphertext,
            message_size,
            NULL,
            0,
            tag,
            plaintext
        ) != 0) {

        fprintf(
            stderr,
            "GyroJett: autenticação da mensagem falhou.\n"
        );

        gyrojet_connection_close(&connection);

        return -1;
    }

    plaintext[message_size] = '\0';

    printf(
        "\nPeer: %s\n",
        plaintext
    );

    gyrojet_crypto_secure_zero(
        nonce,
        sizeof(nonce)
    );

    gyrojet_crypto_secure_zero(
        ciphertext,
        sizeof(ciphertext)
    );

    gyrojet_crypto_secure_zero(
        tag,
        sizeof(tag)
    );

    gyrojet_crypto_secure_zero(
        plaintext,
        sizeof(plaintext)
    );

    gyrojet_connection_close(&connection);

    return 0;
}
