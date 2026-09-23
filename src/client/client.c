#define _POSIX_C_SOURCE 200809L

#include "client.h"

#include "../network/connection.h"
#include "../network/socks5.h"

#include <stdio.h>

int gyrojet_client_connect(
    const char *onion_address,
    unsigned short port
)
{
    if (onion_address == NULL)
        return -1;

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

    printf(
        "✓ Conexão estabelecida.\n"
    );

    char buffer[1024];

    ssize_t received = gyrojet_connection_recv(
        &connection,
        buffer,
        sizeof(buffer) - 1
    );

    if (received < 0) {
        fprintf(
            stderr,
            "GyroJett: erro ao receber dados.\n"
        );

        gyrojet_connection_close(&connection);

        return -1;
    }

    if (received == 0) {
        printf(
            "Peer fechou a conexão.\n"
        );

        gyrojet_connection_close(&connection);

        return 0;
    }

    buffer[received] = '\0';

    printf(
        "\nPeer: %s\n",
        buffer
    );

    gyrojet_connection_close(&connection);

    return 0;
}
