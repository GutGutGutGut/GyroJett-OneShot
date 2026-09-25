#define _POSIX_C_SOURCE 200809L

#include "client.h"

#include "../chat/chat.h"
#include "../network/connection.h"
#include "../network/socks5.h"

#include <stdio.h>

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
            "GyroJett: não foi possível "
            "estabelecer a conexão.\n"
        );

        return -1;
    }

    printf(
        "✓ Conexão estabelecida.\n"
    );

    int result = gyrojet_chat_run(
        &connection,
        session_key
    );

    gyrojet_connection_close(
        &connection
    );

    return result;
}
