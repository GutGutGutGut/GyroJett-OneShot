#define _POSIX_C_SOURCE 200809L

#include "server.h"

#include "../chat/chat.h"
#include "../network/connection.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int gyrojet_server_start(
    gyrojet_server_t *server,
    unsigned short port
)
{
    if (server == NULL)
        return -1;

    memset(
        server,
        0,
        sizeof(*server)
    );

    server->socket_fd = -1;

    server->socket_fd = socket(
        AF_INET,
        SOCK_STREAM,
        0
    );

    if (server->socket_fd < 0) {
        perror("GyroJett: socket");
        return -1;
    }

    int reuse = 1;

    if (setsockopt(
            server->socket_fd,
            SOL_SOCKET,
            SO_REUSEADDR,
            &reuse,
            sizeof(reuse)
        ) < 0) {

        perror("GyroJett: setsockopt");

        close(server->socket_fd);
        server->socket_fd = -1;

        return -1;
    }

    struct sockaddr_in address;

    memset(
        &address,
        0,
        sizeof(address)
    );

    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(
        INADDR_LOOPBACK
    );

    if (bind(
            server->socket_fd,
            (struct sockaddr *)&address,
            sizeof(address)
        ) < 0) {

        perror("GyroJett: bind");

        close(server->socket_fd);
        server->socket_fd = -1;

        return -1;
    }

    if (listen(
            server->socket_fd,
            16
        ) < 0) {

        perror("GyroJett: listen");

        close(server->socket_fd);
        server->socket_fd = -1;

        return -1;
    }

    server->port = port;

    return 0;
}

void gyrojet_server_stop(
    gyrojet_server_t *server
)
{
    if (server == NULL)
        return;

    if (server->socket_fd >= 0) {
        close(server->socket_fd);
        server->socket_fd = -1;
    }
}

int gyrojet_server_run(
    gyrojet_server_t *server,
    const unsigned char session_key[
        GYROJET_SERVER_SESSION_KEY_SIZE
    ]
)
{
    if (server == NULL ||
        server->socket_fd < 0 ||
        session_key == NULL) {
        return -1;
    }

    printf(
        "Servidor aguardando conexão...\n"
    );

    for (;;) {
        struct sockaddr_in client;

        socklen_t client_length =
            sizeof(client);

        int client_fd = accept(
            server->socket_fd,
            (struct sockaddr *)&client,
            &client_length
        );

        if (client_fd < 0) {
            if (errno == EINTR)
                continue;

            perror("GyroJett: accept");
            return -1;
        }

        char address[INET_ADDRSTRLEN];

        if (inet_ntop(
                AF_INET,
                &client.sin_addr,
                address,
                sizeof(address)
            ) != NULL) {

            printf(
                "Conexão recebida de %s:%u\n",
                address,
                ntohs(client.sin_port)
            );
        }

        gyrojet_connection_t connection = {
            .fd = client_fd
        };

        printf(
            "Iniciando sessão de chat...\n"
        );

        int chat_result = gyrojet_chat_run(
            &connection,
            session_key
        );

        gyrojet_connection_close(
            &connection
        );

        if (chat_result < 0) {
            fprintf(
                stderr,
                "GyroJett: sessão de chat "
                "encerrada com erro.\n"
            );
        } else {
            printf(
                "Sessão de chat encerrada.\n"
            );
        }
    }
}
