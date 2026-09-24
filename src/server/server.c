#define _POSIX_C_SOURCE 200809L

#include "server.h"

#include "../crypto/aead.h"
#include "../crypto/crypto.h"
#include "../network/connection.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define GYROJET_FRAME_MAX_SIZE 4096

static int gyrojet_server_send_message(
    int client_fd,
    const unsigned char session_key[
        GYROJET_SERVER_SESSION_KEY_SIZE
    ],
    const unsigned char *message,
    size_t message_size
)
{
    if (client_fd < 0 ||
        session_key == NULL ||
        message == NULL) {
        return -1;
    }

    if (message_size > GYROJET_FRAME_MAX_SIZE)
        return -1;

    unsigned char nonce[GYROJET_AEAD_NONCE_SIZE];

    unsigned char ciphertext[
        GYROJET_FRAME_MAX_SIZE
    ];

    unsigned char tag[
        GYROJET_AEAD_TAG_SIZE
    ];

    if (gyrojet_crypto_random(
            nonce,
            sizeof(nonce)
        ) != 0) {
        return -1;
    }

    if (gyrojet_aead_encrypt(
            session_key,
            nonce,
            message,
            message_size,
            NULL,
            0,
            ciphertext,
            tag
        ) != 0) {

        gyrojet_crypto_secure_zero(
            nonce,
            sizeof(nonce)
        );

        return -1;
    }

    uint32_t length = htonl(
        (uint32_t)message_size
    );

    gyrojet_connection_t connection = {
        .fd = client_fd
    };

    if (gyrojet_connection_send(
            &connection,
            &length,
            sizeof(length)
        ) != 0) {
        return -1;
    }

    if (gyrojet_connection_send(
            &connection,
            nonce,
            sizeof(nonce)
        ) != 0) {
        return -1;
    }

    if (gyrojet_connection_send(
            &connection,
            ciphertext,
            message_size
        ) != 0) {
        return -1;
    }

    if (gyrojet_connection_send(
            &connection,
            tag,
            sizeof(tag)
        ) != 0) {
        return -1;
    }

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

    return 0;
}

int gyrojet_server_start(
    gyrojet_server_t *server,
    unsigned short port
)
{
    if (server == NULL)
        return -1;

    memset(server, 0, sizeof(*server));

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

    memset(&address, 0, sizeof(address));

    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

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

    if (listen(server->socket_fd, 16) < 0) {
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

    printf("Servidor aguardando conexão...\n");

    for (;;) {
        struct sockaddr_in client;
        socklen_t client_length = sizeof(client);

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

        static const unsigned char message[] =
            "GyroJett-OneShot2 encrypted session online.\n";

        if (gyrojet_server_send_message(
                client_fd,
                session_key,
                message,
                sizeof(message) - 1
            ) != 0) {

            fprintf(
                stderr,
                "GyroJett: erro ao enviar mensagem cifrada.\n"
            );

            close(client_fd);
            continue;
        }

        printf("Mensagem cifrada enviada.\n");

        close(client_fd);

        printf("Conexão encerrada.\n");
    }
}
