#define _POSIX_C_SOURCE 200809L

#include "chat.h"

#include "../crypto/aead.h"
#include "../crypto/crypto.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

enum {
    GYROJET_CHAT_RECV_ERROR = -1,
    GYROJET_CHAT_RECV_OK = 0,
    GYROJET_CHAT_RECV_CLOSED = 1
};

static int gyrojet_chat_recv_all(
    gyrojet_connection_t *connection,
    void *buffer,
    size_t size
)
{
    if (connection == NULL ||
        buffer == NULL) {
        return GYROJET_CHAT_RECV_ERROR;
    }

    unsigned char *ptr = buffer;
    size_t received = 0;

    while (received < size) {
        ssize_t result = gyrojet_connection_recv(
            connection,
            ptr + received,
            size - received
        );

        if (result < 0)
            return GYROJET_CHAT_RECV_ERROR;

        if (result == 0) {
            if (received == 0)
                return GYROJET_CHAT_RECV_CLOSED;

            return GYROJET_CHAT_RECV_ERROR;
        }

        received += (size_t)result;
    }

    return GYROJET_CHAT_RECV_OK;
}

static int gyrojet_chat_send_message(
    gyrojet_connection_t *connection,
    const unsigned char key[GYROJET_CHAT_KEY_SIZE],
    const unsigned char *message,
    size_t message_size
)
{
    if (connection == NULL ||
        connection->fd < 0 ||
        key == NULL) {
        return -1;
    }

    if (message == NULL && message_size > 0)
        return -1;

    if (message_size > GYROJET_CHAT_MAX_MESSAGE_SIZE)
        return -1;

    unsigned char nonce[GYROJET_AEAD_NONCE_SIZE];
    unsigned char ciphertext[
        GYROJET_CHAT_MAX_MESSAGE_SIZE
    ];
    unsigned char tag[GYROJET_AEAD_TAG_SIZE];

    uint32_t network_length = htonl(
        (uint32_t)message_size
    );

    int result = -1;

    memset(nonce, 0, sizeof(nonce));
    memset(ciphertext, 0, sizeof(ciphertext));
    memset(tag, 0, sizeof(tag));

    if (gyrojet_crypto_random(
            nonce,
            sizeof(nonce)
        ) < 0) {
        goto cleanup;
    }

    /*
     * O tamanho do frame faz parte do AAD.
     *
     * Assim, alguém não consegue alterar o tamanho
     * declarado sem invalidar a autenticação GCM.
     */
    if (gyrojet_aead_encrypt(
            key,
            nonce,
            message,
            message_size,
            (const unsigned char *)&network_length,
            sizeof(network_length),
            ciphertext,
            tag
        ) < 0) {
        goto cleanup;
    }

    if (gyrojet_connection_send(
            connection,
            &network_length,
            sizeof(network_length)
        ) < 0) {
        goto cleanup;
    }

    if (gyrojet_connection_send(
            connection,
            nonce,
            sizeof(nonce)
        ) < 0) {
        goto cleanup;
    }

    if (message_size > 0) {
        if (gyrojet_connection_send(
                connection,
                ciphertext,
                message_size
            ) < 0) {
            goto cleanup;
        }
    }

    if (gyrojet_connection_send(
            connection,
            tag,
            sizeof(tag)
        ) < 0) {
        goto cleanup;
    }

    result = 0;

cleanup:

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

    return result;
}

static int gyrojet_chat_receive_message(
    gyrojet_connection_t *connection,
    const unsigned char key[GYROJET_CHAT_KEY_SIZE],
    unsigned char *message,
    size_t message_capacity,
    size_t *message_size
)
{
    if (connection == NULL ||
        connection->fd < 0 ||
        key == NULL ||
        message == NULL ||
        message_size == NULL) {
        return GYROJET_CHAT_RECV_ERROR;
    }

    uint32_t network_length = 0;

    int result = gyrojet_chat_recv_all(
        connection,
        &network_length,
        sizeof(network_length)
    );

    if (result != GYROJET_CHAT_RECV_OK)
        return result;

    uint32_t length = ntohl(network_length);

    if (length > GYROJET_CHAT_MAX_MESSAGE_SIZE)
        return GYROJET_CHAT_RECV_ERROR;

    if ((size_t)length > message_capacity)
        return GYROJET_CHAT_RECV_ERROR;

    unsigned char nonce[GYROJET_AEAD_NONCE_SIZE];
    unsigned char ciphertext[
        GYROJET_CHAT_MAX_MESSAGE_SIZE
    ];
    unsigned char tag[GYROJET_AEAD_TAG_SIZE];

    memset(nonce, 0, sizeof(nonce));
    memset(ciphertext, 0, sizeof(ciphertext));
    memset(tag, 0, sizeof(tag));

    result = gyrojet_chat_recv_all(
        connection,
        nonce,
        sizeof(nonce)
    );

    if (result != GYROJET_CHAT_RECV_OK)
        goto cleanup;

    if (length > 0) {
        result = gyrojet_chat_recv_all(
            connection,
            ciphertext,
            (size_t)length
        );

        if (result != GYROJET_CHAT_RECV_OK)
            goto cleanup;
    }

    result = gyrojet_chat_recv_all(
        connection,
        tag,
        sizeof(tag)
    );

    if (result != GYROJET_CHAT_RECV_OK)
        goto cleanup;

    if (gyrojet_aead_decrypt(
            key,
            nonce,
            ciphertext,
            (size_t)length,
            (const unsigned char *)&network_length,
            sizeof(network_length),
            tag,
            message
        ) < 0) {
        result = GYROJET_CHAT_RECV_ERROR;
        goto cleanup;
    }

    *message_size = (size_t)length;

    result = GYROJET_CHAT_RECV_OK;

cleanup:

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

    return result;
}

int gyrojet_chat_run(
    gyrojet_connection_t *connection,
    const unsigned char key[GYROJET_CHAT_KEY_SIZE]
)
{
    if (connection == NULL ||
        connection->fd < 0 ||
        key == NULL) {
        return -1;
    }

    printf("\n");
    printf("##########################################\n");
    printf("#         GyroJett-OneShot2 Chat         #\n");
    printf("##########################################\n");
    printf("#                                        #\n");
    printf("# Conversa iniciada.                     #\n");
    printf("# Digite uma mensagem e pressione Enter. #\n");
    printf("# Ctrl+D encerra a conversa.             #\n");
    printf("##########################################\n");

    for (;;) {
        fd_set read_fds;

        FD_ZERO(&read_fds);

        FD_SET(STDIN_FILENO, &read_fds);
        FD_SET(connection->fd, &read_fds);

        int max_fd = connection->fd;

        if (STDIN_FILENO > max_fd)
            max_fd = STDIN_FILENO;

        int result = select(
            max_fd + 1,
            &read_fds,
            NULL,
            NULL,
            NULL
        );

        if (result < 0) {
            if (errno == EINTR)
                continue;

            perror("GyroJett: select");
            return -1;
        }

        /*
         * Primeiro verificamos o socket.
         */
        if (FD_ISSET(
                connection->fd,
                &read_fds
            )) {

            unsigned char message[
                GYROJET_CHAT_MAX_MESSAGE_SIZE + 1
            ];

            size_t message_size = 0;

            result = gyrojet_chat_receive_message(
                connection,
                key,
                message,
                GYROJET_CHAT_MAX_MESSAGE_SIZE,
                &message_size
            );

            if (result == GYROJET_CHAT_RECV_CLOSED) {
                printf(
                    "\nUser encerrou a conversa.\n"
                );

                gyrojet_crypto_secure_zero(
                    message,
                    sizeof(message)
                );

                return 0;
            }

            if (result != GYROJET_CHAT_RECV_OK) {
                fprintf(
                    stderr,
                    "\nGyroJett: mensagem inválida "
                    "ou conexão interrompida.\n"
                );

                gyrojet_crypto_secure_zero(
                    message,
                    sizeof(message)
                );

                return -1;
            }

            message[message_size] = '\0';

            printf(
                "\nUser> %s\n",
                message
            );

            fflush(stdout);

            gyrojet_crypto_secure_zero(
                message,
                sizeof(message)
            );
        }

        /*
         * Agora verificamos o terminal.
         */
        if (FD_ISSET(
                STDIN_FILENO,
                &read_fds
            )) {

            unsigned char message[
                GYROJET_CHAT_MAX_MESSAGE_SIZE
            ];

            memset(
                message,
                0,
                sizeof(message)
            );

            if (fgets(
                    (char *)message,
                    sizeof(message),
                    stdin
                ) == NULL) {

                printf(
                    "\nEncerrando a conversa...\n"
                );

                shutdown(
                    connection->fd,
                    SHUT_WR
                );

                gyrojet_crypto_secure_zero(
                    message,
                    sizeof(message)
                );

                return 0;
            }

            size_t message_size = strlen(
                (char *)message
            );

            if (message_size > 0 &&
                message[message_size - 1] == '\n') {

                message[message_size - 1] = '\0';
                message_size--;
            }

            if (message_size == 0) {
                gyrojet_crypto_secure_zero(
                    message,
                    sizeof(message)
                );

                continue;
            }

            if (gyrojet_chat_send_message(
                    connection,
                    key,
                    message,
                    message_size
                ) < 0) {

                fprintf(
                    stderr,
                    "GyroJett: falha ao enviar mensagem.\n"
                );

                gyrojet_crypto_secure_zero(
                    message,
                    sizeof(message)
                );

                return -1;
            }

            gyrojet_crypto_secure_zero(
                message,
                sizeof(message)
            );
        }
    }
}
