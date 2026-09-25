#define _POSIX_C_SOURCE 200809L

#include "protocol.h"

#include "../crypto/aead.h"
#include "../crypto/crypto.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

static int recv_all(
    gyrojet_connection_t *connection,
    void *buffer,
    size_t size,
    int *clean_close
)
{
    if (connection == NULL ||
        buffer == NULL ||
        clean_close == NULL) {
        return -1;
    }

    *clean_close = 0;

    unsigned char *ptr = buffer;
    size_t received = 0;

    while (received < size) {
        ssize_t result = gyrojet_connection_recv(
            connection,
            ptr + received,
            size - received
        );

        if (result < 0)
            return -1;

        if (result == 0) {
            if (received == 0)
                *clean_close = 1;

            return -1;
        }

        received += (size_t)result;
    }

    return 0;
}

static int send_all(
    gyrojet_connection_t *connection,
    const void *buffer,
    size_t size
)
{
    ssize_t result = gyrojet_connection_send(
        connection,
        buffer,
        size
    );

    return result < 0 ? -1 : 0;
}

static void protocol_clear_key(
    unsigned char key[GYROJET_PROTOCOL_KEY_SIZE]
)
{
    gyrojet_crypto_secure_zero(key, GYROJET_PROTOCOL_KEY_SIZE);
}

int gyrojet_protocol_session_init(
    gyrojet_protocol_session_t *session,
    gyrojet_connection_t *connection,
    const unsigned char key[GYROJET_PROTOCOL_KEY_SIZE]
)
{
    if (session == NULL ||
        connection == NULL ||
        connection->fd < 0 ||
        key == NULL) {
        return -1;
    }

    memset(session, 0, sizeof(*session));
    session->connection = connection;
    memcpy(session->key, key, sizeof(session->key));

    return 0;
}

void gyrojet_protocol_session_clear(
    gyrojet_protocol_session_t *session
)
{
    if (session == NULL)
        return;

    protocol_clear_key(session->key);
    session->connection = NULL;
    session->send_sequence = 0;
    session->receive_sequence = 0;
}

int gyrojet_protocol_send(
    gyrojet_protocol_session_t *session,
    uint8_t type,
    const unsigned char *payload,
    size_t payload_size
)
{
    if (session == NULL ||
        session->connection == NULL ||
        session->connection->fd < 0 ||
        (payload == NULL && payload_size != 0)) {
        return -1;
    }

    if (!gyrojet_frame_type_valid(type) ||
        payload_size > GYROJET_PROTOCOL_MAX_PAYLOAD_SIZE) {
        return -1;
    }

    gyrojet_frame_header_t header = {
        .version = GYROJET_PROTOCOL_VERSION,
        .type = type,
        .flags = 0,
        .sequence = session->send_sequence,
        .payload_size = (uint32_t)payload_size
    };

    unsigned char encoded_header[GYROJET_PROTOCOL_HEADER_SIZE];
    unsigned char nonce[GYROJET_PROTOCOL_NONCE_SIZE];
    unsigned char *ciphertext = NULL;
    size_t ciphertext_alloc_size = payload_size == 0 ? 1U : payload_size;
    unsigned char tag[GYROJET_PROTOCOL_TAG_SIZE];

    memset(encoded_header, 0, sizeof(encoded_header));
    memset(nonce, 0, sizeof(nonce));
    ciphertext = malloc(ciphertext_alloc_size);

    if (ciphertext == NULL)
        goto cleanup;

    memset(ciphertext, 0, ciphertext_alloc_size);
    memset(tag, 0, sizeof(tag));

    int result = -1;

    if (gyrojet_frame_header_encode(
            &header,
            encoded_header
        ) < 0) {
        goto cleanup;
    }

    if (gyrojet_crypto_random(nonce, sizeof(nonce)) < 0)
        goto cleanup;

    if (gyrojet_aead_encrypt(
            session->key,
            nonce,
            payload,
            payload_size,
            encoded_header,
            sizeof(encoded_header),
            ciphertext,
            tag
        ) < 0) {
        goto cleanup;
    }

    if (send_all(
            session->connection,
            encoded_header,
            sizeof(encoded_header)
        ) < 0) {
        goto cleanup;
    }

    if (send_all(
            session->connection,
            nonce,
            sizeof(nonce)
        ) < 0) {
        goto cleanup;
    }

    if (payload_size > 0 &&
        send_all(
            session->connection,
            ciphertext,
            payload_size
        ) < 0) {
        goto cleanup;
    }

    if (send_all(
            session->connection,
            tag,
            sizeof(tag)
        ) < 0) {
        goto cleanup;
    }

    if (session->send_sequence == UINT64_MAX)
        goto cleanup;

    ++session->send_sequence;
    result = 0;

cleanup:
    gyrojet_crypto_secure_zero(nonce, sizeof(nonce));
    if (ciphertext != NULL) {
        gyrojet_crypto_secure_zero(ciphertext, ciphertext_alloc_size);
        free(ciphertext);
    }
    gyrojet_crypto_secure_zero(tag, sizeof(tag));
    gyrojet_crypto_secure_zero(encoded_header, sizeof(encoded_header));

    return result;
}

int gyrojet_protocol_receive(
    gyrojet_protocol_session_t *session,
    gyrojet_frame_header_t *header,
    unsigned char *payload,
    size_t payload_capacity,
    size_t *payload_size
)
{
    if (session == NULL ||
        session->connection == NULL ||
        session->connection->fd < 0 ||
        header == NULL ||
        payload_size == NULL ||
        (payload == NULL && payload_capacity != 0)) {
        return -1;
    }

    *payload_size = 0;

    unsigned char encoded_header[GYROJET_PROTOCOL_HEADER_SIZE];
    unsigned char nonce[GYROJET_PROTOCOL_NONCE_SIZE];
    unsigned char *ciphertext = NULL;
    size_t ciphertext_alloc_size = 0;
    unsigned char tag[GYROJET_PROTOCOL_TAG_SIZE];
    int clean_close = 0;

    memset(encoded_header, 0, sizeof(encoded_header));
    memset(nonce, 0, sizeof(nonce));
    memset(tag, 0, sizeof(tag));

    int result = -1;

    if (recv_all(
            session->connection,
            encoded_header,
            sizeof(encoded_header),
            &clean_close
        ) < 0) {
        result = clean_close ? 1 : -1;
        goto cleanup;
    }

    if (gyrojet_frame_header_decode(
            encoded_header,
            header
        ) < 0) {
        goto cleanup;
    }

    if (header->sequence != session->receive_sequence)
        goto cleanup;

    if ((size_t)header->payload_size > payload_capacity)
        goto cleanup;

    ciphertext_alloc_size = header->payload_size == 0 ? 1U : header->payload_size;
    ciphertext = malloc(ciphertext_alloc_size);

    if (ciphertext == NULL)
        goto cleanup;

    memset(ciphertext, 0, ciphertext_alloc_size);

    if (recv_all(
            session->connection,
            nonce,
            sizeof(nonce),
            &clean_close
        ) < 0) {
        goto cleanup;
    }

    if (header->payload_size > 0 &&
        recv_all(
            session->connection,
            ciphertext,
            header->payload_size,
            &clean_close
        ) < 0) {
        goto cleanup;
    }

    if (recv_all(
            session->connection,
            tag,
            sizeof(tag),
            &clean_close
        ) < 0) {
        goto cleanup;
    }

    if (gyrojet_aead_decrypt(
            session->key,
            nonce,
            ciphertext,
            header->payload_size,
            encoded_header,
            sizeof(encoded_header),
            tag,
            payload
        ) < 0) {
        goto cleanup;
    }

    *payload_size = header->payload_size;

    if (session->receive_sequence == UINT64_MAX)
        goto cleanup;

    ++session->receive_sequence;
    result = 0;

cleanup:
    if (result != 0 && result != 1)
        *payload_size = 0;

    gyrojet_crypto_secure_zero(nonce, sizeof(nonce));
    if (ciphertext != NULL) {
        gyrojet_crypto_secure_zero(
            ciphertext,
            ciphertext_alloc_size
        );
        free(ciphertext);
    }
    gyrojet_crypto_secure_zero(tag, sizeof(tag));
    gyrojet_crypto_secure_zero(encoded_header, sizeof(encoded_header));

    return result;
}
