#define _POSIX_C_SOURCE 200809L

#include "auth.h"

#include "../crypto/crypto.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define GYROJET_AUTH_DOMAIN \
    "GyroJett-OneShot2 session authentication v1"

#define GYROJET_AUTH_HELLO_SIZE \
    GYROJET_AUTH_NONCE_SIZE

#define GYROJET_AUTH_PROOF_SIZE \
    GYROJET_AUTH_MAC_SIZE

#define GYROJET_AUTH_MAX_TRANSCRIPT_SIZE \
    (sizeof(GYROJET_AUTH_DOMAIN) - 1 + \
     1 + \
     GYROJET_AUTH_NONCE_SIZE + \
     GYROJET_AUTH_NONCE_SIZE)

enum {
    GYROJET_AUTH_PROOF_CLIENT = 0x01,
    GYROJET_AUTH_PROOF_SERVER = 0x02
};

static int gyrojet_auth_hmac(
    const unsigned char key[GYROJET_PROTOCOL_KEY_SIZE],
    const unsigned char *data,
    size_t data_size,
    unsigned char output[GYROJET_AUTH_MAC_SIZE]
)
{
    if (key == NULL ||
        data == NULL ||
        output == NULL) {
        return -1;
    }

    EVP_MAC *mac = EVP_MAC_fetch(
        NULL,
        "HMAC",
        NULL
    );

    if (mac == NULL)
        return -1;

    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);

    if (ctx == NULL) {
        EVP_MAC_free(mac);
        return -1;
    }

    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_utf8_string(
        "digest",
        "SHA256",
        0
    );

    params[1] = OSSL_PARAM_construct_end();

    int result = -1;

    if (EVP_MAC_init(
            ctx,
            key,
            GYROJET_PROTOCOL_KEY_SIZE,
            params
        ) != 1) {
        goto cleanup;
    }

    if (EVP_MAC_update(
            ctx,
            data,
            data_size
        ) != 1) {
        goto cleanup;
    }

    size_t output_size = 0;

    if (EVP_MAC_final(
            ctx,
            output,
            &output_size,
            GYROJET_AUTH_MAC_SIZE
        ) != 1) {
        goto cleanup;
    }

    if (output_size != GYROJET_AUTH_MAC_SIZE)
        goto cleanup;

    result = 0;

cleanup:

    if (result != 0) {
        gyrojet_crypto_secure_zero(
            output,
            GYROJET_AUTH_MAC_SIZE
        );
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);

    return result;
}

static int gyrojet_auth_build_proof(
    const gyrojet_protocol_t *protocol,
    unsigned char proof_role,
    const unsigned char client_nonce[
        GYROJET_AUTH_NONCE_SIZE
    ],
    const unsigned char server_nonce[
        GYROJET_AUTH_NONCE_SIZE
    ],
    unsigned char proof[
        GYROJET_AUTH_MAC_SIZE
    ]
)
{
    if (protocol == NULL ||
        client_nonce == NULL ||
        server_nonce == NULL ||
        proof == NULL) {
        return -1;
    }

    unsigned char transcript[
        GYROJET_AUTH_MAX_TRANSCRIPT_SIZE
    ];

    memset(
        transcript,
        0,
        sizeof(transcript)
    );

    size_t offset = 0;

    memcpy(
        transcript + offset,
        GYROJET_AUTH_DOMAIN,
        sizeof(GYROJET_AUTH_DOMAIN) - 1
    );

    offset += sizeof(GYROJET_AUTH_DOMAIN) - 1;

    transcript[offset++] = proof_role;

    memcpy(
        transcript + offset,
        client_nonce,
        GYROJET_AUTH_NONCE_SIZE
    );

    offset += GYROJET_AUTH_NONCE_SIZE;

    memcpy(
        transcript + offset,
        server_nonce,
        GYROJET_AUTH_NONCE_SIZE
    );

    offset += GYROJET_AUTH_NONCE_SIZE;

    int result = gyrojet_auth_hmac(
        protocol->key,
        transcript,
        offset,
        proof
    );

    gyrojet_crypto_secure_zero(
        transcript,
        sizeof(transcript)
    );

    return result;
}

static int gyrojet_auth_send_hello(
    gyrojet_protocol_t *protocol,
    const unsigned char nonce[
        GYROJET_AUTH_NONCE_SIZE
    ]
)
{
    return gyrojet_protocol_send(
        protocol,
        GYROJET_FRAME_HELLO,
        nonce,
        GYROJET_AUTH_HELLO_SIZE
    );
}

static int gyrojet_auth_receive_hello(
    gyrojet_protocol_t *protocol,
    unsigned char nonce[
        GYROJET_AUTH_NONCE_SIZE
    ]
)
{
    gyrojet_frame_header_t header;
    size_t payload_size = 0;

    int result = gyrojet_protocol_receive(
        protocol,
        &header,
        nonce,
        GYROJET_AUTH_NONCE_SIZE,
        &payload_size
    );

    if (result != 0)
        return -1;

    if (header.type != GYROJET_FRAME_HELLO)
        return -1;

    if (payload_size != GYROJET_AUTH_HELLO_SIZE)
        return -1;

    return 0;
}

static int gyrojet_auth_send_proof(
    gyrojet_protocol_t *protocol,
    const unsigned char proof[
        GYROJET_AUTH_MAC_SIZE
    ]
)
{
    return gyrojet_protocol_send(
        protocol,
        GYROJET_FRAME_AUTH,
        proof,
        GYROJET_AUTH_PROOF_SIZE
    );
}

static int gyrojet_auth_receive_proof(
    gyrojet_protocol_t *protocol,
    unsigned char proof[
        GYROJET_AUTH_MAC_SIZE
    ]
)
{
    gyrojet_frame_header_t header;
    size_t payload_size = 0;

    int result = gyrojet_protocol_receive(
        protocol,
        &header,
        proof,
        GYROJET_AUTH_MAC_SIZE,
        &payload_size
    );

    if (result != 0)
        return -1;

    if (header.type != GYROJET_FRAME_AUTH)
        return -1;

    if (payload_size != GYROJET_AUTH_PROOF_SIZE)
        return -1;

    return 0;
}

static int gyrojet_auth_client(
    gyrojet_protocol_t *protocol
)
{
    unsigned char client_nonce[
        GYROJET_AUTH_NONCE_SIZE
    ];

    unsigned char server_nonce[
        GYROJET_AUTH_NONCE_SIZE
    ];

    unsigned char expected_proof[
        GYROJET_AUTH_MAC_SIZE
    ];

    unsigned char received_proof[
        GYROJET_AUTH_MAC_SIZE
    ];

    memset(
        client_nonce,
        0,
        sizeof(client_nonce)
    );

    memset(
        server_nonce,
        0,
        sizeof(server_nonce)
    );

    memset(
        expected_proof,
        0,
        sizeof(expected_proof)
    );

    memset(
        received_proof,
        0,
        sizeof(received_proof)
    );

    int result = -1;

    if (gyrojet_crypto_random(
            client_nonce,
            sizeof(client_nonce)
        ) < 0) {
        goto cleanup;
    }

    if (gyrojet_auth_send_hello(
            protocol,
            client_nonce
        ) < 0) {
        goto cleanup;
    }

    if (gyrojet_auth_receive_hello(
            protocol,
            server_nonce
        ) < 0) {
        goto cleanup;
    }

    /*
     * Prova de posse do segredo pelo cliente.
     */
    if (gyrojet_auth_build_proof(
            protocol,
            GYROJET_AUTH_PROOF_CLIENT,
            client_nonce,
            server_nonce,
            expected_proof
        ) < 0) {
        goto cleanup;
    }

    if (gyrojet_auth_send_proof(
            protocol,
            expected_proof
        ) < 0) {
        goto cleanup;
    }

    /*
     * Recebe a prova de posse do servidor.
     */
    if (gyrojet_auth_receive_proof(
            protocol,
            received_proof
        ) < 0) {
        goto cleanup;
    }

    /*
     * O servidor deve provar posse do mesmo segredo
     * usando o papel SERVER e os mesmos nonces.
     */
    if (gyrojet_auth_build_proof(
            protocol,
            GYROJET_AUTH_PROOF_SERVER,
            client_nonce,
            server_nonce,
            expected_proof
        ) < 0) {
        goto cleanup;
    }

    if (CRYPTO_memcmp(
            received_proof,
            expected_proof,
            GYROJET_AUTH_MAC_SIZE
        ) != 0) {
        goto cleanup;
    }

    result = 0;

cleanup:

    gyrojet_crypto_secure_zero(
        client_nonce,
        sizeof(client_nonce)
    );

    gyrojet_crypto_secure_zero(
        server_nonce,
        sizeof(server_nonce)
    );

    gyrojet_crypto_secure_zero(
        expected_proof,
        sizeof(expected_proof)
    );

    gyrojet_crypto_secure_zero(
        received_proof,
        sizeof(received_proof)
    );

    return result;
}

static int gyrojet_auth_server(
    gyrojet_protocol_t *protocol
)
{
    unsigned char client_nonce[
        GYROJET_AUTH_NONCE_SIZE
    ];

    unsigned char server_nonce[
        GYROJET_AUTH_NONCE_SIZE
    ];

    unsigned char expected_proof[
        GYROJET_AUTH_MAC_SIZE
    ];

    unsigned char received_proof[
        GYROJET_AUTH_MAC_SIZE
    ];

    memset(
        client_nonce,
        0,
        sizeof(client_nonce)
    );

    memset(
        server_nonce,
        0,
        sizeof(server_nonce)
    );

    memset(
        expected_proof,
        0,
        sizeof(expected_proof)
    );

    memset(
        received_proof,
        0,
        sizeof(received_proof)
    );

    int result = -1;

    /*
     * Recebe o nonce gerado pelo cliente.
     */
    if (gyrojet_auth_receive_hello(
            protocol,
            client_nonce
        ) < 0) {
        goto cleanup;
    }

    /*
     * Gera um nonce novo para esta sessão.
     */
    if (gyrojet_crypto_random(
            server_nonce,
            sizeof(server_nonce)
        ) < 0) {
        goto cleanup;
    }

    if (gyrojet_auth_send_hello(
            protocol,
            server_nonce
        ) < 0) {
        goto cleanup;
    }

    /*
     * Recebe a prova de posse do cliente.
     */
    if (gyrojet_auth_receive_proof(
            protocol,
            received_proof
        ) < 0) {
        goto cleanup;
    }

    /*
     * Calcula o proof que o cliente deveria ter produzido.
     */
    if (gyrojet_auth_build_proof(
            protocol,
            GYROJET_AUTH_PROOF_CLIENT,
            client_nonce,
            server_nonce,
            expected_proof
        ) < 0) {
        goto cleanup;
    }

    if (CRYPTO_memcmp(
            received_proof,
            expected_proof,
            GYROJET_AUTH_MAC_SIZE
        ) != 0) {
        goto cleanup;
    }

    /*
     * Cliente autenticado.
     *
     * Agora o servidor prova sua própria posse
     * do mesmo segredo.
     */
    if (gyrojet_auth_build_proof(
            protocol,
            GYROJET_AUTH_PROOF_SERVER,
            client_nonce,
            server_nonce,
            expected_proof
        ) < 0) {
        goto cleanup;
    }

    if (gyrojet_auth_send_proof(
            protocol,
            expected_proof
        ) < 0) {
        goto cleanup;
    }

    result = 0;

cleanup:

    gyrojet_crypto_secure_zero(
        client_nonce,
        sizeof(client_nonce)
    );

    gyrojet_crypto_secure_zero(
        server_nonce,
        sizeof(server_nonce)
    );

    gyrojet_crypto_secure_zero(
        expected_proof,
        sizeof(expected_proof)
    );

    gyrojet_crypto_secure_zero(
        received_proof,
        sizeof(received_proof)
    );

    return result;
}

int gyrojet_session_authenticate(
    gyrojet_protocol_t *protocol,
    gyrojet_auth_role_t role
)
{
    if (protocol == NULL ||
        protocol->connection == NULL ||
        protocol->connection->fd < 0) {
        return -1;
    }

    switch (role) {
        case GYROJET_AUTH_CLIENT:
            return gyrojet_auth_client(protocol);

        case GYROJET_AUTH_SERVER:
            return gyrojet_auth_server(protocol);

        default:
            return -1;
    }
}
