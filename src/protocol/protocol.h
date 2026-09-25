#ifndef GYROJET_PROTOCOL_H
#define GYROJET_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#include "frame.h"
#include "../network/connection.h"

#define GYROJET_PROTOCOL_KEY_SIZE 32U

typedef struct {
    gyrojet_connection_t *connection;
    unsigned char key[GYROJET_PROTOCOL_KEY_SIZE];
    uint64_t send_sequence;
    uint64_t receive_sequence;
} gyrojet_protocol_session_t;

int gyrojet_protocol_session_init(
    gyrojet_protocol_session_t *session,
    gyrojet_connection_t *connection,
    const unsigned char key[GYROJET_PROTOCOL_KEY_SIZE]
);

void gyrojet_protocol_session_clear(
    gyrojet_protocol_session_t *session
);

int gyrojet_protocol_send(
    gyrojet_protocol_session_t *session,
    uint8_t type,
    const unsigned char *payload,
    size_t payload_size
);

/*
 * Return values:
 *   0  frame received
 *   1  clean peer close before the next frame
 *  -1 protocol/I/O/crypto error
 */
int gyrojet_protocol_receive(
    gyrojet_protocol_session_t *session,
    gyrojet_frame_header_t *header,
    unsigned char *payload,
    size_t payload_capacity,
    size_t *payload_size
);

#endif
