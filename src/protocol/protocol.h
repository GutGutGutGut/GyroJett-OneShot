#ifndef GYROJET_PROTOCOL_H
#define GYROJET_PROTOCOL_H

#include "../network/connection.h"
#include "frame.h"

#include <stddef.h>
#include <stdint.h>

#define GYROJET_PROTOCOL_KEY_SIZE 32

typedef struct {
    gyrojet_connection_t *connection;

    unsigned char key[GYROJET_PROTOCOL_KEY_SIZE];

    uint64_t send_sequence;
    uint64_t receive_sequence;
} gyrojet_protocol_t;

int gyrojet_protocol_init(
    gyrojet_protocol_t *protocol,
    gyrojet_connection_t *connection,
    const unsigned char key[GYROJET_PROTOCOL_KEY_SIZE]
);

int gyrojet_protocol_send(
    gyrojet_protocol_t *protocol,
    uint8_t type,
    const unsigned char *payload,
    size_t payload_size
);

int gyrojet_protocol_receive(
    gyrojet_protocol_t *protocol,
    gyrojet_frame_header_t *header,
    unsigned char *payload,
    size_t payload_capacity,
    size_t *payload_size
);

void gyrojet_protocol_clear(
    gyrojet_protocol_t *protocol
);

#endif
