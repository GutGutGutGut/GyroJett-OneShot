#ifndef GYROJET_PROTOCOL_FRAME_H
#define GYROJET_PROTOCOL_FRAME_H

#include <stddef.h>
#include <stdint.h>

#define GYROJET_PROTOCOL_MAGIC 0x474A3250U /* "GJ2P" */
#define GYROJET_PROTOCOL_VERSION 1U

#define GYROJET_PROTOCOL_HEADER_SIZE 20U
#define GYROJET_PROTOCOL_NONCE_SIZE 12U
#define GYROJET_PROTOCOL_TAG_SIZE 16U

#define GYROJET_PROTOCOL_MAX_PAYLOAD_SIZE (60U * 1024U)
#define GYROJET_PROTOCOL_MAX_FRAME_SIZE \
    (GYROJET_PROTOCOL_HEADER_SIZE + \
     GYROJET_PROTOCOL_NONCE_SIZE + \
     GYROJET_PROTOCOL_MAX_PAYLOAD_SIZE + \
     GYROJET_PROTOCOL_TAG_SIZE)

typedef enum {
    GYROJET_FRAME_HELLO = 1,
    GYROJET_FRAME_HANDSHAKE = 2,
    GYROJET_FRAME_AUTH = 3,
    GYROJET_FRAME_TEXT = 4,
    GYROJET_FRAME_ACK = 5,
    GYROJET_FRAME_FILE_OFFER = 6,
    GYROJET_FRAME_FILE_ACCEPT = 7,
    GYROJET_FRAME_FILE_CHUNK = 8,
    GYROJET_FRAME_FILE_FINISH = 9,
    GYROJET_FRAME_FILE_CANCEL = 10,
    GYROJET_FRAME_CLOSE = 11,
    GYROJET_FRAME_ERROR = 12
} gyrojet_frame_type_t;

typedef struct {
    uint8_t version;
    uint8_t type;
    uint16_t flags;
    uint64_t sequence;
    uint32_t payload_size;
} gyrojet_frame_header_t;

int gyrojet_frame_header_encode(
    const gyrojet_frame_header_t *header,
    unsigned char output[GYROJET_PROTOCOL_HEADER_SIZE]
);

int gyrojet_frame_header_decode(
    const unsigned char input[GYROJET_PROTOCOL_HEADER_SIZE],
    gyrojet_frame_header_t *header
);

int gyrojet_frame_type_valid(uint8_t type);

#endif
