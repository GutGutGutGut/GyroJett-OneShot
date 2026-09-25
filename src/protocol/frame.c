#include "frame.h"

#include <arpa/inet.h>
#include <string.h>

static void gyrojet_write_u64_be(
    unsigned char output[8],
    uint64_t value
)
{
    output[0] = (unsigned char)(value >> 56);
    output[1] = (unsigned char)(value >> 48);
    output[2] = (unsigned char)(value >> 40);
    output[3] = (unsigned char)(value >> 32);
    output[4] = (unsigned char)(value >> 24);
    output[5] = (unsigned char)(value >> 16);
    output[6] = (unsigned char)(value >> 8);
    output[7] = (unsigned char)value;
}

static uint64_t gyrojet_read_u64_be(
    const unsigned char input[8]
)
{
    return
        ((uint64_t)input[0] << 56) |
        ((uint64_t)input[1] << 48) |
        ((uint64_t)input[2] << 40) |
        ((uint64_t)input[3] << 32) |
        ((uint64_t)input[4] << 24) |
        ((uint64_t)input[5] << 16) |
        ((uint64_t)input[6] << 8) |
        (uint64_t)input[7];
}

int gyrojet_frame_type_valid(
    uint8_t type
)
{
    switch (type) {
        case GYROJET_FRAME_HELLO:
        case GYROJET_FRAME_HANDSHAKE:
        case GYROJET_FRAME_AUTH:
        case GYROJET_FRAME_TEXT:
        case GYROJET_FRAME_ACK:
        case GYROJET_FRAME_FILE_OFFER:
        case GYROJET_FRAME_FILE_ACCEPT:
        case GYROJET_FRAME_FILE_CHUNK:
        case GYROJET_FRAME_FILE_FINISH:
        case GYROJET_FRAME_FILE_CANCEL:
        case GYROJET_FRAME_CLOSE:
        case GYROJET_FRAME_ERROR:
            return 1;

        default:
            return 0;
    }
}

int gyrojet_frame_header_encode(
    const gyrojet_frame_header_t *header,
    unsigned char output[GYROJET_PROTOCOL_HEADER_SIZE]
)
{
    if (header == NULL || output == NULL)
        return -1;

    if (header->version != GYROJET_PROTOCOL_VERSION)
        return -1;

    if (!gyrojet_frame_type_valid(header->type))
        return -1;

    if (header->payload_size >
        GYROJET_PROTOCOL_MAX_PAYLOAD_SIZE) {
        return -1;
    }

    const uint32_t magic = htonl(
        GYROJET_PROTOCOL_MAGIC
    );

    const uint16_t flags = htons(
        header->flags
    );

    const uint32_t payload_size = htonl(
        header->payload_size
    );

    memcpy(output, &magic, sizeof(magic));

    output[4] = header->version;
    output[5] = header->type;

    memcpy(
        output + 6,
        &flags,
        sizeof(flags)
    );

    gyrojet_write_u64_be(
        output + 8,
        header->sequence
    );

    memcpy(
        output + 16,
        &payload_size,
        sizeof(payload_size)
    );

    return 0;
}

int gyrojet_frame_header_decode(
    const unsigned char input[GYROJET_PROTOCOL_HEADER_SIZE],
    gyrojet_frame_header_t *header
)
{
    if (input == NULL || header == NULL)
        return -1;

    uint32_t magic;
    uint16_t flags;
    uint32_t payload_size;

    memcpy(
        &magic,
        input,
        sizeof(magic)
    );

    memcpy(
        &flags,
        input + 6,
        sizeof(flags)
    );

    memcpy(
        &payload_size,
        input + 16,
        sizeof(payload_size)
    );

    magic = ntohl(magic);
    flags = ntohs(flags);
    payload_size = ntohl(payload_size);

    if (magic != GYROJET_PROTOCOL_MAGIC)
        return -1;

    if (input[4] != GYROJET_PROTOCOL_VERSION)
        return -1;

    if (!gyrojet_frame_type_valid(input[5]))
        return -1;

    if (payload_size >
        GYROJET_PROTOCOL_MAX_PAYLOAD_SIZE) {
        return -1;
    }

    header->version = input[4];
    header->type = input[5];
    header->flags = flags;
    header->sequence = gyrojet_read_u64_be(
        input + 8
    );
    header->payload_size = payload_size;

    return 0;
}
