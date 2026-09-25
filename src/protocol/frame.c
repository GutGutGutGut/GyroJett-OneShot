#include "frame.h"

#include <string.h>

static void put_u16(unsigned char *out, uint16_t value)
{
    out[0] = (unsigned char)(value >> 8);
    out[1] = (unsigned char)value;
}

static void put_u32(unsigned char *out, uint32_t value)
{
    out[0] = (unsigned char)(value >> 24);
    out[1] = (unsigned char)(value >> 16);
    out[2] = (unsigned char)(value >> 8);
    out[3] = (unsigned char)value;
}

static void put_u64(unsigned char *out, uint64_t value)
{
    for (size_t i = 0; i < sizeof(value); ++i)
        out[7U - i] = (unsigned char)(value >> (i * 8U));
}

static uint16_t get_u16(const unsigned char *in)
{
    return (uint16_t)(((uint16_t)in[0] << 8) | in[1]);
}

static uint32_t get_u32(const unsigned char *in)
{
    return ((uint32_t)in[0] << 24) |
           ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) |
           (uint32_t)in[3];
}

static uint64_t get_u64(const unsigned char *in)
{
    uint64_t value = 0;

    for (size_t i = 0; i < sizeof(value); ++i)
        value = (value << 8U) | in[i];

    return value;
}

int gyrojet_frame_type_valid(uint8_t type)
{
    return type >= GYROJET_FRAME_HELLO &&
           type <= GYROJET_FRAME_ERROR;
}

int gyrojet_frame_header_encode(
    const gyrojet_frame_header_t *header,
    unsigned char output[GYROJET_PROTOCOL_HEADER_SIZE]
)
{
    if (header == NULL || output == NULL)
        return -1;

    if (header->version != GYROJET_PROTOCOL_VERSION ||
        !gyrojet_frame_type_valid(header->type) ||
        header->flags != 0 ||
        header->payload_size > GYROJET_PROTOCOL_MAX_PAYLOAD_SIZE) {
        return -1;
    }

    put_u32(output, GYROJET_PROTOCOL_MAGIC);
    output[4] = header->version;
    output[5] = header->type;
    put_u16(output + 6, header->flags);
    put_u64(output + 8, header->sequence);
    put_u32(output + 16, header->payload_size);

    return 0;
}

int gyrojet_frame_header_decode(
    const unsigned char input[GYROJET_PROTOCOL_HEADER_SIZE],
    gyrojet_frame_header_t *header
)
{
    if (input == NULL || header == NULL)
        return -1;

    if (get_u32(input) != GYROJET_PROTOCOL_MAGIC)
        return -1;

    header->version = input[4];
    header->type = input[5];
    header->flags = get_u16(input + 6);
    header->sequence = get_u64(input + 8);
    header->payload_size = get_u32(input + 16);

    if (header->version != GYROJET_PROTOCOL_VERSION ||
        !gyrojet_frame_type_valid(header->type) ||
        header->flags != 0 ||
        header->payload_size > GYROJET_PROTOCOL_MAX_PAYLOAD_SIZE) {
        memset(header, 0, sizeof(*header));
        return -1;
    }

    return 0;
}
