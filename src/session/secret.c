#define _POSIX_C_SOURCE 200809L

#include "secret.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

int gyrojet_secret_generate(
    char *output,
    size_t output_size
)
{
    if (output == NULL)
        return -1;

    if (output_size < GYROJET_SECRET_BUFFER_SIZE)
        return -1;

    unsigned char random_data[GYROJET_SECRET_ENTROPY_BYTES];

    int fd = open(
        "/dev/urandom",
        O_RDONLY
    );

    if (fd < 0)
        return -1;

    size_t received = 0;

    while (received < sizeof(random_data)) {
        ssize_t result = read(
            fd,
            random_data + received,
            sizeof(random_data) - received
        );

        if (result < 0) {
            if (errno == EINTR)
                continue;

            close(fd);
            return -1;
        }

        if (result == 0) {
            close(fd);
            return -1;
        }

        received += (size_t)result;
    }

    close(fd);

    size_t output_position = 0;

    for (;;) {
        unsigned int remainder = 0;
        int non_zero = 0;

        for (size_t i = 0; i < sizeof(random_data); ++i) {
            unsigned int value =
                (remainder << 8) | random_data[i];

            random_data[i] =
                (unsigned char)(value / GYROJET_SECRET_ALPHABET_SIZE);

            remainder =
                value % GYROJET_SECRET_ALPHABET_SIZE;

            if (random_data[i] != 0)
                non_zero = 1;
        }

        if (output_position >= output_size - 1)
            return -1;

        output[output_position++] =
            GYROJET_SECRET_ALPHABET[remainder];

        if (!non_zero)
            break;
    }

    output[output_position] = '\0';

    for (size_t i = 0; i < output_position / 2; ++i) {
        char temporary = output[i];

        output[i] =
            output[output_position - 1 - i];

        output[output_position - 1 - i] =
            temporary;
    }

    return 0;
}
