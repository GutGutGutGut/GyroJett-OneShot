#define _POSIX_C_SOURCE 200809L

#include "connection.h"

#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

int gyrojet_connection_send(
    gyrojet_connection_t *connection,
    const void *data,
    size_t size
)
{
    if (connection == NULL || connection->fd < 0)
        return -1;

    if (data == NULL && size > 0)
        return -1;

    const unsigned char *buffer = data;
    size_t sent = 0;

    while (sent < size) {
        ssize_t result = send(
            connection->fd,
            buffer + sent,
            size - sent,
            0
        );

        if (result < 0) {
            if (errno == EINTR)
                continue;

            return -1;
        }

        if (result == 0)
            return -1;

        sent += (size_t)result;
    }

    return 0;
}

ssize_t gyrojet_connection_recv(
    gyrojet_connection_t *connection,
    void *buffer,
    size_t size
)
{
    if (connection == NULL || connection->fd < 0)
        return -1;

    if (buffer == NULL && size > 0)
        return -1;

    for (;;) {
        ssize_t result = recv(
            connection->fd,
            buffer,
            size,
            0
        );

        if (result < 0 && errno == EINTR)
            continue;

        return result;
    }
}

void gyrojet_connection_close(
    gyrojet_connection_t *connection
)
{
    if (connection == NULL)
        return;

    if (connection->fd >= 0) {
        close(connection->fd);
        connection->fd = -1;
    }
}
