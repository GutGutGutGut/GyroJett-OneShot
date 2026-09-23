#ifndef GYROJET_CONNECTION_H
#define GYROJET_CONNECTION_H

#include <stddef.h>
#include <sys/types.h>

typedef struct {
    int fd;
} gyrojet_connection_t;

int gyrojet_connection_send(
    gyrojet_connection_t *connection,
    const void *data,
    size_t size
);

ssize_t gyrojet_connection_recv(
    gyrojet_connection_t *connection,
    void *buffer,
    size_t size
);

void gyrojet_connection_close(
    gyrojet_connection_t *connection
);

#endif
