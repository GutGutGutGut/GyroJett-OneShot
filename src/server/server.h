#ifndef GYROJET_SERVER_H
#define GYROJET_SERVER_H


#include <stddef.h>

#define GYROJET_SERVER_SESSION_KEY_SIZE 32

typedef struct {
    int socket_fd;
    unsigned short port;
} gyrojet_server_t;

int gyrojet_server_start(
    gyrojet_server_t *server,
    unsigned short port
);

int gyrojet_server_run(
    gyrojet_server_t *server,
    const unsigned char session_key[
        GYROJET_SERVER_SESSION_KEY_SIZE
    ]
);

void gyrojet_server_stop(
    gyrojet_server_t *server
);

#endif
