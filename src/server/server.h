#ifndef GYROJET_SERVER_H
#define GYROJET_SERVER_H

typedef struct {
    int socket_fd;
    unsigned short port;
} gyrojet_server_t;

int gyrojet_server_start(
    gyrojet_server_t *server,
    unsigned short port
);

void gyrojet_server_stop(
    gyrojet_server_t *server
);

int gyrojet_server_run(
    gyrojet_server_t *server
);

#endif
