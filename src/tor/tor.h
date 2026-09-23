#ifndef GYROJET_TOR_H
#define GYROJET_TOR_H

#define GYROJET_TOR_SERVICE_ID_SIZE 57
#define GYROJET_TOR_ONION_ADDRESS_SIZE 64

typedef struct {
    int control_fd;

    char service_id[GYROJET_TOR_SERVICE_ID_SIZE];
    char onion_address[GYROJET_TOR_ONION_ADDRESS_SIZE];

} gyrojet_tor_t;

int gyrojet_tor_start(
    gyrojet_tor_t *tor,
    unsigned short port
);

int gyrojet_tor_stop(
    gyrojet_tor_t *tor
);

#endif
