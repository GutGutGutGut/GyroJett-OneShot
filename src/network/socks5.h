#ifndef GYROJET_NETWORK_SOCKS5_H
#define GYROJET_NETWORK_SOCKS5_H

#include "connection.h"

int gyrojet_socks5_connect(
    const char *host,
    unsigned short port,
    gyrojet_connection_t *connection
);

#endif
