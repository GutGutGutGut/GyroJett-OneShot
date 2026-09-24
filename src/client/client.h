#ifndef GYROJET_CLIENT_H
#define GYROJET_CLIENT_H

#include <stddef.h>

#define GYROJET_CLIENT_SESSION_KEY_SIZE 32

int gyrojet_client_connect(
    const char *onion_address,
    unsigned short port,
    const unsigned char session_key[
        GYROJET_CLIENT_SESSION_KEY_SIZE
    ]
);

#endif
