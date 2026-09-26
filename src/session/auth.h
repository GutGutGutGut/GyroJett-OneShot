#ifndef GYROJET_SESSION_AUTH_H
#define GYROJET_SESSION_AUTH_H

#include "../protocol/protocol.h"

#define GYROJET_AUTH_NONCE_SIZE 32
#define GYROJET_AUTH_MAC_SIZE 32

typedef enum {
    GYROJET_AUTH_CLIENT = 1,
    GYROJET_AUTH_SERVER = 2
} gyrojet_auth_role_t;

int gyrojet_session_authenticate(
    gyrojet_protocol_t *protocol,
    gyrojet_auth_role_t role
);

#endif
