#ifndef GYROJET_CHAT_H
#define GYROJET_CHAT_H

#include "../network/connection.h"

#define GYROJET_CHAT_KEY_SIZE 32
#define GYROJET_CHAT_MAX_MESSAGE_SIZE 4096

typedef enum {
GYROJET_CHAT_SERVER,
GYROJET_CHAT_CLIENT
} gyrojet_chat_role_t;

int gyrojet_chat_run(
gyrojet_connection_t *connection,
const unsigned char key[GYROJET_CHAT_KEY_SIZE],
gyrojet_chat_role_t role
);

#endif

