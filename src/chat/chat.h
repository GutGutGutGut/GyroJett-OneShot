#ifndef GYROJET_CHAT_H
#define GYROJET_CHAT_H

#include "../network/connection.h"

#define GYROJET_CHAT_KEY_SIZE 32
#define GYROJET_CHAT_MAX_MESSAGE_SIZE 4096

int gyrojet_chat_run(
    gyrojet_connection_t *connection,
    const unsigned char key[GYROJET_CHAT_KEY_SIZE]
);

#endif
