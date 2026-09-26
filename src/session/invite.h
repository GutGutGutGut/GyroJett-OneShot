#ifndef GYROJET_SESSION_INVITE_H
#define GYROJET_SESSION_INVITE_H

#include <stddef.h>

#define GYROJET_INVITE_PREFIX "gyrojett://v1/"

#define GYROJET_INVITE_MAX_SIZE 256

int gyrojet_invite_create(
    const char *onion_address,
    const char *secret,
    char *output,
    size_t output_size
);

int gyrojet_invite_parse(
    const char *invite,
    char *onion_address,
    size_t onion_size,
    char *secret,
    size_t secret_size
);

int gyrojet_invite_copy_clipboard(
    const char *invite
);

#endif
