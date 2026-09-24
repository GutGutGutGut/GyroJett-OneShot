#include "core.h"

#include <signal.h>

#include "../cli/cli.h"
#include "../crypto/crypto.h"

int gyrojet_core_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
        return -1;

    if (gyrojet_crypto_init() != 0)
        return -1;

    int result = gyrojet_cli_run();

    gyrojet_crypto_cleanup();

    return result;
}
