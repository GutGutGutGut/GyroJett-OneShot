#include "core.h"

#include "../cli/cli.h"

#include <signal.h>

int gyrojet_core_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    signal(SIGPIPE, SIG_IGN);

    return gyrojet_cli_run();
}
