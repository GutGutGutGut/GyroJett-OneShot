#include "crypto.h"

#include <gpgme.h>
#include <locale.h>
#include <stdio.h>

int crypto_init(void)
{
    setlocale(LC_ALL, "");

    gpgme_check_version(NULL);

    if (gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP) != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "GPGME: engine OpenPGP indisponível\n");
        return -1;
    }

    return 0;
}

void crypto_cleanup(void)
{
}
