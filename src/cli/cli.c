#define _POSIX_C_SOURCE 200809L

#include "cli.h"
#include "../client/client.h"
#include "../server/server.h"
#include "../tor/tor.h"
#include "../session/secret.h"

#include <stdio.h>
#include <string.h>

static int read_choice(void)
{
    char buffer[32];

    printf("Escolha: ");
    fflush(stdout);

    if (fgets(buffer, sizeof(buffer), stdin) == NULL)
        return -1;

    int choice;

    if (sscanf(buffer, "%d", &choice) != 1)
        return -1;

    return choice;
}

int gyrojet_cli_run(void)
{
    for (;;) {
        printf("\n");
        printf("GyroJett-OneShot2\n");
        printf("#--------------------------#\n");
        printf("\n");
        printf("O que você deseja fazer?\n");
        printf("\n");
        printf("  [1] Criar uma sessão\n");
        printf("  [2] Conectar a uma sessão\n");
        printf("  [3] Sair\n");
        printf("\n");

        int choice = read_choice();

        switch (choice) {
            case 1: {
    const unsigned short port = 4242;

    gyrojet_server_t server;
    gyrojet_tor_t tor;

    char secret[GYROJET_SECRET_BUFFER_SIZE];

    printf("\n");
    printf("Criar uma sessão\n");
    printf("----------------\n");
    printf("\n");

    printf("Iniciando servidor...\n");

    if (gyrojet_server_start(&server, port) < 0) {
        fprintf(
            stderr,
            "GyroJett: não foi possível iniciar o servidor.\n"
        );

        break;
    }

    printf("✓ Servidor iniciado.\n");

    printf("Conectando ao Tor...\n");

    if (gyrojet_tor_start(&tor, port) < 0) {
        fprintf(
            stderr,
            "GyroJett: não foi possível criar o Onion Service.\n"
        );

        gyrojet_server_stop(&server);

        break;
    }

    printf("✓ Onion Service criado.\n");

    printf("Gerando segredo da sessão...\n");

    if (gyrojet_secret_generate(
            secret,
            sizeof(secret)
        ) < 0) {

        fprintf(
            stderr,
            "GyroJett: não foi possível gerar o segredo.\n"
        );

        gyrojet_tor_stop(&tor);
        gyrojet_server_stop(&server);

        break;
    }

    printf("✓ Segredo gerado.\n");

    printf("\n");
    printf("#========================================#\n");
    printf("#           SESSÃO CRIADA                #\n");
    printf("#========================================#\n");
    printf("\n");

    printf("Endereço .onion:\n");
    printf("%s\n", tor.onion_address);

    printf("\n");

    printf("Segredo da sessão:\n");
    printf("%s\n", secret);

    printf("\n");
    printf("#========================================#\n");
    printf("\n");

    printf("Aguardando conexão...\n");
    printf("Pressione Ctrl+C para sair.\n");
    printf("\n");

    int result = gyrojet_server_run(&server);

    gyrojet_tor_stop(&tor);
    gyrojet_server_stop(&server);

    if (result < 0)
        fprintf(
            stderr,
            "GyroJett: servidor encerrado com erro.\n"
        );

    break;
}

            case 2: {
                char onion[256];

                printf("\n");
                printf("Conectar a uma sessão\n");
                printf("---------------------\n");
                printf("\n");

                printf("Endereço .onion: ");
                fflush(stdout);

               if (fgets(onion, sizeof(onion), stdin) == NULL) {
                   printf("\nErro ao ler o endereço.\n");
                   break;
                 }

               onion[strcspn(onion, "\n")] = '\0';

                    if (onion[0] == '\0') {
                         printf("Endereço inválido.\n");
                         break;
                    }

                if (gyrojet_client_connect(onion, 4242) < 0)
                    printf("Não foi possível conectar.\n");

               break;
                  }

            case 3:
                printf("\nSaindo...\n");
                return 0;

            default:
                printf("\nOpção inválida.\n");
                break;
        }
    }
}
