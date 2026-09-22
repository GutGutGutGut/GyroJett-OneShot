#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "crypto.h"

#define TOR_HOST "127.0.0.1"
#define TOR_PORT 9050
#define BUFFER_SIZE 65536

#define PKT_MSG       1
#define PKT_FILE      2
#define PKT_FILE_DATA 3
#define PKT_FILE_END  4
#define PKT_QUIT      5

typedef struct {
    int sock;
    volatile int running;
} connection_t;

/* --------------------------------------------------------- */
/* Utilidades                                                 */
/* --------------------------------------------------------- */

static int send_all(int sock, const void *data, size_t len)
{
    const char *p = data;

    while (len > 0) {
        ssize_t n = send(sock, p, len, 0);

        if (n <= 0)
            return -1;

        p += n;
        len -= n;
    }

    return 0;
}

static int recv_all(int sock, void *data, size_t len)
{
    char *p = data;

    while (len > 0) {
        ssize_t n = recv(sock, p, len, 0);

        if (n <= 0)
            return -1;

        p += n;
        len -= n;
    }

    return 0;
}

static void print_progress(uint64_t current, uint64_t total)
{
    int percent = 0;

    if (total > 0)
        percent = (int)((current * 100) / total);

    int bars = percent / 5;

    printf("\r[");

    for (int i = 0; i < 20; i++)
        putchar(i < bars ? '#' : ' ');

    printf("] %3d%%", percent);
    fflush(stdout);
}

/* --------------------------------------------------------- */
/* Inteiros em formato de rede                               */
/* --------------------------------------------------------- */

static uint64_t htonll(uint64_t value)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ((uint64_t)htonl(value & 0xffffffff) << 32) |
           htonl(value >> 32);
#else
    return value;
#endif
}

static uint64_t ntohll(uint64_t value)
{
    return htonll(value);
}

/* --------------------------------------------------------- */
/* SOCKS5                                                     */
/* --------------------------------------------------------- */

static int connect_tor(const char *host, uint16_t port)
{
    int sock;
    struct sockaddr_in addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock < 0) {
        perror("socket");
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(TOR_PORT);
    inet_pton(AF_INET, TOR_HOST, &addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect Tor");
        close(sock);
        return -1;
    }

    /* SOCKS5 greeting */
    unsigned char greeting[] = {
        0x05,
        0x01,
        0x00
    };

    if (send_all(sock, greeting, sizeof(greeting)) < 0)
        goto error;

    unsigned char response[2];

    if (recv_all(sock, response, 2) < 0)
        goto error;

    if (response[0] != 0x05 || response[1] != 0x00) {
        fprintf(stderr, "Tor SOCKS5 recusou conexão.\n");
        goto error;
    }

    /* Resolve o hostname como domínio pelo próprio Tor */
    size_t host_len = strlen(host);

    if (host_len > 255) {
        fprintf(stderr, "Hostname muito grande.\n");
        goto error;
    }

    unsigned char request[4 + 1 + 255 + 2];

    request[0] = 0x05; /* version */
    request[1] = 0x01; /* CONNECT */
    request[2] = 0x00;
    request[3] = 0x03; /* DOMAINNAME */

    request[4] = (unsigned char)host_len;

    memcpy(&request[5], host, host_len);

    uint16_t net_port = htons(port);
    memcpy(&request[5 + host_len], &net_port, 2);

    size_t request_len = 7 + host_len;

    if (send_all(sock, request, request_len) < 0)
        goto error;

    unsigned char header[4];

    if (recv_all(sock, header, 4) < 0)
        goto error;

    if (header[0] != 0x05 || header[1] != 0x00) {
        fprintf(stderr, "Tor não conseguiu conectar ao destino.\n");
        goto error;
    }

    /* Consumir endereço retornado pelo SOCKS5 */
    size_t addr_len;

    if (header[3] == 0x01)
        addr_len = 4;
    else if (header[3] == 0x03) {
        unsigned char len;

        if (recv_all(sock, &len, 1) < 0)
            goto error;

        addr_len = len;
    }
    else if (header[3] == 0x04)
        addr_len = 16;
    else
        goto error;

    unsigned char *addr_buf = malloc(addr_len + 2);

    if (!addr_buf)
        goto error;

    if (recv_all(sock, addr_buf, addr_len + 2) < 0) {
        free(addr_buf);
        goto error;
    }

    free(addr_buf);

    printf("Tor: conectado a %s:%u\n", host, port);

    return sock;

error:
    close(sock);
    return -1;
}

/* --------------------------------------------------------- */
/* Envio de mensagem                                          */
/* --------------------------------------------------------- */

static int send_message(int sock, const char *msg)
{
    uint8_t type = PKT_MSG;
    uint32_t len = (uint32_t)strlen(msg);
    uint32_t net_len = htonl(len);

    if (send_all(sock, &type, 1) < 0)
        return -1;

    if (send_all(sock, &net_len, 4) < 0)
        return -1;

    if (send_all(sock, msg, len) < 0)
        return -1;

    return 0;
}

/* --------------------------------------------------------- */
/* Envio de arquivo                                           */
/* --------------------------------------------------------- */

static int send_file(int sock, const char *path)
{
    FILE *file = fopen(path, "rb");

    if (!file) {
        perror("fopen");
        return -1;
    }

    struct stat st;

    if (stat(path, &st) < 0) {
        perror("stat");
        fclose(file);
        return -1;
    }

    const char *filename = strrchr(path, '/');

    if (filename)
        filename++;
    else
        filename = path;

    uint16_t name_len = (uint16_t)strlen(filename);
    uint16_t net_name_len = htons(name_len);

    uint64_t size = (uint64_t)st.st_size;
    uint64_t net_size = htonll(size);

    uint8_t type = PKT_FILE;

    if (send_all(sock, &type, 1) < 0 ||
        send_all(sock, &net_name_len, 2) < 0 ||
        send_all(sock, &net_size, 8) < 0 ||
        send_all(sock, filename, name_len) < 0) {

        fclose(file);
        return -1;
    }

    char buffer[BUFFER_SIZE];
    uint64_t sent = 0;

    printf("Enviando %s\n", filename);

    while (sent < size) {

        size_t want = sizeof(buffer);

        if (size - sent < want)
            want = (size_t)(size - sent);

        size_t n = fread(buffer, 1, want, file);

        if (n == 0)
            break;

        uint8_t data_type = PKT_FILE_DATA;
        uint32_t chunk_len = htonl((uint32_t)n);

        if (send_all(sock, &data_type, 1) < 0 ||
            send_all(sock, &chunk_len, 4) < 0 ||
            send_all(sock, buffer, n) < 0) {

            fclose(file);
            return -1;
        }
        sent += n;

        print_progress(sent, size);
    }

    printf("\n");

    fclose(file);

    uint8_t end = PKT_FILE_END;

    if (send_all(sock, &end, 1) < 0)
        return -1;

    printf("Arquivo enviado: %s (%llu bytes)\n",
           filename,
           (unsigned long long)sent);

    return 0;
}

/* --------------------------------------------------------- */
/* Recepção                                                    */
/* --------------------------------------------------------- */

static void receive_message(int sock)
{
    uint32_t net_len;

    if (recv_all(sock, &net_len, 4) < 0)
        return;

    uint32_t len = ntohl(net_len);

    if (len > 16 * 1024 * 1024) {
        fprintf(stderr, "\nMensagem muito grande.\n");
        return;
    }

    char *msg = malloc(len + 1);

    if (!msg)
        return;

    if (recv_all(sock, msg, len) < 0) {
        free(msg);
        return;
    }

    msg[len] = '\0';

    printf("\r< %s\n> ", msg);
    fflush(stdout);

    free(msg);
}

static FILE *incoming_file = NULL;
static uint64_t incoming_size = 0;
static uint64_t incoming_received = 0;
static char incoming_name[512];

static void receive_file_begin(int sock)
{
    uint16_t net_name_len;
    uint64_t net_size;

    if (recv_all(sock, &net_name_len, 2) < 0)
        return;

    if (recv_all(sock, &net_size, 8) < 0)
        return;

    uint16_t name_len = ntohs(net_name_len);

    if (name_len >= sizeof(incoming_name))
        return;

    if (recv_all(sock, incoming_name, name_len) < 0)
        return;

    incoming_name[name_len] = '\0';

    incoming_size = ntohll(net_size);
    incoming_received = 0;

    incoming_file = fopen(incoming_name, "wb");

    if (!incoming_file) {
        perror("fopen");
        return;
    }

    printf("\nRecebendo %s\n", incoming_name);
}

static void receive_file_data(int sock)
{
    uint32_t net_len;

    if (recv_all(sock, &net_len, 4) < 0)
        return;

    uint32_t len = ntohl(net_len);

    char *buffer = malloc(len);

    if (!buffer)
        return;

    if (recv_all(sock, buffer, len) < 0) {
        free(buffer);
        return;
    }

    if (incoming_file)
        fwrite(buffer, 1, len, incoming_file);

    incoming_received += len;

    print_progress(incoming_received, incoming_size);

    free(buffer);
}

static void receive_file_end(void)
{
    if (incoming_file) {
        fclose(incoming_file);
        incoming_file = NULL;
    }

    printf("\n< %s recebido (%llu bytes)\n",
           incoming_name,
           (unsigned long long)incoming_received);

    incoming_size = 0;
    incoming_received = 0;
}

/* --------------------------------------------------------- */
/* Thread de recepção                                         */
/* --------------------------------------------------------- */

static void *receiver_thread(void *arg)
{
    connection_t *conn = arg;

    while (conn->running) {

        uint8_t type;

        ssize_t n = recv(conn->sock, &type, 1, 0);

        if (n <= 0) {
            conn->running = 0;
            break;
        }

        switch (type) {

        case PKT_MSG:
            receive_message(conn->sock);
            break;

        case PKT_FILE:
            receive_file_begin(conn->sock);
            break;

        case PKT_FILE_DATA:
            receive_file_data(conn->sock);
            break;

        case PKT_FILE_END:
            receive_file_end();
            break;

        case PKT_QUIT:
            printf("\n< Peer desconectou.\n");
            conn->running = 0;
            break;

        default:
            fprintf(stderr, "\nPacote desconhecido: %u\n", type);
            conn->running = 0;
            break;
        }
    }

    return NULL;
}

/* --------------------------------------------------------- */
/* Chat                                                       */
/* --------------------------------------------------------- */

static void chat(int sock)
{
    connection_t conn = {
        .sock = sock,
        .running = 1
    };

    pthread_t thread;

    if (pthread_create(&thread, NULL, receiver_thread, &conn) != 0) {
        perror("pthread_create");
        return;
    }

    printf("\nGyroJett-OneShot conectado.\n");
    printf("Comandos:\n");
    printf("  /send arquivo\n");
    printf("  /quit\n\n");

    char input[4096];

    while (conn.running) {

        printf("> ");
        fflush(stdout);

        if (!fgets(input, sizeof(input), stdin))
            break;

        input[strcspn(input, "\n")] = '\0';

        if (strlen(input) == 0)
            continue;

        if (strcmp(input, "/quit") == 0) {

            uint8_t type = PKT_QUIT;
            send_all(sock, &type, 1);

            conn.running = 0;
            shutdown(sock, SHUT_RDWR);
            break;
        }

        if (strncmp(input, "/send ", 6) == 0) {

            const char *path = input + 6;

            if (strlen(path) == 0) {
                printf("Uso: /send arquivo\n");
                continue;
            }

            if (send_file(sock, path) < 0)
                printf("Erro ao enviar arquivo.\n");

            continue;
        }

        if (send_message(sock, input) < 0) {
            printf("Erro ao enviar mensagem.\n");
            break;
        }
    }

    conn.running = 0;

    shutdown(sock, SHUT_RDWR);
    pthread_join(thread, NULL);
}

/* --------------------------------------------------------- */
/* Server                                                      */
/* --------------------------------------------------------- */

static int server_socket(uint16_t port)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock < 0) {
        perror("socket");
        return -1;
    }

    int yes = 1;

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = htons(port)
    };

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }

    if (listen(sock, 1) < 0) {
        perror("listen");
        close(sock);
        return -1;
    }

    return sock;
}

/* --------------------------------------------------------- */
/* Main                                                        */
/* --------------------------------------------------------- */

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("Uso:\n");
        printf("  %s server porta Recomend:4242\n", argv[0]);
        printf("  %s connect endereco.onion porta\n", argv[0]);
        return 1;
    }

    if (crypto_init() < 0) {
        fprintf(stderr, "Erro ao inicializar GPGME.\n");
        return 1;
    }

    int sock = -1;

    if (strcmp(argv[1], "server") == 0) {

        if (argc != 3) {
            fprintf(stderr, "Uso: %s server port EX:4242\n", argv[0]);
            return 1;
        }

        uint16_t port = atoi(argv[2]);

        int server = server_socket(port);

        if (server < 0)
            return 1;

        printf("GyroJett-OneShot server\n");
        printf("Escutando na porta %u...\n", port);

        struct sockaddr_in client;
        socklen_t client_len = sizeof(client);

        sock = accept(
            server,
            (struct sockaddr *)&client,
            &client_len
        );

        close(server);

        if (sock < 0) {
            perror("accept");
            return 1;
        }

        printf("Peer conectado.\n");
    }

    else if (strcmp(argv[1], "connect") == 0) {

        if (argc != 4) {
            fprintf(stderr,
                    "Uso: %s connect endereco.onion porta\n",
                    argv[0]);
            return 1;
        }

        const char *host = argv[2];
        uint16_t port = atoi(argv[3]);

        sock = connect_tor(host, port);

        if (sock < 0)
            return 1;
    }

    else {
        fprintf(stderr, "Unknow Comand.\n");
        return 1;
    }

    chat(sock);

    close(sock);

    return 0;
}
