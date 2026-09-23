#define _POSIX_C_SOURCE 200809L

#include "tor.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define TOR_CONTROL_HOST "127.0.0.1"
#define TOR_CONTROL_PORT 9051

#define TOR_MAX_REPLY 8192
#define TOR_COOKIE_SIZE 32

static int tor_send(int fd, const char *command)
{
    size_t len = strlen(command);
    size_t sent = 0;

    while (sent < len) {
        ssize_t n = send(fd, command + sent, len - sent, 0);

        if (n < 0) {
            if (errno == EINTR)
                continue;

            return -1;
        }

        sent += (size_t)n;
    }

    return 0;
}

static int tor_read_reply(
    int fd,
    char *buffer,
    size_t size
)
{
    if (buffer == NULL || size < 2)
        return -1;

    size_t used = 0;

    while (used + 1 < size) {
        ssize_t n = recv(
            fd,
            buffer + used,
            1,
            0
        );

        if (n < 0) {
            if (errno == EINTR)
                continue;

            return -1;
        }

        if (n == 0)
            return -1;

        used += (size_t)n;
        buffer[used] = '\0';

        /*
         * As respostas do Tor terminam com:
         *
         *     250 OK\r\n
         *
         * Em respostas multilinha, também pode haver
         * linhas 250- antes do 250 OK final.
         */
        if (used >= 8 &&
            memcmp(
                buffer + used - 8,
                "250 OK\r\n",
                8
            ) == 0) {

            return (int)used;
        }
    }

    return -1;
}

static int tor_connect_control(void)
{
    int fd;
    struct sockaddr_in address;

    fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0)
        return -1;

    memset(&address, 0, sizeof(address));

    address.sin_family = AF_INET;
    address.sin_port = htons(TOR_CONTROL_PORT);

    if (inet_pton(AF_INET, TOR_CONTROL_HOST, &address.sin_addr) != 1) {
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

static int tor_protocol_info(int fd, char *cookie_path, size_t cookie_size)
{
    char reply[TOR_MAX_REPLY];

    if (tor_send(fd, "PROTOCOLINFO 1\r\n") < 0)
        return -1;

    if (tor_read_reply(fd, reply, sizeof(reply)) < 0)
        return -1;

    char *cookie = strstr(reply, "COOKIEFILE=\"");

    if (cookie == NULL)
        return -1;

    cookie += strlen("COOKIEFILE=\"");

    char *end = strchr(cookie, '"');

    if (end == NULL)
        return -1;

    size_t length = (size_t)(end - cookie);

    if (length == 0 || length >= cookie_size)
        return -1;

    memcpy(cookie_path, cookie, length);
    cookie_path[length] = '\0';

    return 0;
}

static int tor_authenticate(int fd, const char *cookie_path)
{
    unsigned char cookie[TOR_COOKIE_SIZE];

    FILE *file = fopen(cookie_path, "rb");

    if (file == NULL) {
        fprintf(stderr,
                "GyroJett: não foi possível abrir o cookie do Tor: %s\n",
                cookie_path);

        return -1;
    }

    size_t read_count = fread(cookie, 1, sizeof(cookie), file);

    fclose(file);

    if (read_count != TOR_COOKIE_SIZE) {
        fprintf(stderr, "GyroJett: cookie do Tor possui tamanho inválido.\n");
        return -1;
    }

    char hex_cookie[TOR_COOKIE_SIZE * 2 + 1];

    for (size_t i = 0; i < TOR_COOKIE_SIZE; ++i) {
        snprintf(
            &hex_cookie[i * 2],
            3,
            "%02x",
            cookie[i]
        );
    }

    hex_cookie[sizeof(hex_cookie) - 1] = '\0';

    char command[128];

    snprintf(
        command,
        sizeof(command),
        "AUTHENTICATE %s\r\n",
        hex_cookie
    );

    if (tor_send(fd, command) < 0)
        return -1;

    char reply[TOR_MAX_REPLY];

    if (tor_read_reply(fd, reply, sizeof(reply)) < 0)
        return -1;

    if (strncmp(reply, "250 OK", 6) != 0) {
        fprintf(stderr,
                "GyroJett: autenticação no Tor falhou:\n%s",
                reply);

        return -1;
    }

    return 0;
}

static int tor_add_onion(
    gyrojet_tor_t *tor,
    unsigned short port
)
{
    char command[256];

    snprintf(
        command,
        sizeof(command),
        "ADD_ONION NEW:ED25519-V3 Flags=DiscardPK Port=%u,127.0.0.1:%u\r\n",
        port,
        port
    );

    if (tor_send(tor->control_fd, command) < 0)
        return -1;

    char reply[TOR_MAX_REPLY];

    if (tor_read_reply(
            tor->control_fd,
            reply,
            sizeof(reply)
        ) < 0) {
        return -1;
    }

    if (strncmp(reply, "250-ServiceID=", 14) != 0) {
        fprintf(stderr,
                "GyroJett: ADD_ONION falhou:\n%s",
                reply);

        return -1;
    }

    char *start = reply + strlen("250-ServiceID=");
    char *end = strstr(start, "\r\n");

    if (end == NULL)
        return -1;

    size_t length = (size_t)(end - start);

    if (length == 0 || length >= sizeof(tor->service_id))
        return -1;

    memcpy(tor->service_id, start, length);
    tor->service_id[length] = '\0';

    if (length != 56) {
    fprintf(
        stderr,
        "GyroJett: ServiceID do Tor possui tamanho inválido.\n"
    );

    return -1;
}


snprintf(
    tor->onion_address,
    sizeof(tor->onion_address),
    "%s.onion",
    tor->service_id
);

    return 0;
}

static int tor_del_onion(gyrojet_tor_t *tor)
{
    if (tor->service_id[0] == '\0')
        return 0;

    char command[128];

    snprintf(
        command,
        sizeof(command),
        "DEL_ONION %s\r\n",
        tor->service_id
    );

    if (tor_send(tor->control_fd, command) < 0)
        return -1;

    char reply[TOR_MAX_REPLY];

    if (tor_read_reply(
            tor->control_fd,
            reply,
            sizeof(reply)
        ) < 0) {
        return -1;
    }

    if (strncmp(reply, "250 OK", 6) != 0)
        return -1;

    tor->service_id[0] = '\0';
    tor->onion_address[0] = '\0';

    return 0;
}

int gyrojet_tor_start(
    gyrojet_tor_t *tor,
    unsigned short port
)
{
    if (tor == NULL)
        return -1;

    memset(tor, 0, sizeof(*tor));

    tor->control_fd = tor_connect_control();

    if (tor->control_fd < 0) {
        fprintf(stderr,
                "GyroJett: não foi possível conectar ao Tor ControlPort %d.\n",
                TOR_CONTROL_PORT);

        return -1;
    }

    char cookie_path[512];

    if (tor_protocol_info(
            tor->control_fd,
            cookie_path,
            sizeof(cookie_path)
        ) < 0) {

        fprintf(stderr,
                "GyroJett: não foi possível obter informações do Tor.\n");

        close(tor->control_fd);
        tor->control_fd = -1;

        return -1;
    }

    if (tor_authenticate(
            tor->control_fd,
            cookie_path
        ) < 0) {

        close(tor->control_fd);
        tor->control_fd = -1;

        return -1;
    }

    if (tor_add_onion(tor, port) < 0) {
        close(tor->control_fd);
        tor->control_fd = -1;

        return -1;
    }

    return 0;
}

int gyrojet_tor_stop(gyrojet_tor_t *tor)
{
    if (tor == NULL)
        return -1;

    if (tor->control_fd < 0)
        return 0;

    if (tor->service_id[0] != '\0')
        tor_del_onion(tor);

    tor_send(tor->control_fd, "QUIT\r\n");

    close(tor->control_fd);

    tor->control_fd = -1;
    tor->service_id[0] = '\0';
    tor->onion_address[0] = '\0';

    return 0;
}
