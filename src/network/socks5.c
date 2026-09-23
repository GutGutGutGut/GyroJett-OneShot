#define _POSIX_C_SOURCE 200809L

#include "socks5.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define GYROJET_SOCKS5_HOST "127.0.0.1"
#define GYROJET_SOCKS5_PORT 9050

#define SOCKS5_VERSION 0x05
#define SOCKS5_NO_AUTH 0x00
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_ATYP_DOMAIN 0x03

static int send_all(
    int fd,
    const void *data,
    size_t size
)
{
    const unsigned char *buffer = data;
    size_t sent = 0;

    while (sent < size) {
        ssize_t result = send(
            fd,
            buffer + sent,
            size - sent,
            0
        );

        if (result < 0) {
            if (errno == EINTR)
                continue;

            return -1;
        }

        if (result == 0)
            return -1;

        sent += (size_t)result;
    }

    return 0;
}

static int recv_all(
    int fd,
    void *data,
    size_t size
)
{
    unsigned char *buffer = data;
    size_t received = 0;

    while (received < size) {
        ssize_t result = recv(
            fd,
            buffer + received,
            size - received,
            0
        );

        if (result < 0) {
            if (errno == EINTR)
                continue;

            return -1;
        }

        if (result == 0)
            return -1;

        received += (size_t)result;
    }

    return 0;
}

static int connect_proxy(void)
{
    int fd = socket(
        AF_INET,
        SOCK_STREAM,
        0
    );

    if (fd < 0)
        return -1;

    struct sockaddr_in address;

    memset(&address, 0, sizeof(address));

    address.sin_family = AF_INET;
    address.sin_port = htons(GYROJET_SOCKS5_PORT);

    if (inet_pton(
            AF_INET,
            GYROJET_SOCKS5_HOST,
            &address.sin_addr
        ) != 1) {

        close(fd);
        return -1;
    }

    if (connect(
            fd,
            (struct sockaddr *)&address,
            sizeof(address)
        ) < 0) {

        close(fd);
        return -1;
    }

    return fd;
}

int gyrojet_socks5_connect(
    const char *host,
    unsigned short port,
    gyrojet_connection_t *connection
)
{
    if (host == NULL || connection == NULL)
        return -1;

    connection->fd = -1;

    size_t host_length = strlen(host);

    if (host_length == 0 || host_length > 255)
        return -1;

    int fd = connect_proxy();

    if (fd < 0) {
        fprintf(
            stderr,
            "GyroJett: não foi possível conectar ao Tor SOCKS5.\n"
        );

        return -1;
    }

    /*
     * SOCKS5 greeting:
     *
     * VER = 5
     * NMETHODS = 1
     * METHOD = NO AUTH
     */

    unsigned char greeting[] = {
        SOCKS5_VERSION,
        0x01,
        SOCKS5_NO_AUTH
    };

    if (send_all(
            fd,
            greeting,
            sizeof(greeting)
        ) < 0) {

        close(fd);
        return -1;
    }

    unsigned char greeting_reply[2];

    if (recv_all(
            fd,
            greeting_reply,
            sizeof(greeting_reply)
        ) < 0) {

        close(fd);
        return -1;
    }

    if (greeting_reply[0] != SOCKS5_VERSION ||
        greeting_reply[1] != SOCKS5_NO_AUTH) {

        fprintf(
            stderr,
            "GyroJett: Tor recusou SOCKS5 sem autenticação.\n"
        );

        close(fd);
        return -1;
    }

    /*
     * SOCKS5 CONNECT request using DOMAINNAME.
     *
     * This deliberately sends the .onion hostname
     * to Tor instead of resolving it locally.
     */

    if (host_length > UINT8_MAX) {
        close(fd);
        return -1;
    }

    size_t request_size = 4 + 1 + host_length + 2;

    unsigned char request[4 + 1 + 255 + 2];

    request[0] = SOCKS5_VERSION;
    request[1] = SOCKS5_CMD_CONNECT;
    request[2] = 0x00;
    request[3] = SOCKS5_ATYP_DOMAIN;
    request[4] = (unsigned char)host_length;

    memcpy(
        request + 5,
        host,
        host_length
    );

    uint16_t network_port = htons(port);

    memcpy(
        request + 5 + host_length,
        &network_port,
        sizeof(network_port)
    );

    if (send_all(
            fd,
            request,
            request_size
        ) < 0) {

        close(fd);
        return -1;
    }

    unsigned char response[4];

    if (recv_all(
            fd,
            response,
            sizeof(response)
        ) < 0) {

        close(fd);
        return -1;
    }

    if (response[0] != SOCKS5_VERSION) {
        close(fd);
        return -1;
    }

    if (response[1] != 0x00) {
        fprintf(
            stderr,
            "GyroJett: Tor SOCKS5 CONNECT falhou. Código: 0x%02x\n",
            response[1]
        );

        close(fd);
        return -1;
    }

    /*
     * Consume the BND.ADDR + BND.PORT fields.
     */

    size_t address_size;

    switch (response[3]) {
        case 0x01:
            address_size = 4;
            break;

        case 0x03: {
            unsigned char length;

            if (recv_all(
                    fd,
                    &length,
                    sizeof(length)
                ) < 0) {

                close(fd);
                return -1;
            }

            address_size = length;
            break;
        }

        case 0x04:
            address_size = 16;
            break;

        default:
            close(fd);
            return -1;
    }

    unsigned char address_buffer[256];

    if (address_size > sizeof(address_buffer)) {
        close(fd);
        return -1;
    }

    if (recv_all(
            fd,
            address_buffer,
            address_size
        ) < 0) {

        close(fd);
        return -1;
    }

    unsigned char bound_port[2];

    if (recv_all(
            fd,
            bound_port,
            sizeof(bound_port)
        ) < 0) {

        close(fd);
        return -1;
    }

    connection->fd = fd;

     return 0;
}
