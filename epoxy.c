#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netdb.h>
#include <systemd/sd-daemon.h>

#include "proxy.h"

static inline int sock_reuseaddr(int sock, int val)
{
    return setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(int));
}

static int start_server(uint16_t port)
{
    int fd, n;

    n = sd_listen_fds(0);
    if (n > 1)
        err(EXIT_FAILURE, "too many file descriptors recieved");
    else if (n == 1) {
        fd = SD_LISTEN_FDS_START;
        /* sd_activated = true; */
    } else {
        union {
            struct sockaddr sa;
            struct sockaddr_in in;
        } sa;

        fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0)
            err(EXIT_FAILURE, "couldn't create socket");

        sock_reuseaddr(fd, 1);

        sa.in = (struct sockaddr_in){
            .sin_family = AF_INET,
            .sin_port = htons(port),
            .sin_addr.s_addr = INADDR_ANY
        };

        if (bind(fd, &sa.sa, sizeof(sa)) < 0)
            err(EXIT_FAILURE, "failed to bind");

        if (listen(fd, SOMAXCONN) < 0)
            err(EXIT_FAILURE, "failed to listen");
    }

    return fd;
}

static int accept_conn(int fd)
{
    union {
        struct sockaddr sa;
        struct sockaddr_in in;
    } sa;
    socklen_t sa_len = sizeof(sa);

    /* int cfd = accept4(fd, &sa.sa, &sa_len, SOCK_CLOEXEC); */
    int cfd = accept(fd, &sa.sa, &sa_len);
    if (cfd < 0)
        err(EXIT_FAILURE, "failed to accept connection");

    return cfd;
}


int main(void)
{
    int server_fd = start_server(8080);

    while (true) {
        int cfd = accept_conn(server_fd);

        printf("accepted connection %d\n", cfd);
        read_request(cfd);
        close(cfd);
    }

    return 0;
}
