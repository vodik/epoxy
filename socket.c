#include "socket.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <err.h>

#include <sys/stat.h>
#include <sys/sendfile.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <systemd/sd-daemon.h>

static inline int sock_reuseaddr(int sock, int val)
{
    return setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(int));
}

static inline int sock_nonblock(int sock)
{
    int flags = fcntl(sock, F_GETFL, 0);
    return flags < 0 ? flags : fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

int connect_to(const char *hostname, const char *service)
{
    struct addrinfo *results, *rp;
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_CANONNAME
    };

    int err = getaddrinfo(hostname, service, &hints, &results);
    if (err != 0) {
        printf("error %d: %s\n", err, gai_strerror(err));
        return 1;
    }

    int fd;
    for (rp = results; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype | SOCK_CLOEXEC, rp->ai_protocol);
        if (fd < 0)
            continue;

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) != -1)
            break;
    }

    if (rp == NULL)
        errx(EXIT_FAILURE, "could not establish connection");

    freeaddrinfo(results);
    return fd;
}

int start_server(uint16_t port)
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

int accept_connection(int fd)
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

    /* if (sock_nonblock(cfd) < 0) */
    /*     err(EXIT_FAILURE, "failed to set nonblocking"); */

    return cfd;
}

void copyfile(const char *filename, int out_fd)
{
    struct stat st;
    int ret;

    int fd = open(filename, O_RDONLY);
    if (fd < 0)
        err(EXIT_FAILURE, "couldn't access %s", filename);

    fstat(fd, &st);
    ret = sendfile(out_fd, fd, NULL, st.st_size);
    if (ret < 0)
        err(EXIT_FAILURE, "failed to send file %s across socket", filename);

    close(fd);
}

void copydata(int in_fd, int out_fd)
{
    char buf[BUFSIZ];
    ssize_t bytes_r;

    while (true) {
        bytes_r = read(in_fd, buf, BUFSIZ);
        if (bytes_r == 0) {
            break;
        } else if (bytes_r < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            err(EXIT_FAILURE, "copy between fds failed");
        }

        write(out_fd, buf, bytes_r);
    }
}
