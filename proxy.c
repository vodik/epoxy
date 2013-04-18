#include "proxy.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netdb.h>

#include "http_parser.h"

#define UNUSED __attribute__((unused))

struct http_data {
    /* should be enough for now, but its a hack */
    struct iovec iov[100], *v;

    int fd;
    const char *hostname;

    const char *path;
    const char *modified;
};

static struct http_parser parser;

static int load_proxy(const char *hostname, const char *service)
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

/* {{{ CALLBACKS */
static const struct iovec iov_host  = { "Host: ", strlen("Host: ") };
static const struct iovec iov_crlf  = { "\r\n",   2 };

static void http_request_method(void *data, const char *at, size_t len)
{
    struct http_data *header = data;
    *header->v++ = (struct iovec){ (void *)at,  len + 1 };
}

static void http_request_uri(void *data, const char *at, size_t len)
{
    struct http_data *header = data;
    /* *header->v++ = (struct iovec){ (void *)at + 2,  len - 2 + 1 }; */
    *header->v++ = (struct iovec){ "/ ",  2 };

    header->hostname = strndup(at + 2, len - 3); /** -3 to avoid the / */
    header->fd = load_proxy(header->hostname, "http");
    /* TODO: store the lenght to avoid the strlen */

    header->path = strndup(at, len);
}

static void http_version(void *data, const char *at, size_t len)
{
    struct http_data *header = data;
    *header->v++ = (struct iovec){ (void *)at,  len + 2 };
}

static void http_field(void *data, const char *field, size_t flen, const char *value, size_t vlen)
{
    struct http_data *header = data;

    if (strncmp("Host", field, flen) == 0) {
        *header->v++ = iov_host;
        *header->v++ = (struct iovec){ (void *)header->hostname, strlen(header->hostname) };
        *header->v++ = iov_crlf;
        return;
    } else if (strncmp("If-Modified-Since", field, flen) == 0) {
        header->modified = strndup(value, vlen);
    } else if (strncmp("Proxy-Connection", field, flen) == 0) {
        return;
    }

    *header->v++ = (struct iovec){ (void *)field, flen + 2 };
    *header->v++ = (struct iovec){ (void *)value, vlen + 2 };
}
/* }}} */

void read_request(int fd)
{
    struct http_data data = {
        .hostname = NULL,
    };

    struct http_callbacks callbacks = {
        .data = &data,

        .request_method = http_request_method,
        .request_uri    = http_request_uri,
        .http_version   = http_version,
        .http_field     = http_field,
    };

    char buf[BUFSIZ];
    ssize_t bytes_r;

    data.v = data.iov;
    http_parser_init(&parser);

    /* TODO: should be a loop */
    bytes_r = read(fd, buf, BUFSIZ);
    http_parser_execute(&parser, buf, bytes_r, &callbacks);
    assert(http_parser_is_finished(&parser) && "http header was too big?");

    /* printf("-----------------\n"); */
    /* printf("Path = %s\n", data.path); */
    /* printf("User-Agent = %s\n", data.useragent); */
    /* printf("Host = %s\n", data.host); */
    /* printf("Accept = %s\n", data.accept); */
    /* printf("If-Modified-Since = %s\n", data.modified); */
    /* printf("-----------------\n\n"); */

    *data.v++ = iov_crlf;

    int pfd = data.fd;
    if (pfd <= 0)
        errx(EXIT_FAILURE, "no proxy socket");
    int iovcnt = data.v - data.iov;

    printf("SENDING: ");
    fflush(stdout);
    writev(STDOUT_FILENO, data.iov, iovcnt);

    /* write out header */
    writev(pfd, data.iov, iovcnt);
    shutdown(pfd, SHUT_WR);

    while (true) {
        bytes_r = recv(pfd, buf, BUFSIZ, 0);
        if (bytes_r == 0)
            break;
        else if (bytes_r < 0)
            err(EXIT_FAILURE, "read from proxy failed");

        write(fd, buf, bytes_r);
    }

    close(pfd);
}
