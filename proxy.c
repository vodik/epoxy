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

#include "http_parser.h"
#include "socket.h"

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

/* {{{ CALLBACKS */
static const struct iovec iov_host  = { "Host: ", strlen("Host: ") };
static const struct iovec iov_crlf  = { "\r\n",   2 };

/* XXX: needs a better name */
static inline void add_write(struct http_data *data, const char *field, size_t len)
{
    *data->v++ = (struct iovec){ (void *)field,  len };
}

static void http_request_method(void *data, const char *at, size_t len)
{
    struct http_data *header = data;
    add_write(header, at, len + 1);
}

static void http_request_uri(void *data, const char *at, size_t len)
{
    struct http_data *header = data;

    /* *header->v++ = (struct iovec){ (void *)at + 2,  len - 2 + 1 }; */
    add_write(header, "/ ", 2);

    if (true) { /* if (is_uri) { */
        header->hostname = strndup(at + 2, len - 3); /** -3 to avoid the /, parser broken? */
        header->fd = connect_to(header->hostname, "http");

        /* TODO: store the lenght to avoid the strlen later */
        header->path = strndup(at, len);

        /* TODO: check if uri or path, this should affect below */
        /* header->http_version = http_version; */
        /* header->http_field   = http_field; */
    }
}

static void http_version(void *data, const char *at, size_t len)
{
    /* XXX: do we really need to pass this on verbatum? Lets just
     * automatically upgrade to HTTP 1.1 */
    struct http_data *header = data;
    add_write(header, at, len + 2);
}

static void http_field(void *data, const char *field, size_t flen, const char *value, size_t vlen)
{
    struct http_data *header = data;

    if (strncmp("Host", field, flen) == 0) {
        *header->v++ = iov_host;
        add_write(header, header->hostname, strlen(header->hostname));
        *header->v++ = iov_crlf;
        return;
    } else if (strncmp("If-Modified-Since", field, flen) == 0) {
        header->modified = strndup(value, vlen);
    } else if (strncmp("Proxy-Connection", field, flen) == 0) {
        return;
    }

    add_write(header, field, flen + 2);
    add_write(header, value, vlen + 2);
}
/* }}} */

void read_request(int client_fd)
{
    struct http_data data = {
        .hostname = NULL,
    };

    struct http_callbacks callbacks = {
        .data = &data,

        .request_method = http_request_method,
        .request_uri    = http_request_uri,
        .http_version   = http_version,
        .http_field     = http_field
    };

    char buf[BUFSIZ];
    ssize_t bytes_r;

    data.v = data.iov;
    http_parser_init(&parser);

    /* TODO: should be a loop */
    bytes_r = read(client_fd, buf, BUFSIZ);
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

    int target_fd = data.fd;
    if (target_fd <= 0)
        errx(EXIT_FAILURE, "no proxy socket");
    int iovcnt = data.v - data.iov;

    printf("SENDING: ");
    fflush(stdout);
    writev(STDOUT_FILENO, data.iov, iovcnt);

    /* write out header */
    writev(target_fd, data.iov, iovcnt);
    shutdown(target_fd, SHUT_WR);
    copydata(target_fd, client_fd);

    close(target_fd);
}
