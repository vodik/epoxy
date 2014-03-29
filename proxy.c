#include "proxy.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <err.h>
#include <limits.h>
#include <assert.h>

#include <sys/stat.h>
#include <sys/sendfile.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include "http_parser.h"
#include "socket.h"
#include "iobuf.h"
#include "util.h"

/* struct vector { */
/*     /1* should be enough for now, but its a hack *1/ */
/*     struct iovec *iov, *v; */
/*     size_t count; */
/* }; */

enum http_request {
    INVALID_REQUEST = 0,
    REQUEST_PATH,
    REQUEST_URI
};

struct proxy_request {
    int fd;
    const char *hostname;

    struct iobuf request;
};

struct http_data {
    enum http_request request_type;

    /* union d { */
        struct proxy_request p;
    /* }; */

    const char *path;
    const char *modified;

    /* XXX: necessary/temporary? */
    const char *method;
    size_t method_len;
};

static struct http_parser parser;

/* {{{ CALLBACKS */
/* static const struct iovec iov_host  = { "Host: ", sizeof("Host: ") - 1 }; */
/* static const struct iovec iov_crlf  = { "\r\n",   2 }; */

static void http_request_method(void *data, const char *at, size_t len)
{
    struct http_data *header = data;
    /* iobuf_append(header, at, len + 1); */

    header->method = at;
    header->method_len = len;
}

static void http_request_uri(void *data, const char *at, size_t len)
{
    struct http_data *header = data;

    /* *header->p.v++ = (struct iovec){ (void *)at + 2,  len - 2 + 1 }; */
    if (strncmp(at, "//", 2) == 0) {
        header->request_type = REQUEST_URI;
    } else {
        header->request_type = REQUEST_PATH;
    }

    switch (header->request_type) {
    case REQUEST_URI:
        /* TODO: properly init proxy response */
        iobuf_init(&header->p.request, 10);

        header->p.hostname = strndup(at + 2, len - 3); /** -3 to avoid the /, parser broken? */
        header->p.fd = connect_to(header->p.hostname, "http");

        iobuf_append(&header->p.request, header->method, header->method_len + 1);
        iobuf_append(&header->p.request, "/ ", 2);

        /* TODO: store the lenght to avoid the strlen later */
        header->path = strndup(at, len);

        /* TODO: check if uri or path, this should affect below */
        /* header->http_request_version = http_request_version; */
        /* header->http_field   = http_field; */
        break;
    case REQUEST_PATH:
        header->path = strndup(at, len);
        printf("requesting PATH=%s\n", header->path);
        break;
    default:
        break;
    }
}

static void http_request_version(void *data, const char *at, size_t len)
{
    /* XXX: do we really need to pass this on verbatum? Lets just
     * automatically upgrade to HTTP 1.1 */
    struct http_data *header = data;

    /* TODO: redo how callbacks are set */
    if (header->request_type != REQUEST_URI)
        return;

    iobuf_append(&header->p.request, at, len + 2);
}

static void http_field(void *data, const char *field, size_t flen, const char *value, size_t vlen)
{
    struct http_data *header = data;

    /* TODO: redo how callbacks are set */
    if (header->request_type != REQUEST_URI)
        return;

    if (strncmp("Host", field, flen) == 0) {
        iobuf_append(&header->p.request, "Host: ", 6);
        iobuf_append(&header->p.request, header->p.hostname, strlen(header->p.hostname));
        iobuf_append(&header->p.request, "\r\n", 2);
        return;
    } else if (strncmp("If-Modified-Since", field, flen) == 0) {
        header->modified = strndup(value, vlen);
    } else if (strncmp("Proxy-Connection", field, flen) == 0) {
        return;
    }

    iobuf_append(&header->p.request, field, flen + 2);
    iobuf_append(&header->p.request, value, vlen + 2);
}

/* TODO: this doesn't need any arguments */
static void http_request_done(void *data, const char _unused_ *at, size_t _unused_ len)
{
    struct http_data *header = data;

    /* TODO: redo how callbacks are set */
    if (header->request_type != REQUEST_URI)
        return;

    iobuf_append(&header->p.request, "Connection: Close\r\n", 19);
    iobuf_append(&header->p.request, "\r\n", 2);
}
/* }}} */

static void handle_proxy_request(struct proxy_request *conn, int client_fd)
{
    if (conn->fd <= 0)
        errx(EXIT_FAILURE, "no proxy socket");

    printf("SENDING: ");
    fflush(stdout);
    iobuf_write(&conn->request, STDOUT_FILENO);

    /* write out header */
    iobuf_write(&conn->request, conn->fd);
    copydata(conn->fd, client_fd);

    close(conn->fd);
}

/* XXX: hacktastic but should return a valid file from pacman's cache */
static void handle_file_request(const char *path, int client_fd)
{
    struct iobuf buf;
    struct stat st;
    int ret;

    iobuf_init(&buf, 10);
    iobuf_append(&buf, "HTTP/1.1 ", 9);
    iobuf_append(&buf, "200 ", 4);
    iobuf_append(&buf, "OK\r\n", 4);

    _cleanup_free_ char *filename = joinpath(".", path, NULL);

    int fd = open(filename, O_RDONLY);
    if (fd < 0)
        err(EXIT_FAILURE, "couldn't access %s", filename);

    fstat(fd, &st);

    /* XXX: cleanup */
    snprintf(filename, PATH_MAX, "%s: %zd\r\n", "Content-Length", st.st_size);
    iobuf_append(&buf, "\r\n", 2);

    /* write out header */
    iobuf_write(&buf, client_fd);

    ret = sendfile(client_fd, fd, NULL, st.st_size);
    if (ret < 0)
        err(EXIT_FAILURE, "failed to send file %s across socket", filename);

    close(fd);
}

static void parse_header(int fd, struct http_data *data)
{
    struct http_callbacks callbacks = {
        .data = data,

        .request_method = http_request_method,
        .request_uri    = http_request_uri,
        .http_version   = http_request_version,

        .http_field     = http_field,
        .header_done    = http_request_done
    };

    char buf[BUFSIZ];
    ssize_t bytes_r;

    http_parser_init(&parser);

    /* TODO: should be a loop */
    bytes_r = read(fd, buf, BUFSIZ);
    http_parser_execute(&parser, buf, bytes_r, &callbacks);
    assert(http_parser_is_finished(&parser) && "http header was too big?");
}

void handle_request(int client_fd)
{
    struct http_data data = {
        .request_type = INVALID_REQUEST
    };

    parse_header(client_fd, &data);

    switch (data.request_type) {
    case REQUEST_URI:
        handle_proxy_request(&data.p, client_fd);
        break;
    default:
        handle_file_request(data.path, client_fd);
        break;
    }
}
