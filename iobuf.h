#pragma once

#include <stddef.h>
#include <unistd.h>

struct iobuf {
    struct iovec *iov;
    size_t len;
    size_t nbytes;
    size_t pos;
};

int iobuf_init(struct iobuf *buf, size_t reserve);
int iobuf_append(struct iobuf *buf, const char *field, size_t len);
ssize_t iobuf_write(struct iobuf *buf, int fd);
