#include "iobuf.h"

#include <stdlib.h>
#include <stdio.h>
#include <err.h>
#include <errno.h>
#include <sys/uio.h>

#include "util.h"

static inline size_t next_power(size_t x)
{
    return 1UL << (64 - __builtin_clzl(x - 1));
}

static int iovec_extendby(struct iobuf *buf, size_t extby)
{
    struct iovec *iov;
    size_t newlen = _unlikely_(!buf->len && extby < 16)
        ? 16 : buf->len + extby;

    if (newlen > buf->len) {
        newlen = next_power(newlen);
        iov = realloc(buf->iov, newlen);
        if (!iov)
            return -errno;

        buf->len = newlen;
        buf->iov = iov;
    }

    return 0;
}

int iobuf_init(struct iobuf *buf, size_t reserve)
{
    zero(buf, sizeof(struct iobuf));

    if (reserve && iovec_extendby(buf, reserve) < 0)
        return -errno;
    return 0;
}

int iobuf_append(struct iobuf *buf, const char *field, size_t len)
{
    if (iovec_extendby(buf, 1) < 0)
        return -errno;

    buf->nbytes += len;
    buf->iov[buf->pos++] = (struct iovec){
        .iov_base = (void *)field,
        .iov_len  = len
    };

    return 0;
}

ssize_t iobuf_write(struct iobuf *buf, int fd)
{
    size_t cur = 0;

    while (true) {
        ssize_t bytes_w = writev(fd, buf->iov + cur, buf->pos - cur);
        if ((size_t)bytes_w == buf->nbytes || bytes_w < 0)
            return bytes_w;

        /* TODO: fix return on partial write */
        errx(1, "partial write in iobuf_write");

        /* handle partial writes */
        /* while ((size_t)bytes_w >= buf->iov[cur].iov_len) */
        /*     bytes_w -= buf->iov[cur++].iov_len; */

        /* if (cur == buf->pos) */
        /*     break; */

        /* buf->iov[cur].iov_base = (char *)buf->iov[cur].iov_base + bytes_w; */
        /* buf->iov[cur].iov_len -= bytes_w; */
    }

    return 0;
}
