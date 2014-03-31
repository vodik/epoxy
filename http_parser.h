#ifndef http11_parser_h
#define http11_parser_h

#include <sys/types.h>
#include "socket.h"

typedef void (*element_cb)(void *data, const char *at, size_t length);
typedef void (*field_cb)(void *data, const char *field, size_t flen, const char *value, size_t vlen);

struct http_callbacks {
    void *data;

    field_cb http_field;
    element_cb request_method;
    element_cb request_uri;
    element_cb fragment;
    element_cb request_path;
    element_cb query_string;
    element_cb http_version;
    element_cb header_done;
};

struct http_parser {
    size_t body_start;
    int content_len;
    size_t nread;
    size_t mark;
    size_t field_start;
    size_t field_len;
    size_t query_start;

    struct http_parser_cbs *cbs;
};

void http_parser_init(struct http_parser *parser, struct sock *sock);
size_t http_parser_execute(struct http_parser *parser, struct sock *sock, struct http_callbacks *cbs);
int http_parser_finish(struct sock *sock);
int http_parser_has_error(struct sock *sock);
int http_parser_is_finished(struct sock *sock);

#define http_parser_nread(parser) (parser)->nread

#endif
