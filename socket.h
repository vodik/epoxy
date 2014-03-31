#pragma once

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

struct sock {
    int fd;
    char buf[BUFSIZ];
    size_t pos, len;

    int cs;
    char *p, *pe;
};

int connect_to(const char *hostname, const char *service);
int start_server(uint16_t port);
int accept_connection(int fd);

void copyfile(const char *filename, int out_fd);
void copydata(int in_fd, int out_fd);
