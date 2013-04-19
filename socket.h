#ifndef SOCKET_H
#define SOCKET_H

#include <stdint.h>

int connect_to(const char *hostname, const char *service);
int start_server(uint16_t port);
int accept_connection(int fd);

void copyfile(const char *filename, int out_fd);
void copydata(int in_fd, int out_fd);

#endif
