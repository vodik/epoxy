#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>

#include "socket.h"
#include "proxy.h"

int main(void)
{
    int server_fd = start_server(8080);

    while (true) {
        int cfd = accept_connection(server_fd);

        printf("accepted connection %d\n", cfd);
        read_request(cfd);
        close(cfd);
    }

    return 0;
}
