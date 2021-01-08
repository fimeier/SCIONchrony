#include <stdio.h>
#include <sys/socket.h>

#include "call_me_api.h"

/*
gcc -o callme callme.c /home/fimeier/Dropbox/00ETH/HS20/MasterThesis/repos/chrony/sciontest/bug/server/call_me_api.so
*/
int main()
{

    /* DUmmy work for c part*/
    int domain = AF_UNIX;
    int type = SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK;
    int protocol = 0;
    int fd = socket(domain, type, protocol);

    fd_set readSet;
    fd_set exceptSet;

    FD_ZERO(&readSet);
    FD_ZERO(&exceptSet);
    FD_SET(fd, &readSet);

    printf("calling CallMe()....\n");
    CallMe();
    printf("......returned form CallMe()\n");

    

    while (1)
    {
        struct timeval timeout = {1, 0};
        
        printf("Calling select...\n");

        int readyFDs = select(fd + 1, &readSet, NULL, &exceptSet, &timeout);
    }
}