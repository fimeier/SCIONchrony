#ifdef HAVE_LINUX_TIMESTAMPING
#include <linux/errqueue.h>
#include <linux/net_tstamp.h>
#endif

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <float.h>
#include <glob.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <netinet/in.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <bits/socket.h>

#include <sys/timex.h>
#include <arpa/inet.h>
#include <sys/random.h>

int main()
{
    int status = 0;

    const char addrStr[] = "/home/fimeier/Dropbox/00ETH/HS20/MasterThesis/repos/chrony/sciontest/unixsockets/uxtime.sock";

    printf("Hello from Site Two\n");

    int domain = AF_UNIX;

    int type = SOCK_DGRAM | SOCK_CLOEXEC; // | SOCK_NONBLOCK;

    int protocol = 0;

    int fd = socket(domain, type, protocol);
    printf("socket() created fd=%d\n", fd);

    int value = 1;
    status = setsockopt(fd, SOL_SOCKET, SO_SELECT_ERR_QUEUE, &value, sizeof(value)); //__optlen == NULL?
    //On success, zero is returned. On error, -1 is returned, and errno is set appropriately.
    printf("setsockopt() returned %d (0 is ok)\n", status);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));

    if (snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", addrStr) >=
        sizeof(addr.sun_path))
    {
        printf("Unix socket path %s too long\n", addrStr);
        return 0;
    }
    addr.sun_family = AF_UNIX;

    status = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    printf("connect() returned %d (0 is ok)\n", status);

    /* send crap*/



//geht das???

    int sendFlags = MSG_ERRQUEUE;




    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iovlen = 1;

    struct iovec msg_iov;
    memset(&msg_iov, 0, sizeof(msg_iov));
    char gugug[]="Hello Duda";
    msg_iov.iov_base = gugug;
    msg_iov.iov_len = sizeof(gugug);
    msg.msg_iov = &msg_iov;

        status = sendmsg(fd, &msg, sendFlags);
    printf("sendmsg() returned %d (#bytes sent)\n", status);

    struct timeval timeout = {60, 0};

    fd_set readSet;
    fd_set exceptSet;

    FD_ZERO(&readSet);
    FD_ZERO(&exceptSet);

    FD_SET(fd, &readSet);
    FD_SET(fd, &exceptSet);

    int nfds = fd + 1; //max fd i want to check

    int i = 0;
    while (i < 10)
    {
        //select() setzt timeout allenfalls zurück
        timeout.tv_sec = 60;
        timeout.tv_usec = 0;

        printf("calling select() with timout of %ld %ld\n", timeout.tv_sec, timeout.tv_usec);
        int readyFDs = select(nfds, &readSet, NULL, &exceptSet, &timeout);
        printf("select() returned readyFDs=%d\n", readyFDs);

        for (int fd = 0; readyFDs && fd < nfds; fd++)
        { //mefi84 man geht alle FD's durch...
            if (FD_ISSET(fd, &readSet))
            {
                printf("fd=%d reported file input\n", fd);
                readyFDs--;
            }

            if (FD_ISSET(fd, &exceptSet))
            {
                printf("fd=%d reported an exception\n", fd);
                readyFDs--;
            }
        }
        i++;
    }

    return 0;
}