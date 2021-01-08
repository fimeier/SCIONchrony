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


#include <sys/timex.h>
#include <arpa/inet.h>
#include <sys/random.h>

//#include <socket.h>

static int
bind_unix_address(int sock_fd, const char *addr, int flags)
{
    struct sockaddr_un saddr;

    memset(&saddr, 0, sizeof(addr));

    if (snprintf(saddr.sun_path, sizeof(saddr.sun_path), "%s", addr) >=
        sizeof(saddr.sun_path))
    {
        printf("Unix socket path %s too long\n", addr);
        return 0;
    }
    saddr.sun_family = AF_UNIX;

    if (unlink(addr) < 0)
        printf("Could not remove %s : %s\n", addr, strerror(errno));

    /* PRV_BindSocket() doesn't support Unix sockets yet */
    if (bind(sock_fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
    {
        printf("Could not bind Unix socket to %s : %s\n", addr, strerror(errno));
        return 0;
    }

    /* Allow access to everyone with access to the directory */
    if (chmod(addr, 0666) < 0)
    {
        printf("Could not change permissions of %s : %s\n", addr, strerror(errno));
        return 0;
    }

    return 1;
}

int main()
{
    int status = 0;
    const char addr[] = "/home/fimeier/Dropbox/00ETH/HS20/MasterThesis/repos/chrony/sciontest/unixsockets/uxtime.sock";

    printf("Hello from Site One %s\n", addr);

    int domain = AF_UNIX;

    int type = SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK;

    int protocol = 0;

    int fd = socket(domain, type, protocol);
    printf("socket() created fd=%d\n", fd);

    int value = 1;
    status = setsockopt(fd, SOL_SOCKET, SO_SELECT_ERR_QUEUE, &value, sizeof(value)); //__optlen == NULL?
    //On success, zero is returned. On error, -1 is returned, and errno is set appropriately.
    printf("setsockopt() returned %d (0 is ok)\n", status);

    int bindFlags = 0;
    status = bind_unix_address(fd, (char *)&addr, bindFlags);
    printf("bind_unix_address() returned %d (1 is ok)\n", status);

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

        int ready = 0;

        printf("calling select() with timout of %ld %ld\n", timeout.tv_sec, timeout.tv_usec);
        int readyFDs = select(nfds, &readSet, NULL, &exceptSet, &timeout);
        printf("select() returned readyFDs=%d\n", readyFDs);
        if (readyFDs > 0)
        {
            ready = 1;
        }

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

        if (ready)
        {
            printf("Hier sollte ich die Daten empfangen....\n");
            printf("Hier sollte ich die Daten empfangen....\n");
            printf("Hier sollte ich die Daten empfangen....\n");
            printf("Hier sollte ich die Daten empfangen....\n");
            printf("Hier sollte ich die Daten empfangen....\n");
            printf("Hier sollte ich die Daten empfangen....\n");
            printf("Hier sollte ich die Daten empfangen....\n");
            printf("Hier sollte ich die Daten empfangen....\n");
            printf("Hier sollte ich die Daten empfangen....\n");
            printf("Hier sollte ich die Daten empfangen....\n");
        }

        i++;
    }

    return 0;
}