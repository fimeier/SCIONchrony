#include "scion.h"
//#include "scion_api.h"

static int socked_mapping[1024];

//TODO CHange is if still needed
static unsigned int highest_fd = 0;

static fdInfo *fdInfos[1024];

void SCION_Initialise()
{
    memset(socked_mapping, 0, 1024 * sizeof(int)); //needed?
}

void SCION_TestCall(int a)
{
    printf("SCION_TestCall:: a=%d\n", a);
}

int SCION_close(int sock_fd)
{
    DEBUG_LOG("Closing socket %d", sock_fd);
    if (sock_fd == highest_fd)
    {
        highest_fd--;
        DEBUG_LOG("Setting highest_fd=%d ", highest_fd);
    }

    if (fdInfos[sock_fd] != NULL)
    {
        free(fdInfos[sock_fd]); //TODO okay? :-D
    }

    return close(sock_fd);
    //return SCIONgoclose(sock_fd);
}

/* Emulates "return socket (__domain, __type,__protocol)"
__domain as defined in bits/socket.h
*/
int SCION_socket(int __domain, int __type, int __protocol)
{
    DEBUG_LOG("Creating socket with domain=%d type=%d protocol=%d", __domain, __type, __protocol);

    fdInfo *sinfo = calloc(1, sizeof(fdInfo));
    sinfo->domain = __domain;
    sinfo->type = __type;
    sinfo->protocol = __protocol;
    sinfo->connectionType = NOT_CONNECTED;

    if (DEBUG)
    {
        switch (__domain)
        {
        case AF_INET:
            DEBUG_LOG("\t\t domain = AF_INET");
            break;
        case AF_UNIX:
            DEBUG_LOG("\t\t domain = AF_UNIX");
            break;
        default:
            DEBUG_LOG("\t\t domain = tbd");
            break;
        }

        switch (__type)
        {
        case SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK:
            DEBUG_LOG("\t\t type = SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK");
            break;
        case SOCK_DGRAM | SOCK_NONBLOCK:
            DEBUG_LOG("\t\t type = SOCK_DGRAM | SOCK_NONBLOCK");
            break;
        case SOCK_DGRAM | SOCK_CLOEXEC:
            DEBUG_LOG("\t\t type = SOCK_DGRAM | SOCK_CLOEXEC");
            break;
        default:
            DEBUG_LOG("\t\t type = tbd");
            break;
        }
    }

    int fd = socket(__domain, __type, __protocol);
    sinfo->fd = fd;
    fdInfos[fd] = sinfo;

    DEBUG_LOG("\t\t fd = %d", fd);

    if (fd > highest_fd)
    {
        highest_fd = fd;
        DEBUG_LOG("Setting highest_fd=%d ", highest_fd);
    }
    //c2go scion api
    //int fd2 = SCIONgosocket(__domain, __type, __protocol);
    //printf("fd2=%d\n", fd2);

    return fd;
}

int SCION_setsockopt(int __fd, int __level, int __optname, const void *__optval, socklen_t __optlen)
{
    DEBUG_LOG("Setting options fd=%d level=%d optname=%d", __fd, __level, __optname);

    int scion_level;
    int scion_optname;

    switch (__level)
    {
        /************************************************************/

    case IPPROTO_IP:
        DEBUG_LOG("\t\t level = IPPROTO_IP");
        scion_level = SCION_IPPROTO_IP;
        switch (__optname)
        {
        case IP_PKTINFO:
            DEBUG_LOG("\t\t optname = IP_PKTINFO");
            scion_optname = SCION_IP_PKTINFO;
            break;
        case IP_FREEBIND:
            DEBUG_LOG("\t\t optname = IP_FREEBIND");
            scion_optname = SCION_IP_FREEBIND;
            break;
        default:
            DEBUG_LOG("\t\t optname = tbd");
            break;
        }
        break;

        /************************************************************/

    case SOL_SOCKET:
        DEBUG_LOG("\t\t level = SOL_SOCKET");
        scion_level = SCION_SOL_SOCKET;
        switch (__optname)
        {
        case SO_REUSEADDR:
            DEBUG_LOG("\t\t optname = SO_REUSEADDR");
            scion_optname = SCION_SO_REUSEADDR;
            break;
        case SO_REUSEPORT:
            DEBUG_LOG("\t\t optname = SO_REUSEPORT");
            scion_optname = SCION_SO_REUSEPORT;
            break;
        case SO_TIMESTAMPING:
            DEBUG_LOG("\t\t optname = SO_TIMESTAMPING");
            scion_optname = SCION_SO_TIMESTAMPING;
            break;
        case SO_BROADCAST:
            DEBUG_LOG("\t\t optname = SO_BROADCAST");
            scion_optname = SCION_SO_BROADCAST;
            break;
        case SO_SELECT_ERR_QUEUE:
            DEBUG_LOG("\t\t optname = SO_SELECT_ERR_QUEUE");
            scion_optname = SCION_SO_SELECT_ERR_QUEUE;
            break;
        default:
            DEBUG_LOG("\t\t optname = tbd");
            break;
        }
        break;
        /************************************************************/

    default:
        DEBUG_LOG("\t\t level = tbd");
        DEBUG_LOG("\t\t optname = tbd");
        break;
    }

    if (*((int *)__optval) != 0)
    {
        DEBUG_LOG("\t\t optval = %d => activate option", *((int *)__optval));
    }
    else
    {
        DEBUG_LOG("\t\t optval = 0 => disable option");
    }

    /*On success, zero is returned for the standard options.  On error, -1
    is returned, and errno is set appropriately.*/

    int result = setsockopt(__fd, __level, __optname, __optval, __optlen);

    if (fdInfos[__fd] != NULL) //should always be true
    {
        fdInfo *fdi = fdInfos[__fd];
        fdi->level_optname_value[scion_level][scion_optname] = *((int *)__optval);
    }
    if (result < 0)
    {
        DEBUG_LOG("\t\t setsockopt() returned an error!");
    }

    return result;
}

/*
    TODO? How can I define (__CONST_SOCKADDR_ARG __addr) in the header and use it afterwards as I do it?

    ---> no problem in the debugger. Function defined as...
                SCION_bind(int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len)
        ...then "viewing" the datastructure as "(struct sockaddr*)__addr"
    ---> Why does the compiler prevents me from compiling similar code?
*/
int SCION_bind(int __fd, const struct sockaddr *__addr, socklen_t __len)
{
    DEBUG_LOG("Binding fd=%d", __fd);

    if (fdInfos[__fd] != NULL) //should always be true
    {
        fdInfo *fdi = fdInfos[__fd];
        SCK_SockaddrToIPSockAddr(__addr, __len, &fdi->boundTo);
        DEBUG_LOG("\t\t%s",UTI_IPSockAddrToString(&fdi->boundTo));

    }
    else
    {
        DEBUG_LOG("nonexisting fdInfo: cannot add informations");
    }

    return bind(__fd, __addr, __len);
}

int SCION_getsockopt(int __fd, int __level, int __optname, void *__restrict __optval, socklen_t *__restrict __optlen)
{
    DEBUG_LOG("Getting options fd=%d level=%d optname=%d", __fd, __level, __optname);
    return getsockopt(__fd, __level, __optname, __optval, __optlen);
}

int SCION_connect(int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len, IPSockAddr *addr)
{
    //ist this an ntp server..... should normally be the case

    //TODO ist this safe?? Buffer??? CHANGE THIS!!!!
    char *remoteAddress = UTI_IPSockAddrToString(addr);

    //TODO 1 Solve this for all cases
    char *ntpServer1 = "10.80.45.128:123";
    char *ntpServer1AsScionAddress = "1-ff00:0:110,10.80.45.83:11111";
    if (strcmp(remoteAddress, ntpServer1) == 0)
    {
        DEBUG_LOG("Connecting socket fd=%d to %s is an ntp server", __fd, remoteAddress);
        if (fdInfos[__fd] != NULL) //should always be true
        {
            fdInfo *fdi = fdInfos[__fd];
            fdi->connectionType = CONNECTED_TO_NTP_SERVER;
            strcpy(fdi->remoteAddress, remoteAddress);
            strcpy(fdi->remoteAddressSCION, ntpServer1AsScionAddress);
        }
    }

    DEBUG_LOG("Connecting socket fd=%d to %s", __fd, remoteAddress);
    return connect(__fd, __addr, __len);
}

ssize_t SCION_sendmsg(int __fd, const struct msghdr *__message, int __flags)
{
    DEBUG_LOG("Sending message on socket fd=%d", __fd);

    int status;
    if (fdInfos[__fd] != NULL && fdInfos[__fd]->connectionType == CONNECTED_TO_NTP_SERVER)
    {
        //This implies we are using SCION
        DEBUG_LOG("\t|----> connected to %s i.e. %s\n", fdInfos[__fd]->remoteAddress, fdInfos[__fd]->remoteAddressSCION);
        status = SCIONgosendmsg(__fd, __message, __flags, fdInfos[__fd]->remoteAddressSCION);
        DEBUG_LOG("Sent message on socket fd=%d with status=%d(<-#bytes sent)", __fd, status);

        //TODO remove sendmsg()
        DEBUG_LOG("TODO remove sendmsg()!!!!");
        status = sendmsg(__fd, __message, __flags);
    }
    else
    {
        DEBUG_LOG("\t|----> not a connection to an ntp server. Not using SCION!");
        status = sendmsg(__fd, __message, __flags);
    }

    return status;
}

typedef struct mmsghdr recvHdr;

typedef union sockaddr_all
{
    struct sockaddr_in in4;
#ifdef FEAT_IPV6
    struct sockaddr_in6 in6;
#endif
    struct sockaddr_un un;
    struct sockaddr sa;
} sockaddr_all;

void printMMSGHDR(struct mmsghdr *msgvec, int n)
{
    for (int i = 0; i < n; i++)
    {
        struct msghdr *msg_hdr = &msgvec[i].msg_hdr;

        DEBUG_LOG("\t|-----> Printing message %d:", i + 1);
        DEBUG_LOG("\t\t\tmsg_len=%u", msgvec[i].msg_len);
        DEBUG_LOG("\t\t\tmsg_hdr @ %p", msg_hdr);

        if (msg_hdr->msg_namelen == 0)
        {
            DEBUG_LOG("\t\t\t\tmsg_hdr.msg_namelen=%d", msg_hdr->msg_namelen);
            DEBUG_LOG("\t\t\t\tmsg_hdr.msg_name=%s", "NULL");
        }
        else
        {
            DEBUG_LOG("\t\t\t\tmsg_hdr.msg_namelen=%d", msg_hdr->msg_namelen);
            if (msg_hdr->msg_namelen <= sizeof(union sockaddr_all) &&
                msg_hdr->msg_namelen > sizeof(((struct sockaddr *)msg_hdr->msg_name)->sa_family)) //????
            {
                switch (((struct sockaddr *)msg_hdr->msg_name)->sa_family)
                {
                case AF_INET:
                    DEBUG_LOG("\t\t\t\tmsg_hdr.msg_name (AF_INET) = %s:%u", inet_ntoa(((struct sockaddr_in *)msg_hdr->msg_name)->sin_addr), ntohs(((struct sockaddr_in *)msg_hdr->msg_name)->sin_port));
                    break;
                case AF_UNIX:
                    DEBUG_LOG("\t\t\t\tmsg_hdr.msg_name (AF_UNIX) = %s", ((struct sockaddr_un *)msg_hdr->msg_name)->sun_path);
                    break;
                default:
                    DEBUG_LOG("\t\t\t\tmsg_hdr.msg_name (NOT IMPLEMENTED!!!) = tbd");
                    break;
                }
            }
        }

        DEBUG_LOG("\t\t\t\tmsg_hdr.msg_iovlen=%lu", msg_hdr->msg_iovlen);

        for (int io = 0; io < msg_hdr->msg_iovlen; io++) //probably always 1 vector
        {
            DEBUG_LOG("\t\t\t\t|-----> Printing vector=%d:", io);
            DEBUG_LOG("\t\t\t\t\t*iov_base=%p", msg_hdr->msg_iov[io].iov_base);
            DEBUG_LOG("\t\t\t\t\tiov_len=%lu", msg_hdr->msg_iov[io].iov_len);
        }

        /*       
       The field msg_control, which has length msg_controllen, points to a
       buffer for other protocol control-related messages or miscellaneous
       ancillary data.  When recvmsg() is called, msg_controllen should con‐
       tain the length of the available buffer in msg_control; upon return
       from a successful call it will contain the length of the control mes‐
       sage sequence.

       The messages are of the form:

           struct cmsghdr {
               size_t cmsg_len;    // Data byte count, including header (type is socklen_t in POSIX)
               int    cmsg_level;  // Originating protocol 
               int    cmsg_type;   // Protocol-specific type
                                    // followed by
               unsigned char cmsg_data[];
           };

       Ancillary data should be accessed only by the macros defined in
       cmsg(3).
       */
        DEBUG_LOG("\t\t\t\tmsg_hdr->msg_control@%p", msg_hdr->msg_control);
        DEBUG_LOG("\t\t\t\tmsg_hdr->msg_controllen=%lu", msg_hdr->msg_controllen);

        struct cmsghdr *cmsg;
        for (cmsg = CMSG_FIRSTHDR(msg_hdr); cmsg; cmsg = CMSG_NXTHDR(msg_hdr, cmsg))
        {
            DEBUG_LOG("\t\t\t\tProcessing *cmsghdr@%p....", cmsg);
#ifdef HAVE_IN_PKTINFO
            if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO)
            {
                DEBUG_LOG("\t\t\t\t|-----> *cmsghdr@%p is of type IP_PKTINFO", cmsg);

                struct in_pktinfo ipi;

                memcpy(&ipi, CMSG_DATA(cmsg), sizeof(ipi));
                DEBUG_LOG("\t\t\t\t\tipi.ipi_ifindex=%d (Interface index)", ipi.ipi_ifindex);
                DEBUG_LOG("\t\t\t\t\tipi.ipi_spec_dst.s_addr=%s (Local address.. wrong->? Routing destination address)", inet_ntoa(ipi.ipi_spec_dst));
                DEBUG_LOG("\t\t\t\t\tipi.ipi_addr.s_addr=%s (Header destination address)", inet_ntoa(ipi.ipi_addr));
            }

#endif

            if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMPING)
            { //mefi84 Kernel Timestamps / HW Timestamps werden in seperaten Messages erhalten
                DEBUG_LOG("\t\t\t\t|-----> *cmsghdr@%p is of type SO_TIMESTAMPING", cmsg);

                struct scm_timestamping ts3;

                memcpy(&ts3, CMSG_DATA(cmsg), sizeof(ts3));
                struct timespec kernel = ts3.ts[0];
                struct timespec hw = ts3.ts[2];
                if (kernel.tv_sec)
                {
                    DEBUG_LOG("\t\t\t\t\tKerne-TS tv_sec=%ld tv_nsec=%ld", kernel.tv_sec, kernel.tv_nsec);
                }
                if (hw.tv_sec)
                {
                    DEBUG_LOG("\t\t\t\t\tHW-TS tv_sec=%ld tv_nsec=%ld", hw.tv_sec, hw.tv_nsec);
                }
            }
        }

        DEBUG_LOG("\t\t\t\tmsg_hdr->msg_flags=%d", msg_hdr->msg_flags);

        //!process_header(&hdr->msg_hdr, hdr->msg_len, sock_fd, flags, &messages[n_ok])
    }
}

int SCION_recvmmsg(int __fd, struct mmsghdr *__vmessages, unsigned int __vlen, int __flags, struct timespec *__tmo)
{

    //assuming this are the only possible flags
    int receiveFlag = (__flags & MSG_ERRQUEUE) ? SCION_MSG_ERRQUEUE : SCION_FILE_INPUT;

    char *flagsMeaning;
    flagsMeaning = (receiveFlag == SCION_MSG_ERRQUEUE) ? "MSG_ERRQUEUE" : "file input";
    DEBUG_LOG("Receiving message on socket fd=%d with flags=%d => %s", __fd, __flags, flagsMeaning);

    /*Receive up to VLEN messages as described by VMESSAGES from socket FD.
   Returns the number of messages received or -1 for errors.*/
    int n;
    if (fdInfos[__fd] != NULL && fdInfos[__fd]->connectionType == CONNECTED_TO_NTP_SERVER)
    {
        /*
        Hier weitermachen... was soll genau passieren!!!!???
        ZB entscheide ob als nächstes GO Augerufen wird... ob zB. receiveFlag oder __flags weitergegeben werden soll
        */

        n = 0; //add call to SCIOn receive...
        DEBUG_LOG("|----->received %d messages over SCION connection", n);

        //TODO remove recvmmsg()
        DEBUG_LOG("TODO remove recvmmsg()!!!!");
        n = recvmmsg(__fd, __vmessages, __vlen, __flags, __tmo);
        DEBUG_LOG("|----->received %d messages over NON-scion connection", n);
    }
    else
    {
        n = recvmmsg(__fd, __vmessages, __vlen, __flags, __tmo);
        DEBUG_LOG("|----->received %d messages over NON-scion connection", n);
    }

    printMMSGHDR(__vmessages, n);

    return n;
}

/*Returns the number of ready descriptors, or -1 for errors.*/
int SCION_select(int __nfds, fd_set *__restrict __readfds,
                 fd_set *__restrict __writefds,
                 fd_set *__restrict __exceptfds,
                 struct timeval *__restrict __timeout)
{

    DEBUG_LOG("SCION_select(...) called....");
    int n = SCIONselect(__nfds, __readfds, __writefds, __exceptfds, __timeout);
    DEBUG_LOG("SCION_select(...) found %d ready fd's", n);

    //Debug stuff
    int readyFDs = n;
    for (int fd = 0; readyFDs && fd <= highest_fd; fd++)
    { //mefi84 man geht alle FD's durch...
        if (__exceptfds && FD_ISSET(fd, __exceptfds))
        {
            DEBUG_LOG("SCION_select(...) fd=%d reported an exception", fd);
            readyFDs--;
        }

        if (__readfds && FD_ISSET(fd, __readfds))
        {
            DEBUG_LOG("SCION_select(...) fd=%d reported file input", fd);
            readyFDs--;
        }

        if (__writefds && FD_ISSET(fd, __writefds))
        {
            DEBUG_LOG("SCION_select(...) fd=%d reported file output", fd);
            readyFDs--;
        }
    }

    return n;
}
