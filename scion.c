#include "scion.h"

//#include "scion_api.h" 


static int socked_mapping[1024];


void SCION_Initialise(){
    memset(socked_mapping, 0, 1024*sizeof(int)); //needed?
}


void SCION_TestCall(int a){
    printf("SCION_TestCall:: a=%d\n",a);
}



int SCION_close(int sock_fd){
    DEBUG_LOG("Closing socket %d", sock_fd);
    return close(sock_fd);
    //return SCIONgoclose(sock_fd);
}

/* Emulates "return socket (__domain, __type,__protocol)" */
int SCION_socket (int __domain, int __type, int __protocol){
    int fd = socket (__domain, __type,__protocol);
    DEBUG_LOG("Created socket domain=%d type=%d protocol=%d", __domain, __type, __protocol);

    //c2go scion api
    int fd2 = SCIONgosocket(__domain, __type, __protocol);
    printf("fd2=%d\n", fd2);
    
    return fd;
}


int SCION_setsockopt (int __fd, int __level, int __optname, const void *__optval, socklen_t __optlen){
    DEBUG_LOG("Setting options fd=%d level=%d optname=%d", __fd, __level, __optname);
    return setsockopt (__fd, __level, __optname, __optval, __optlen); 
}

int SCION_getsockopt (int __fd, int __level, int __optname, void *__restrict __optval, socklen_t *__restrict __optlen){
      DEBUG_LOG("Getting options fd=%d level=%d optname=%d", __fd, __level, __optname);
      return getsockopt (__fd, __level, __optname, __optval, __optlen);
}


int SCION_connect (int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len){
    DEBUG_LOG("Connecting socket fd=%d to TBD", __fd);// falsch, UTI_IPSockAddrToString( (IPSockAddr *) &__addr));
    return connect (__fd, __addr, __len);
}


ssize_t SCION_sendmsg (int __fd, const struct msghdr *__message, int __flags){
    DEBUG_LOG("Sending message on socket fd=%d", __fd);
    int status = sendmsg (__fd, __message, __flags);

    /*
    typedef struct{
         int msg_namelen;
         int msg_iovlen;
     } cstruct;

    struct cstruct testmsg = {2,4};
    */

    int status2 = SCIONgosendmsg(__fd, __message, __flags);
    DEBUG_LOG("SCIONgosendmsg::Sending message on socket fd=%d status=%d", __fd, status2);

    return status;
}


int SCION_recvmmsg (int __fd, struct mmsghdr *__vmessages, unsigned int __vlen, int __flags, struct timespec *__tmo){
    DEBUG_LOG("Receiving message on socket fd=%d", __fd);
    return recvmmsg (__fd, __vmessages, __vlen, __flags, __tmo);
}
