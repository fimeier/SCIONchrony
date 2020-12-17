#include "config.h"
#include "logging.h"
#include "util.h"
#include "sched.h"
#include "array.h"
#include "ntp_sources.h"
#include "cmdparse.h"

#include "socket.h"
#include "addressing.h"


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

#include "scion_api.h"


#define NTP_PORT 123

#define MAXADDRESSLENGTH 100
#define MAXMESSAGESIZE 1200

/* Used for debuggin
   _IP_ <=> packets/structures in c-World
*/
typedef enum{
   SCION_IP_TX_ERR_MSG,
   SCION_IP_TX_NTP_MSG,
   SCION_IP_RX_NTP_MSG,
} SCION_TYPE;

typedef enum
{
   SCION_FILE_INPUT = 0,
   SCION_MSG_ERRQUEUE,
} SCION_RECEIVE_FLAGS;

typedef enum
{
   SCION_LE_UNDEFINED = 0,
   SCION_IPPROTO_IP,
   SCION_SOL_SOCKET,
   SCION_LE_LEN,
} SCION_LEVEL;

typedef enum
{
   SCION_OPT_UNDEFINED = 0,
   SCION_IP_PKTINFO,
   SCION_IP_FREEBIND,
   SCION_SO_SELECT_ERR_QUEUE,
   SCION_SO_TIMESTAMPING,
   SCION_SO_REUSEADDR,
   SCION_SO_REUSEPORT,
   SCION_SO_BROADCAST,
   SCION_OPTNAME_LEN,
} SCION_OPTNAME;

typedef enum
{
   NOT_CONNECTED = 0,
   CONNECTED_TO_NTP_SERVER,
   IS_NTP_SERVER,
} SCION_CONNECTION_TYPE; //rename this

typedef struct fdInfo
{
   int fd;
   int domain;
   int type;
   int protocol;
   int connectionType; //rename this
   IPSockAddr boundTo;
   char remoteAddress[MAXADDRESSLENGTH];
   char remoteAddressSCION[MAXADDRESSLENGTH];
   int level_optname_value[SCION_LE_LEN][SCION_OPTNAME_LEN]; //optval !=0 0==disabled
   //int optval[SCION_OPTNAME_LEN];

} fdInfo;


typedef struct addressMapping
{
   char addressIP[MAXADDRESSLENGTH];
   char addressSCION[MAXADDRESSLENGTH];
} addressMapping; 



void SCION_Initialise();

void SCION_parse_source(char *line, char *type);



/* Socket Operations */

/* Close the file descriptor FD.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern int SCION_close(int __fd);

extern int SCION_socket(int __domain, int __type, int __protocol) __THROW;

/* Set socket FD's option OPTNAME at protocol level LEVEL
   to *OPTVAL (which is OPTLEN bytes long).
   Returns 0 on success, -1 for errors.  */
extern int SCION_setsockopt(int __fd, int __level, int __optname,
                            const void *__optval, socklen_t __optlen) __THROW;

/* Put the current value for socket FD's option OPTNAME at protocol level LEVEL
   into OPTVAL (which is *OPTLEN bytes long), and set *OPTLEN to the value's
   actual length.  Returns 0 on success, -1 for errors.  */
extern int SCION_getsockopt(int __fd, int __level, int __optname,
                            void *__restrict __optval,
                            socklen_t *__restrict __optlen) __THROW;

/* Give the socket FD the local address ADDR (which is LEN bytes long).  
   On success, zero is returned.  On error, -1 is returned, and errno is
       set appropriately.*/
extern int SCION_bind (int __fd, struct sockaddr *__addr, socklen_t __len)
     __THROW;   //__CONST_SOCKADDR_ARG

/* Open a connection on socket FD to peer at ADDR (which LEN bytes long).
   For connectionless socket types, just set the default address to send to
   and the only address from which to accept transmissions.
   Return 0 on success, -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.
   
   TODO: I added IPSockAddr *addr because to access address (solve this directly by using __addr)
   */
extern int SCION_connect(int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len, IPSockAddr *addr);

/* Send a message described MESSAGE on socket FD.
   Returns the number of bytes sent, or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern ssize_t SCION_sendmsg(int __fd, const struct msghdr *__message,
                             int __flags);

/* Receive up to VLEN messages as described by VMESSAGES from socket FD.
   Returns the number of messages received or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern int SCION_recvmmsg(int __fd, struct mmsghdr *__vmessages,
                          unsigned int __vlen, int __flags,
                          struct timespec *__tmo);

/* Check the first NFDS descriptors each in READFDS (if not NULL) for read
   readiness, in WRITEFDS (if not NULL) for write readiness, and in EXCEPTFDS
   (if not NULL) for exceptional conditions.  If TIMEOUT is not NULL, time out
   after waiting the interval specified therein.  Returns the number of ready
   descriptors, or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern int SCION_select(int __nfds, fd_set *__restrict __readfds,
                        fd_set *__restrict __writefds,
                        fd_set *__restrict __exceptfds,
                        struct timeval *__restrict __timeout);




/* some helpers */

int SCION_extract_udp_data(unsigned char *msg, NTP_Remote_Address *remote_addr, int len);

void printNTPPacket(void * ntpPacket, int len);


void printMMSGHDR(struct mmsghdr *msgvec, int n, int SCION_TYPE);

