#include "config.h"
#include "logging.h"




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


extern void SCION_TestCall(int a);


/* Socket Operations */

/* Close the file descriptor FD.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern int SCION_close (int __fd);

extern int SCION_socket (int __domain, int __type, int __protocol) __THROW;

/* Set socket FD's option OPTNAME at protocol level LEVEL
   to *OPTVAL (which is OPTLEN bytes long).
   Returns 0 on success, -1 for errors.  */
extern int SCION_setsockopt (int __fd, int __level, int __optname,
		       const void *__optval, socklen_t __optlen) __THROW;

/* Put the current value for socket FD's option OPTNAME at protocol level LEVEL
   into OPTVAL (which is *OPTLEN bytes long), and set *OPTLEN to the value's
   actual length.  Returns 0 on success, -1 for errors.  */
extern int SCION_getsockopt (int __fd, int __level, int __optname,
		       void *__restrict __optval,
		       socklen_t *__restrict __optlen) __THROW;


/* Open a connection on socket FD to peer at ADDR (which LEN bytes long).
   For connectionless socket types, just set the default address to send to
   and the only address from which to accept transmissions.
   Return 0 on success, -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern int SCION_connect (int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len);


/* Send a message described MESSAGE on socket FD.
   Returns the number of bytes sent, or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern ssize_t SCION_sendmsg (int __fd, const struct msghdr *__message,
			int __flags);


/* Receive up to VLEN messages as described by VMESSAGES from socket FD.
   Returns the number of messages received or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern int SCION_recvmmsg (int __fd, struct mmsghdr *__vmessages,
		     unsigned int __vlen, int __flags,
		     struct timespec *__tmo);


