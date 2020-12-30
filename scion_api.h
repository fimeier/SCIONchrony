/* Code generated by cmd/cgo; DO NOT EDIT. */

/* package command-line-arguments */


#line 1 "cgo-builtin-export-prolog"

#include <stddef.h> /* for ptrdiff_t below */

#ifndef GO_CGO_EXPORT_PROLOGUE_H
#define GO_CGO_EXPORT_PROLOGUE_H

#ifndef GO_CGO_GOSTRING_TYPEDEF
typedef struct { const char *p; ptrdiff_t n; } _GoString_;
#endif

#endif

/* Start of preamble from import "C" comments.  */


#line 3 "scion_api.go"
 #include "config.h"
 #include "ntp.h"
 #include <sys/types.h>
 #include <sys/socket.h>
 #include <sys/select.h>
 #include <linux/errqueue.h>
 typedef struct fdInfo *fdInfoPtr;
 typedef const struct msghdr *msghdrConstPtr;
 typedef struct timeval *timevalPtr;
 typedef fd_set *fdsetPtr;
 typedef struct mmsghdr *mmsghdrPtr;
 typedef struct timespec *timespecPtr;
 typedef char *charPtr;
 typedef char *intPtr;
 #ifndef _SCION_API_H
 #define _SCION_API_H
 #include "scion.h"
 #endif

#line 1 "cgo-generated-wrapper"


/* End of preamble from import "C" comments.  */


/* Start of boilerplate cgo prologue.  */
#line 1 "cgo-gcc-export-header-prolog"

#ifndef GO_CGO_PROLOGUE_H
#define GO_CGO_PROLOGUE_H

typedef signed char GoInt8;
typedef unsigned char GoUint8;
typedef short GoInt16;
typedef unsigned short GoUint16;
typedef int GoInt32;
typedef unsigned int GoUint32;
typedef long long GoInt64;
typedef unsigned long long GoUint64;
typedef GoInt64 GoInt;
typedef GoUint64 GoUint;
typedef __SIZE_TYPE__ GoUintptr;
typedef float GoFloat32;
typedef double GoFloat64;
typedef float _Complex GoComplex64;
typedef double _Complex GoComplex128;

/*
  static assertion to make sure the file is being used on architecture
  at least with matching size of GoInt.
*/
typedef char _check_for_64_bit_pointer_matching_GoInt[sizeof(void*)==64/8 ? 1:-1];

#ifndef GO_CGO_GOSTRING_TYPEDEF
typedef _GoString_ GoString;
#endif
typedef void *GoMap;
typedef void *GoChan;
typedef struct { void *t; void *v; } GoInterface;
typedef struct { void *data; GoInt len; GoInt cap; } GoSlice;

#endif

/* End of boilerplate cgo prologue.  */

#ifdef __cplusplus
extern "C" {
#endif


// SetSciondAddr Sets the daemon address
extern int SetSciondAddr(char* _sciondAddr);

// SetLocalAddr registers Chrony's SCION address (ex: 1-ff00:0:112,10.80.45.83)
extern int SetLocalAddr(char* _localAddr);
extern int SCIONgoconnect(int _fd);
extern int SCIONgosetsockopt(int _fd);
extern int SCIONgosocket(int domain, int _type, int protocol, fdInfoPtr sinfo);
extern int SCIONgoclose(int _fd);

/*
Optimierung nötig!!!!

Warning: Chronyd is using select() as a timeout mechanism
=> "Iff chrony is a client and plans to send a msg in 60sec, it will call select() with an appropriate timeout, return without any ready fd's and then check for sendtimeouts...."
REMARK: At the moment there is no write-Queue => all Flags will be set to  zero if present
	fmt.Printf("Before calling select: readfds=%v\n", readfds)
	n, err := syscall.Select(int(nfds),
		(*syscall.FdSet)(unsafe.Pointer(readfds)),
		(*syscall.FdSet)(unsafe.Pointer(writefds)),
		(*syscall.FdSet)(unsafe.Pointer(exceptfds)),
		(*syscall.Timeval)(unsafe.Pointer(timeout)))
*/
extern int SCIONselect(int nfds, fdsetPtr readfds, fdsetPtr writefds, fdsetPtr exceptfds, timevalPtr timeout);
extern ssize_t SCIONgosendmsg(int _fd, msghdrConstPtr message, int flags);

// SCIONgorecvmmsg collects the received messages and returns them.... but ist not the one actively receiving the stuff
extern int SCIONgorecvmmsg(int _fd, mmsghdrPtr vmessages, unsigned int vlen, int flags, timespecPtr tmo);

#ifdef __cplusplus
}
#endif
