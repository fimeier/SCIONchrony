package main

// #include <sys/types.h>
// #include <sys/socket.h>
// #include <sys/select.h>
// #include <linux/errqueue.h>
// typedef struct cmsghdr *cmsghdrPtr;
// cmsghdrPtr cmsgFirstHdr(struct msghdr *msg_hdr)
// {
//     return CMSG_FIRSTHDR(msg_hdr);
// }
// typedef unsigned char *ucharPtr;
// ucharPtr cmsgData(struct cmsghdr *cmsg)
// {
//     return CMSG_DATA(cmsg);
// }
// cmsghdrPtr cmsgNextHdr(struct msghdr *msg_hdr, struct cmsghdr *cmsg)
// {
//     return CMSG_NXTHDR(msg_hdr,cmsg);
// }
// size_t cmsgLen(size_t len)
// {
//     return CMSG_LEN(len);
// }
// size_t cmsgSpace(size_t len)
// {
//     return CMSG_SPACE(len);
// }
import "C"

//I do not use this
// #define CMSG_FIRSTHDR2(mhdr) ((size_t) (mhdr)->msg_controllen >= sizeof (struct cmsghdr) ? (struct cmsghdr *) (mhdr)->msg_control : (struct cmsghdr *) 0)

func cmsgFirstHdr(msghdr *C.struct_msghdr) *C.struct_cmsghdr {
	return C.cmsgFirstHdr(msghdr)
}

func cmsgData(cmsg *C.struct_cmsghdr) *C.uchar {
	return C.cmsgData(cmsg)
}

func cmsgNextHdr(msghdr *C.struct_msghdr, cmsg *C.struct_cmsghdr) *C.struct_cmsghdr {
	return C.cmsgNextHdr(msghdr, cmsg)
}

func cmsgLen(len C.size_t) C.size_t {
	return C.cmsgLen(len)
}

func cmsgSpace(len C.size_t) C.size_t {
	return C.cmsgSpace(len)
}
