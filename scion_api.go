package main

// #include <sys/socket.h>
// typedef const struct msghdr *msghdrConstPtr;
// typedef struct cstruct{
//   socklen_t len;
//   size_t iovlen;
// } cstruct;
import "C"
import (
	"encoding/json"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

/*
go build -buildmode=c-shared -o scion_api.so *.go
*/

//export SCIONgosocket
func SCIONgosocket(domain C.int, _type C.int, protocol C.int) C.int {
	return C.int(GetFreeFD())
}

//export SCIONgoclose
func SCIONgoclose(fd C.int) C.int {

	DeleteFD(int(fd))

	//TODO close() returns zero on success.  On error, -1 is returned, and errno
	//is set appropriately.
	return C.int(0)
}

// #include <sys/socket.h>
// typedef const struct msghdr *msghdrConstPtr;
//export SCIONgosendmsg
func SCIONgosendmsg(fd C.int, message C.msghdrConstPtr, flags C.int) C.ssize_t {

	println("GO::SCIONgosendmsg:: Sending message using socket", fd)

	_ = msghdrToMsghr(message)

	/*
			msghdr = message

			fmt.Println(msghdr)
			fmt.Printf("%+v\n", msghdr)



		//Fake using imported package
		/*
			uid := unix.Getuid()
			fmt.Printf("uid type== %T\n", uid)
			fmt.Println("uid ==", uid)
			euid := unix.Geteuid()
			fmt.Printf("euid type== %T\n", euid)
			fmt.Println("euid ==", euid)
	*/

	return 33
}

func msghdrToMsghr(message C.msghdrConstPtr) (msg unix.Msghdr) {
	//Debuggin
	fmt.Printf("msg_name type == %T\n", message.msg_name)
	fmt.Printf("msg_namelen type == %T\n", message.msg_namelen)
	fmt.Printf("msg_iov type == %T\n", message.msg_iov)
	fmt.Printf("msg_iovlen type == %T\n", message.msg_iovlen)
	fmt.Printf("msg_control type == %T\n", message.msg_control)
	fmt.Printf("msg_controllen type == %T\n", message.msg_controllen)
	fmt.Printf("msg_flags type == %T\n", message.msg_flags)

	/*
		type Msghdr struct {
			Name       *byte
			Namelen    uint32
			Iov        *Iovec
			Iovlen     uint64
			Control    *byte
			Controllen uint64
			Flags      int32
			_          [4]byte
		}*/

	//var iov unix.Iovec

	//msg.Name = message.msg_name TODO
	msg.Namelen = uint32(message.msg_namelen)
	//msg.Iov = message.msg_iov TODO
	msg.Iovlen = uint64(message.msg_iov.iov_len)
	//msg.Control := message.msg_control TODO
	msg.Controllen = uint64(message.msg_controllen)
	msg.Flags = int32(message.msg_flags)

	//Debuggin
	s, _ := json.MarshalIndent(msg, "", "\t")
	fmt.Println(string(s))

	stats := *(*unix.Msghdr)(unsafe.Pointer(message))
	s, _ = json.MarshalIndent(stats, "", "\t")
	fmt.Println(string(s))

	return msg

}

/*
func iovToIov(iovC _Ctype_struct_iovec) (iov unix.Iovec) {
	iovC.iov_base
	//iov.Base = iovC.iov_base
	iov.Len = uint64(iovC.iov_len)
}
*/
