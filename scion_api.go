package main

// #include "ntp.h"
// #include <sys/types.h>
// #include <sys/socket.h>
// #include <sys/select.h>
// typedef const struct msghdr *msghdrConstPtr;
// typedef struct timeval *timevalPtr;
// typedef fd_set *fdsetPtr;
// typedef struct mmsghdr *mmsghdrPtr;
// typedef struct timespec *timespecPtr;
import "C"
import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/addrutil"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/sock/reliable/reconnect"
	"github.com/scionproto/scion/go/pkg/app"
	"github.com/scionproto/scion/go/pkg/ping"
)

/*
go build -buildmode=c-shared -o scion_api.so *.go
*/

var fdList = make(map[int]int)
var maxFD = 1024

func GetFreeFD() int {
	for fd := 1; fd <= maxFD; fd++ {
		if fdList[fd] == 0 {
			fdList[fd] = 1
			return fd
		}

	}
	return -1
}

func DeleteFD(fd int) {
	fdList[fd] = 0
}

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

//export SCIONselect
func SCIONselect(nfds C.int, readfds C.fdsetPtr, writefds C.fdsetPtr, exceptfds C.fdsetPtr, timeout C.timevalPtr) C.int {

	//emulate select
	fmt.Printf("Before calling select: readfds=%v\n", readfds)
	n, err := syscall.Select(int(nfds),
		(*syscall.FdSet)(unsafe.Pointer(readfds)),
		(*syscall.FdSet)(unsafe.Pointer(writefds)),
		(*syscall.FdSet)(unsafe.Pointer(exceptfds)),
		(*syscall.Timeval)(unsafe.Pointer(timeout)))

	fmt.Printf("After calling select: readfds=%v\n", readfds)

	if err == nil {
		return C.int(n)
	}

	return C.int(-1) //Todo err to errno?
}

type NTP_int64 struct {
	hi uint32
	lo uint32
}

type NTP_Packet struct {
	/* C to GO datatypes
	uint8_t == unsigned char => uint8 ?
	int8_t == signed char =>  int8?
	NTP_int64 == unsigned int => uint32
	*/
	lvm             uint8 //mefi84 LeapIndicator(2)||VersionNumber(3)||Mode(3) == 8 Bits
	stratum         uint8
	poll            int8
	precision       int8
	root_delay      uint32
	root_dispersion uint32
	reference_id    uint32
	reference_ts    NTP_int64
	originate_ts    NTP_int64
	receive_ts      NTP_int64
	transmit_ts     NTP_int64

	/* header length == 48 => extensions are not used*/
	//extensions [C.NTP_MAX_EXTENSIONS_LENGTH]uint8
}

func copyCstructNTP(iovec *syscall.Iovec) (ntp NTP_Packet) {

	/* stimmt überhaupt nicht */
	//ntpSize := unsafe.Sizeof(NTP_Packet{})
	//iolen := iovec.Len
	//fmt.Println("iolen = %d       ntpSize = %d", iolen, ntpSize)

	ntp = *(*NTP_Packet)(unsafe.Pointer(iovec.Base))
	//fmt.Printf("ntp = %v\n", ntp)
	return ntp

}

//export SCIONgosendmsg
func SCIONgosendmsg(fd C.int, message C.msghdrConstPtr, flags C.int, scionAddressC *C.char) C.ssize_t {
	scionAddress := C.GoString(scionAddressC)
	msg := copyCstructMSGHDR(message)
	ntp := copyCstructNTP(msg.Iov)
	//fmt.Printf("msg = %v\n", msg)
	log.Printf("scion_api.GO:(SCIONgosendmsg) sending ntp packet %v to %v\n", ntp, scionAddress)

	return C.ssize_t(sendmsgOverScion(msg.Iov, scionAddress))
}

func sendmsgOverScion(iovec *syscall.Iovec, scionAddress string) (bytesSent int) {

	iovecLen := iovec.Len
	iovecBase := iovec.Base

	payload := C.GoBytes(unsafe.Pointer(iovecBase), C.int(iovecLen))

	// test it
	/*
		ntp := *(*NTP_Packet)(C.CBytes(payload2))
		fmt.Printf("ntp = %v\n", ntp)
	*/
	//fmt.Printf("iovecLen = %v\tiovecBase = %v\tpayload = %v\n", iovecLen, iovecBase, payload)

	var sciondAddr string
	sciondAddr = "127.0.0.1:30255"
	var localAddr *snet.UDPAddr
	localAddr, _ = snet.ParseUDPAddr("1-ff00:0:112,10.80.45.83") //TODO parse the local address from somewhere

	//var remoteAddr *snet.UDPAddr
	//remoteAddr, _ = snet.ParseUDPAddr("1-ff00:0:110,10.80.45.83:11111")

	var remoteAddr *snet.UDPAddr
	remoteAddr, _ = snet.ParseUDPAddr(scionAddress)
	//log.Printf("scion_api.GO:(sendmsgOverScion) remoteAddr2 %v\n", remoteAddr2)

	var err error
	ctx := context.Background()
	sdc, err := sciond.NewService(sciondAddr).Connect(ctx)
	if err != nil {
		log.Fatal("Failed to create SCION connector:", err)
	}
	pds := &snet.DefaultPacketDispatcherService{
		Dispatcher: reconnect.NewDispatcherService(reliable.NewDispatcher("")),
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: sciond.RevHandler{Connector: sdc},
		},
	}

	ps, err := sdc.Paths(ctx, remoteAddr.IA, localAddr.IA, sciond.PathReqFlags{Refresh: true})
	if err != nil {
		log.Fatal("Failed to lookup core paths: %v:", err)
	}

	log.Printf("scion_api.GO:(sendmsgOverScion) Available paths to %v:\n", remoteAddr.IA)
	for _, p := range ps {
		log.Printf("scion_api.GO:(sendmsgOverScion) \t%v\n", p)
	}

	sp := ps[0]
	log.Printf("scion_api.GO:(sendmsgOverScion) Selected path to %v: %v\n", remoteAddr.IA, sp)

	remoteAddr.Path = sp.Path()
	remoteAddr.NextHop = sp.UnderlayNextHop()

	localAddr.Host.Port = 0 //ignore user defined srcport

	conn, localPort, err := pds.Register(ctx, localAddr.IA, localAddr.Host, addr.SvcNone)
	if err != nil {
		log.Fatal("Failed to register client socket:", err)
	}

	log.Printf("scion_api.GO:(sendmsgOverScion) Sending in %v on %v:%d - %v\n", localAddr.IA, localAddr.Host.IP, localPort, addr.SvcNone)
	log.Printf("scion_api.GO:(sendmsgOverScion) \tDestination:  IP:Port ist in %v on %v:%d - %v\n", remoteAddr.IA, remoteAddr.Host.IP, remoteAddr.Host.Port, addr.SvcNone)

	pkt := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Source: snet.SCIONAddress{
				IA:   localAddr.IA,
				Host: addr.HostFromIP(localAddr.Host.IP),
			},
			Destination: snet.SCIONAddress{
				IA:   remoteAddr.IA,
				Host: addr.HostFromIP(remoteAddr.Host.IP),
			},
			Path: remoteAddr.Path,
			Payload: snet.UDPPayload{
				SrcPort: localPort,
				DstPort: uint16(remoteAddr.Host.Port),
				Payload: payload, //[]byte("Hello, world!"),
			},
		},
	}

	err = conn.WriteTo(pkt, remoteAddr.NextHop)
	if err != nil {
		log.Printf("scion_api.GO:(sendmsgOverScion) [%d] Failed to write packet: %v\n", err)
		return -1
	}

	return len(payload)

}

func copyCstructMSGHDR(message C.msghdrConstPtr) (msg syscall.Msghdr) {

	// C DATASTRUCTURE
	// struct msghdr {

	//----->The msg_name and msg_namelen members are used when the socket is not connected (e.g., an unconnected UDP socket).
	// 	void         *msg_name;        /* protocol address */
	// 	socklen_t     msg_namelen;     /* size of protocol address */

	//----->The msg_iov and msg_iovlen members specify the array of input or output buffers (the array of iovec structures),
	// 	struct iovec *msg_iov;         /* scatter/gather array */
	// 	int           msg_iovlen;      /* # elements in msg_iov */

	//---->The msg_control and msg_controllen members specify the location and size of the optional ancillary data.
	// 	void         *msg_control;     /* ancillary data (cmsghdr struct) */
	// 	socklen_t     msg_controllen;  /* length of ancillary data */

	//---->The msg_flags member is IGNORED by sendmsg because this function USES the flags argument to drive its output processing. This means if we want to set the MSG_DONTWAIT flag in a call to sendmsg, we set the flags argument to this value; setting the msg_flags member to this value has no effect.
	// 	int           msg_flags;       /* flags returned by recvmsg() */
	//   };

	/* GO DATASTRUCTURE
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

	msg = *(*syscall.Msghdr)(unsafe.Pointer(message))
	//s, _ := json.MarshalIndent(msg, "", "\t")
	//fmt.Println(string(s))

	return msg

}

//export SendSomething
func SendSomething() error {
	fmt.Println("I send something now because I can")

	/* Dummy Setting*/
	//count := uint16(1)
	sciondAddress := sciond.DefaultAPIAddress
	dispatcher := reliable.DefaultDispPath
	//interval := time.Second
	//timeout := time.Second
	interactive := false
	refresh := false
	sequence := ""
	noColor := false
	var localString net.IP
	remoteString := "1-ff00:0:110,10.80.45.83:11111"
	//size := 0

	remote, err := snet.ParseUDPAddr(remoteString)
	if err != nil {
		return serrors.WrapStr("parsing remote", err)
	}

	ctx, cancelF := context.WithTimeout(context.Background(), time.Second*3600) //mefi84 *3600 added
	defer cancelF()
	sd, err := sciond.NewService(sciondAddress).Connect(ctx)
	if err != nil {
		return serrors.WrapStr("connecting to SCION Daemon", err)
	}

	info, err := app.QueryASInfo(context.Background(), sd)
	if err != nil {
		return err
	}

	path, err := app.ChoosePath(context.Background(), sd, remote.IA,
		interactive, refresh, sequence,
		app.WithDisableColor(noColor))
	if err != nil {
		return err
	}
	remote.Path = path.Path()
	remote.NextHop = path.UnderlayNextHop()

	localIP := localString
	if localIP == nil {
		target := remote.Host.IP
		if remote.NextHop != nil {
			target = remote.NextHop.IP
		}
		if localIP, err = addrutil.ResolveLocal(target); err != nil {
			return serrors.WrapStr("resolving local address", err)

		}
		fmt.Printf("Resolved local address:\n  %s\n", localIP)
	}
	fmt.Printf("Using path:\n  %s\n\n", path)
	local := &snet.UDPAddr{
		IA: info.IA,
		Host: &net.UDPAddr{IP: localIP,
			Port: 0}, //or client's use automatic port
	}

	svc := snet.DefaultPacketDispatcherService{
		Dispatcher:  reliable.NewDispatcher(dispatcher),
		SCMPHandler: snet.DefaultSCMPHandler{},
	}
	conn, port, err := svc.Register(ctx, local.IA, local.Host, addr.SvcNone)
	if err != nil {
		log.Fatal("Failed to register client socket:", err)
	}

	log.Printf("Sending in %v on %v:%d - %v\n", local.IA, local.Host.IP, port, addr.SvcNone)

	pkt := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Source: snet.SCIONAddress{
				IA:   local.IA,
				Host: addr.HostFromIP(local.Host.IP),
			},
			Destination: snet.SCIONAddress{
				IA:   remote.IA,
				Host: addr.HostFromIP(remote.Host.IP),
			},
			Path: remote.Path,
			Payload: snet.UDPPayload{
				SrcPort: port,
				DstPort: uint16(remote.Host.Port),
				Payload: []byte("Hello, world!"),
			},
		},
	}

	err = conn.WriteTo(pkt, remote.NextHop)
	if err != nil {
		log.Printf("[%d] Failed to write packet: %v\n", err)
	}

	return nil

}

func PingSomething() error {
	fmt.Println("I ping something now because I can")

	/* Dummy Setting*/
	count := uint16(1)
	sciondAddress := sciond.DefaultAPIAddress
	dispatcher := reliable.DefaultDispPath
	interval := time.Second
	timeout := time.Second
	interactive := false
	refresh := false
	sequence := ""
	noColor := false
	var localString net.IP
	remoteString := "1-ff00:0:110,10.80.45.83"
	size := 0

	remote, err := snet.ParseUDPAddr(remoteString)
	if err != nil {
		return serrors.WrapStr("parsing remote", err)
	}

	ctx, cancelF := context.WithTimeout(context.Background(), time.Second*3600) //mefi84 *3600 added
	defer cancelF()
	sd, err := sciond.NewService(sciondAddress).Connect(ctx)
	if err != nil {
		return serrors.WrapStr("connecting to SCION Daemon", err)
	}

	info, err := app.QueryASInfo(context.Background(), sd)
	if err != nil {
		return err
	}

	path, err := app.ChoosePath(context.Background(), sd, remote.IA,
		interactive, refresh, sequence,
		app.WithDisableColor(noColor))
	if err != nil {
		return err
	}
	remote.Path = path.Path()
	remote.NextHop = path.UnderlayNextHop()

	localIP := localString
	if localIP == nil {
		target := remote.Host.IP
		if remote.NextHop != nil {
			target = remote.NextHop.IP
		}
		if localIP, err = addrutil.ResolveLocal(target); err != nil {
			return serrors.WrapStr("resolving local address", err)

		}
		fmt.Printf("Resolved local address:\n  %s\n", localIP)
	}
	fmt.Printf("Using path:\n  %s\n\n", path)
	local := &snet.UDPAddr{
		IA:   info.IA,
		Host: &net.UDPAddr{IP: localIP},
	}

	stats, err := ping.Run(ctx, ping.Config{
		Dispatcher:  reliable.NewDispatcher(dispatcher),
		Attempts:    count,
		Interval:    interval,
		Timeout:     timeout,
		Local:       local,
		Remote:      remote,
		PayloadSize: int(size),
		ErrHandler: func(err error) {
			fmt.Fprintf(os.Stderr, "ERROR: %s\n", err)
		},
		UpdateHandler: func(update ping.Update) {
			var additional string
			switch update.State {
			case ping.AfterTimeout:
				additional = " state=After timeout"
			case ping.OutOfOrder:
				additional = " state=Out of Order"
			case ping.Duplicate:
				additional = " state=Duplicate"
			}
			fmt.Fprintf(os.Stdout, "%d bytes from %s,%s: scmp_seq=%d time=%s%s\n",
				update.Size, update.Source.IA, update.Source.Host, update.Sequence,
				update.RTT, additional)
		},
	})

	fmt.Println("%v", stats)

	return nil
}

//export SCIONgorecvmmsg
func SCIONgorecvmmsg(fd C.int, vmessages C.mmsghdrPtr, vlen C.uint, flags C.int, tmo C.timespecPtr) C.int {

	return C.int(42)

}

func main() {
	fmt.Println("Calling ping tools..")
	PingSomething()
}
