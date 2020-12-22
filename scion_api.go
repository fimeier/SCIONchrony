package main

// #include "config.h"
// #include "ntp.h"
// #include <sys/types.h>
// #include <sys/socket.h>
// #include <sys/select.h>
// typedef struct fdInfo *fdInfoPtr;
// typedef const struct msghdr *msghdrConstPtr;
// typedef struct timeval *timevalPtr;
// typedef fd_set *fdsetPtr;
// typedef struct mmsghdr *mmsghdrPtr;
// typedef struct timespec *timespecPtr;
// typedef char *charPtr;
// #ifndef _SCION_API_H
// #define _SCION_API_H
// #include "scion.h"
// #endif
import "C"
import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"syscall"
	"unsafe"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/sock/reliable/reconnect"
)

/* TODO:
-DO something useful with the Context
*/

/*
go build -buildmode=c-shared -o scion_api.so *.go
*/

/* FDSTATUS contains EVERYTHING */
type FDSTATUS struct {
	Fd                 int         //fd corresponds to the socket number as used by chrony (could also be a pseudo fd)
	Sinfo              C.fdInfoPtr //Pointer to fdInfo c-Struct
	Sent               chan int    //test entry: number of bytes sent
	remoteAddress      string
	remoteAddressSCION string
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

func init() {
	log.Printf("(Init) Changing logging behaviour....")

	log.SetFlags(log.Lshortfile | log.Ldate | log.Ltime | log.LUTC)

	if C.DEBUG == 0 {
		log.Printf("(Init) log.* Output has been disabled as #define DEBUG 0 is set")
		log.SetOutput(ioutil.Discard)
	}
	log.Printf("(Init) ....logging behaviour has been changed")

	//Add default configuration
	sciondAddr = sciond.DefaultAPIAddress
	localAddrStr = "1-ff00:0:112,10.80.45.83" //TODO parse the local address from somewhere
	localAddr, _ = snet.ParseUDPAddr(localAddrStr)
}

var sciondAddr string

// SetSciondAddr is a pretty cool function... would be even cooler without a line break :-(
//export SetSciondAddr
func SetSciondAddr(_sciondAddr *C.char) C.int {
	sciondAddr = C.GoString(C.charPtr(unsafe.Pointer(_sciondAddr)))
	log.Printf("(SetSciondAddr) Setting sciondAddr = %v", sciondAddr)
	return C.int(1)
}

var localAddr *snet.UDPAddr
var localAddrStr string

// SetLocalAddr registers Chrony's SCION address (ex: 1-ff00:0:112,10.80.45.83)
//export SetLocalAddr
func SetLocalAddr(_localAddr *C.char) C.int {
	localAddrStr = C.GoString(C.charPtr(unsafe.Pointer(_localAddr)))
	log.Printf("(SetLocalAddr) Setting localAddr = %v", localAddrStr)
	localAddr, _ = snet.ParseUDPAddr(localAddrStr)
	return C.int(1)
}

var fdstatus = make(map[int]FDSTATUS)

var fdList = make(map[int]int)
var maxFD = 1024

//export SCIONPrintState
func SCIONPrintState(fd C.int) {
	PrintState(int(fd))
}

func PrintState(fd int) {
	var state FDSTATUS
	state, ok := fdstatus[fd]
	if !ok {
		log.Printf("PrintState) There is no state available for fd=%d\n", fd)
		return
	}
	log.Printf("(PrintState) state=%v", state)

	domain := int(state.Sinfo.domain)
	_type := int(state.Sinfo._type)
	protocol := int(state.Sinfo.protocol)
	connectionType := int(state.Sinfo.connectionType)
	log.Printf("(PrintState) fd=%d domainS=%d type=%d protocolS=%d connectionType=%d sinfo=%p\n", fd, domain, _type, protocol, connectionType, state.Sinfo)
}

//export SCIONgosocket
func SCIONgosocket(domain C.int, _type C.int, protocol C.int, sinfo C.fdInfoPtr) C.int {
	fd := int(sinfo.fd)
	log.Printf("(SCIONgosocket) \"Creating socket\" %d\n", fd)

	/*
		domainS := int(sinfo.domain)
		typeS := int(sinfo._type)
		protocolS := int(sinfo.protocol)
		connectionTypeS := int(sinfo.connectionType)
		fmt.Printf("\tdomain=%d type=%d protocol=%d\n", domain, _type, protocol)
		fmt.Printf("fd=%d domainS=%d typeS=%d protocolS=%d connectionTypeS=%d\nsinfo=%v\n", fd, domainS, typeS, protocolS, connectionTypeS, sinfo)
	*/
	_, exists := fdstatus[fd]
	if exists {
		log.Printf("(SCIONgosocket) ERROR Already existing entry for fd=%d,fd")
		return C.int(-1) //TODOdefine correct behaviour
	}

	newState := FDSTATUS{Fd: fd, Sinfo: sinfo}

	fdstatus[fd] = newState

	return C.int(newState.Fd)
}

//export SCIONgoclose
func SCIONgoclose(fd C.int) C.int {
	log.Printf("(SCIONgoclose) \"Closing socket\" %d\n", fd)
	//todo: what else needs to be done?
	delete(fdstatus, int(fd))

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

//export SCIONgosendmsg
func SCIONgosendmsg(_fd C.int, message C.msghdrConstPtr, flags C.int) C.ssize_t {
	fd := int(_fd)
	status, exists := fdstatus[fd]
	if !exists {
		log.Fatal("(SCIONgosendmsg) Non-existing fdstatus[%d]\n", fd) //change this to fatal?
		return C.ssize_t(-1)                                          //TODO correct return value for sendmsg()?
	}

	status.remoteAddress = C.GoString(C.charPtr(unsafe.Pointer(&status.Sinfo.remoteAddress)))
	status.remoteAddressSCION = C.GoString(C.charPtr(unsafe.Pointer(&status.Sinfo.remoteAddressSCION)))

	//msg := copyCstructMSGHDR(message)
	msg := *(*syscall.Msghdr)(unsafe.Pointer(message))
	//ntp := copyCstructNTP(msg.Iov)
	ntp := *(*NTP_Packet)(unsafe.Pointer(msg.Iov.Base))

	//fmt.Printf("msg = %v\n", msg)
	log.Printf("(SCIONgosendmsg) sending ntp packet %v to %v i.e. %v\n", ntp, status.remoteAddress, status.remoteAddressSCION)

	return C.ssize_t(sendmsgOverScion(msg.Iov, &status))
}

func sendmsgOverScion(iovec *syscall.Iovec, status *FDSTATUS) (bytesSent int) {

	iovecLen := iovec.Len
	iovecBase := iovec.Base

	payload := C.GoBytes(unsafe.Pointer(iovecBase), C.int(iovecLen))

	// test it
	/*
		ntp := *(*NTP_Packet)(C.CBytes(payload2))
		fmt.Printf("ntp = %v\n", ntp)
	*/
	//fmt.Printf("iovecLen = %v\tiovecBase = %v\tpayload = %v\n", iovecLen, iovecBase, payload)

	var remoteAddr *snet.UDPAddr
	remoteAddr, _ = snet.ParseUDPAddr(status.remoteAddressSCION)

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

	log.Printf("(sendmsgOverScion) Available paths to %v:\n", remoteAddr.IA)
	for _, p := range ps {
		log.Printf("(sendmsgOverScion) \t%v\n", p)
	}

	sp := ps[0]
	log.Printf("(sendmsgOverScion) Selected path to %v: %v\n", remoteAddr.IA, sp)

	remoteAddr.Path = sp.Path()
	remoteAddr.NextHop = sp.UnderlayNextHop()

	localAddr.Host.Port = 0 //ignore user defined srcport

	conn, localPort, err := pds.Register(ctx, localAddr.IA, localAddr.Host, addr.SvcNone)
	if err != nil {
		log.Fatal("Failed to register client socket:", err)
	}

	log.Printf("(sendmsgOverScion) Sending in %v on %v:%d - %v\n", localAddr.IA, localAddr.Host.IP, localPort, addr.SvcNone)
	log.Printf("(sendmsgOverScion) \tDestination:  IP:Port ist in %v on %v:%d - %v\n", remoteAddr.IA, remoteAddr.Host.IP, remoteAddr.Host.Port, addr.SvcNone)

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
		log.Printf("(sendmsgOverScion) [%d] Failed to write packet: %v\n", err)
		return -1
	}

	return len(payload)

}

//export SCIONgorecvmmsg
func SCIONgorecvmmsg(fd C.int, vmessages C.mmsghdrPtr, vlen C.uint, flags C.int, tmo C.timespecPtr) C.int {

	return C.int(42)

}

/* eigentlich nur ein "cast" */
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

/* eigentlich nur ein "cast" */
func copyCstructNTP(iovec *syscall.Iovec) (ntp NTP_Packet) {

	/* stimmt überhaupt nicht */
	//ntpSize := unsafe.Sizeof(NTP_Packet{})
	//iolen := iovec.Len
	//fmt.Println("iolen = %d       ntpSize = %d", iolen, ntpSize)

	ntp = *(*NTP_Packet)(unsafe.Pointer(iovec.Base))
	//fmt.Printf("ntp = %v\n", ntp)
	return ntp

}

func main() {
	fmt.Println("Doing some tests...")
	fd := 666

	var state FDSTATUS
	ok := false
	for !ok {
		state, ok = fdstatus[fd]
		if !ok {
			log.Printf("adding state for fd=%d", fd)
			state := FDSTATUS{Fd: fd}
			fdstatus[fd] = state
		}
	}

	fmt.Printf("state for fd=%d is:\n%v\n", state.Fd, state)
}

/*
func PingSomething() error {
	fmt.Println("I ping something now because I can")

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
*/

/*
//export SendSomething
func SendSomething() error {
	fmt.Println("I send something now because I can")

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
*/

/*func GetFreeFD() int {
	for fd := 1; fd <= maxFD; fd++ {
		if fdList[fd] == 0 {
			fdList[fd] = 1
			return fd
		}

	}
	return -1
}*/

/*func DeleteFD(fd int) {
	fdList[fd] = 0
}*/
