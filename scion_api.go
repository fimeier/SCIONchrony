package main

// #include "config.h"
// #include "ntp.h"
// #include <sys/types.h>
// #include <sys/socket.h>
// #include <sys/select.h>
// #include <linux/errqueue.h>
// typedef struct fdInfo *fdInfoPtr;
// typedef const struct msghdr *msghdrConstPtr;
// typedef struct timeval *timevalPtr;
// typedef fd_set *fdsetPtr;
// typedef struct mmsghdr *mmsghdrPtr;
// typedef struct timespec *timespecPtr;
// typedef char *charPtr;
// typedef char *intPtr;
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
	"net"
	"syscall"
	"time"
	"unsafe"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/sock/reliable/reconnect"
)

/* TODO:
-DO something useful with the Context
-CGO: Dataexchange performance (Kernel Threads?), memory model for cgo-ROutines accessing c-Pointers (sync?)
---->eignetlich sollte es "keinen" overhead geben, da lediglich Daten ausgetauscht werden
---->falls doch, daten auf andere art austauschen?
-FDSTATUS in Map..... s, exists := fdstatus[fd] s.ändern.... dann zurückspeichern.... buggy
-------->array mit fd als index auf struct ptr
-send() behaviour as it is nonblocking... start go routine? return value?
------> allenfalls rcv erst wärend erstem send starten (wie sollte logik sein...)
---> work with fdstatus[fd] or its copy....
---> non blocking send: Buffer wie lange muss dieser bestehen bleiben (mal rein für C)
-----------> Chrony überschreibt ihn im allgemeinen ja erst wenn eine nachricht empfangen wird für diesesn Socket
*/

/*
go build -buildmode=c-shared -o scion_api.so *.go
*/

//FDSTATUS contains EVERYTHING
type FDSTATUS struct {
	/*TODO: Decide how to use it/change it..... */
	Fd    int         //fd corresponds to the socket number as used by chrony (could also be a pseudo fd)
	Sinfo C.fdInfoPtr //Pointer to fdInfo c-Struct
	//nonblocking        bool
	//dgram              bool
	sent               chan int //test entry: number of bytes sent
	remoteAddress      string   //IP address
	remoteAddressSCION string
	rAddr              *snet.UDPAddr
	sdc                sciond.Connector
	pds                *snet.DefaultPacketDispatcherService
	ps                 []snet.Path
	selectedPath       snet.Path
	ctx                context.Context
	conn               snet.PacketConn
	localPortSCION     uint16        //fix this: bzw vgl mit localAddr.Host.Port = 0 //ignore user defined srcport
	connected          bool          //if set => SCIONgoconnect() finished without errors
	doneRcv            chan struct{} //close this to stop everything related to receiving
	rcvQueueNTPTS      chan rcvMsgNTPTS
	sendQueueTS        chan sendMsgTS
	rcvLogicStarted    bool
	createTxTimestamp  bool
	txKERNELts         bool //use this
	txHWts             bool //use this
	createRxTimestamp  bool //TODO Adapt logig for recv (started after connect, but before setsockopts..)

}

type rcvMsgNTPTS struct {
	pkt snet.Packet
	ov  net.UDPAddr
}
type sendMsgTS struct {
	tsType  int
	payload []byte
	ts3     C.struct_scm_timestamping
	sentTo  *snet.UDPAddr
}

const (
	tskernelhardware = iota + 1
	tskernel
	tshardware
	rxkernelhardware
	rxkernel
	rxhardware
)

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

func cancelled(done chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func init() {
	log.Printf("(Init) Changing logging behaviour....")

	log.SetFlags(log.Lshortfile | log.Ldate | log.Ltime | log.LUTC)

	/*if C.DEBUG == 0 {
		log.Printf("(Init) log.* Output has been disabled as #define DEBUG 0 is set")
		log.SetOutput(ioutil.Discard)
	}*/
	if C.GODEBUG == 0 {
		log.Printf("(Init) log.* Output has been disabled as #define GODEBUG 0 is set")
		log.SetOutput(ioutil.Discard)
	}
	log.Printf("(Init) ....logging behaviour has been changed")

	//Add default configuration
	sciondAddr = sciond.DefaultAPIAddress
	localAddrStr = "1-ff00:0:112,10.80.45.83" //TODO parse the local address from somewhere
	localAddr, _ = snet.ParseUDPAddr(localAddrStr)
	localAddr.Host.Port = 0 //ignore user defined srcport

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
	localAddr.Host.Port = 0 //ignore user defined srcport
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

//export SCIONgoconnect
func SCIONgoconnect(_fd C.int) C.int {
	fd := int(_fd)
	s, exists := fdstatus[fd]
	if !exists {
		log.Printf("(SCIONgoconnect) There is no state available for fd=%d\n", fd)
		return C.int(-1)
	}

	var err error

	s.remoteAddress = C.GoString(C.charPtr(unsafe.Pointer(&s.Sinfo.remoteAddress)))
	s.remoteAddressSCION = C.GoString(C.charPtr(unsafe.Pointer(&s.Sinfo.remoteAddressSCION)))

	s.rAddr, err = snet.ParseUDPAddr(s.remoteAddressSCION)
	if err != nil {
		log.Printf("(SCIONgoconnect) Couldn't parse \"%v\" go error: %v", s.remoteAddressSCION, err)
		return C.int(-1)
	}

	s.ctx = context.Background()
	s.sdc, err = sciond.NewService(sciondAddr).Connect(s.ctx)
	if err != nil {
		log.Printf("(SCIONgoconnect) Failed to create SCION connector:", err)
		return C.int(-1)
	}
	s.pds = &snet.DefaultPacketDispatcherService{
		Dispatcher: reconnect.NewDispatcherService(reliable.NewDispatcher("")),
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: sciond.RevHandler{Connector: s.sdc},
		},
	}

	s.ps, err = s.sdc.Paths(s.ctx, s.rAddr.IA, localAddr.IA, sciond.PathReqFlags{Refresh: true})
	if err != nil {
		log.Printf("(SCIONgoconnect) Failed to lookup core paths: %v:", err)
		return C.int(-1)
	}

	log.Printf("(SCIONgoconnect) Available paths to %v:\n", s.rAddr.IA)
	for _, p := range s.ps {
		log.Printf("(SCIONgoconnect)  \t%v\n", p)
	}

	s.selectedPath = s.ps[0]
	log.Printf("(SCIONgoconnect)  Selected path to %v: %v\n", s.rAddr.IA, s.selectedPath)

	s.rAddr.Path = s.selectedPath.Path()
	s.rAddr.NextHop = s.selectedPath.UnderlayNextHop()

	s.conn, s.localPortSCION, err = s.pds.Register(s.ctx, localAddr.IA, localAddr.Host, addr.SvcNone)
	if err != nil {
		log.Printf("(SCIONgoconnect)  Failed to register client socket:", err)
		return C.int(-1)
	}

	s.connected = true
	s.sent = make(chan int)
	s.doneRcv = make(chan struct{})
	s.rcvQueueNTPTS = make(chan rcvMsgNTPTS, int(C.MSGBUFFERSIZE))
	s.sendQueueTS = make(chan sendMsgTS, int(C.MSGBUFFERSIZE))

	//ASSUMPTION: CONNECTED_TO_NTP_SERVER => RX/TX will be activated (workarround for rcvlogic)
	//s.createRxTimestamp = true
	//s.createTxTimestamp = true

	fdstatus[fd] = s //store it back
	log.Printf("(SCIONgoconnect) Created Connection. rcvLogic() not started")

	//TODO: ACHTUNG SETTINGS sockopt sind hier nicht gesetzt
	//log.Printf("(SCIONgoconnect) Starting Rcv-Go-Routine")
	//go s.rcvLogic() //bei send drin...

	return C.int(0) //TODO -1 for errors
}

func (s *FDSTATUS) rcvLogic() {
	log.Printf("(rcvLogic fd=%v) Started", s.Fd)
	for {
		if cancelled(s.doneRcv) {
			log.Printf("(rcvLogic fd=%v) I have been cancelled. Returning.", s.Fd)
			return
		}

		//Memory Model, sync?

		log.Printf("(rcvLogic fd=%v) Receive ntp packet from chronyScion", s.Fd)
		//log.Printf("")
		var pkt snet.Packet
		var ov net.UDPAddr
		second := time.Now().Add(time.Second)
		s.conn.SetReadDeadline(second)
		log.Printf("(rcvLogic fd=%v) Calling s.conn.ReadFrom()", s.Fd)
		err := s.conn.ReadFrom(&pkt, &ov)
		log.Printf("(rcvLogic fd=%v) \t|----> s.conn.ReadFrom() returned", s.Fd)
		if err != nil {
			log.Printf("(rcvLogic fd=%v) \t---->Failed to read packet: %v", s.Fd, err)
			continue
		}
		pld, ok := pkt.Payload.(snet.UDPPayload)
		if !ok {
			log.Printf("(rcvLogic fd=%v) \t---->Failed to read packet payload", s.Fd)
			continue
		}

		payload := pld.Payload
		log.Printf("(rcvLogic fd=%v) \t---->Received payload: \"%v\"\n", s.Fd, payload)

		payloadLen := len(payload)
		ntpSize := int(unsafe.Sizeof(NTP_Packet{})) //minimum size header 48 bytes???

		//adhoc security.... improve this
		if payloadLen < ntpSize {
			fmt.Printf("(rcvLogic fd=%v) \t---->payload can't be a NTP packet (%d < %d) (IGNORING THIS...\n", payloadLen, ntpSize)
			//continue
		}

		/* the only thing really important comes here.. */
		msg := rcvMsgNTPTS{pkt, ov}
		s.rcvQueueNTPTS <- msg
	}

}

//export SCIONgosetsockopt
func SCIONgosetsockopt(_fd C.int) C.int {
	fd := int(_fd)
	s, exists := fdstatus[fd]
	if !exists {
		log.Fatal("(SCIONgosetsockopt) Non-existing fdstatus[%d]\n", fd) //change this to fatal?
		return C.int(-1)
	}

	/*Will be set everytime the function is called....
	int level_optname_value[SCION_LE_LEN][SCION_OPTNAME_LEN]; //optval !=0 0==disabled contains all the other informations
	*/
	s.createTxTimestamp = int(s.Sinfo.createTxTimestamp) == 1
	s.createRxTimestamp = int(s.Sinfo.createRxTimestamp) == 1

	fdstatus[fd] = s //store it back

	log.Printf("(SCIONgosetsockopt) Called for socket %d. Checking settings...\n", fd)
	log.Printf("(SCIONgosetsockopt) \t|---->  createTxTimestamp=%v", s.createTxTimestamp)
	log.Printf("(SCIONgosetsockopt) \t|---->  createRxTimestamp=%v", s.createRxTimestamp)

	/*On success, zero is returned for the standard options.  On error, -1
	is returned, and errno is set appropriately.*/
	return C.int(0)
}

//export SCIONgosocket
func SCIONgosocket(domain C.int, _type C.int, protocol C.int, sinfo C.fdInfoPtr) C.int {
	fd := int(sinfo.fd)
	log.Printf("(SCIONgosocket fd=) \"Creating socket\" %d\n", fd, fd)
	log.Printf("(SCIONgosocket fd=) \t|----> TODO parse/add socket settings like SOCK_NONBLOCK, type, etc...", fd)

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
	//store it back
	fdstatus[fd] = newState

	//code snippets
	d := int(fdstatus[fd].Sinfo.domain)
	t := int(fdstatus[fd].Sinfo._type)
	p := int(fdstatus[fd].Sinfo.protocol)
	log.Printf("(SCIONgosocket fd=%v) \t|----> domain=%v type=%v protocol=%v", fd, d, t, p)
	if t == int(C.SOCK_DGRAM|C.SOCK_CLOEXEC|C.SOCK_NONBLOCK) {
		log.Printf(" \t|----> type == C.SOCK_DGRAM|C.SOCK_CLOEXEC|C.SOCK_NONBLOCK")
	}
	if int(fdstatus[fd].Sinfo._type&C.SOCK_DGRAM) == C.SOCK_DGRAM {
		log.Printf(" \t|----> type => C.SOCK_DGRAM")
	}
	if int(fdstatus[fd].Sinfo._type&C.SOCK_NONBLOCK) == C.SOCK_NONBLOCK {
		log.Printf(" \t|----> type => C.SOCK_NONBLOCK")
	}

	return C.int(newState.Fd)
}

//export SCIONgoclose
func SCIONgoclose(_fd C.int) C.int {
	fd := int(_fd)
	log.Printf("(SCIONgoclose) \"Closing socket\" %d\n", fd)
	s, exists := fdstatus[fd]
	if !exists {
		log.Fatal("(SCIONgoclose) Non-existing fdstatus[%d]\n", fd) //change this to fatal?
		return C.int(-1)
	}
	if s.doneRcv != nil {
		log.Printf("(SCIONgoclose) ----> closing doneRcv channel")
		close(s.doneRcv)
	} else {
		log.Printf("(SCIONgoclose) ----> There is no doneRcv channel. Nothing to close")
	}
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
	_, exists := fdstatus[fd]
	if !exists {
		log.Fatal("(SCIONgosendmsg) Non-existing fdstatus[%d]\n", fd) //change this to fatal?
		return C.ssize_t(-1)                                          //TODO correct return value for sendmsg()?
	}

	if !fdstatus[fd].rcvLogicStarted {
		log.Printf("(SCIONgosendmsg) Starting Rcv-Go-Routine")
		s := fdstatus[fd]
		s.rcvLogicStarted = true
		fdstatus[fd] = s
		go s.rcvLogic()
	}

	//s.remoteAddress = C.GoString(C.charPtr(unsafe.Pointer(&s.Sinfo.remoteAddress)))
	//s.remoteAddressSCION = C.GoString(C.charPtr(unsafe.Pointer(&s.Sinfo.remoteAddressSCION)))

	//msg := copyCstructMSGHDR(message)
	msg := *(*syscall.Msghdr)(unsafe.Pointer(message))
	//ntp := copyCstructNTP(msg.Iov)
	ntp := *(*NTP_Packet)(unsafe.Pointer(msg.Iov.Base))

	//fmt.Printf("msg = %v\n", msg)
	log.Printf("(SCIONgosendmsg) sending ntp packet %v to %v i.e. %v\n", ntp, fdstatus[fd].remoteAddress, fdstatus[fd].remoteAddressSCION)
	log.Printf("(SCIONgosendmsg)  \t|---->  fd=%v", fdstatus[fd].Fd)
	log.Printf("(SCIONgosendmsg)  \t|---->  createTxTimestamp local=%v c-world=%v", fdstatus[fd].createTxTimestamp, fdstatus[fd].Sinfo.createTxTimestamp)
	log.Printf("(SCIONgosendmsg)  \t|---->  createRxTimestamp local=%v c-world=%v", fdstatus[fd].createRxTimestamp, fdstatus[fd].Sinfo.createRxTimestamp)

	//TODO NONBLOCKING == start go routine... return value????
	//Assuming
	s := fdstatus[fd]
	go s.sendmsgOverScion(msg.Iov)

	//return C.ssize_t(<-fdstatus[fd].sent)
	bytesSent := <-s.sent
	return C.ssize_t(bytesSent)

}

func (s *FDSTATUS) sendmsgOverScion(iovec *syscall.Iovec) {
	log.Printf("(sendmsgOverScion fd=%v) Started", s.Fd)

	nonblocking := int(s.Sinfo._type&C.SOCK_NONBLOCK) == C.SOCK_NONBLOCK

	var err error
	var remoteAddr *snet.UDPAddr
	if s.connected {
		remoteAddr = s.rAddr
	} else {
		log.Fatal("(sendmsgOverScion) Unconnected case needs to be implemended....")
		s.sent <- int(-1)
		return //should never reach this point....
	}

	if s.sent == nil {
		log.Fatal("(sendmsgOverScion) Send channel needs to be implemended....")
	}

	iovecLen := iovec.Len
	iovecBase := iovec.Base

	if nonblocking {
		log.Printf("(sendmsgOverScion fd=%v) |----> type => C.SOCK_NONBLOCK => returning direcly without blocking)", s.Fd)
		//This allows SCIONgosendmsg() to return, i.e. it is a non blocking send
		s.sent <- int(iovecLen)
	}

	if s.createTxTimestamp {
		log.Printf("(sendmsgOverScion fd=%v) |----> will create TX-Timestamps", s.Fd)
	}

	payload := C.GoBytes(unsafe.Pointer(iovecBase), C.int(iovecLen))

	// test it
	/*
		ntp := *(*NTP_Packet)(C.CBytes(payload2))
		fmt.Printf("ntp = %v\n", ntp)
	*/
	//fmt.Printf("iovecLen = %v\tiovecBase = %v\tpayload = %v\n", iovecLen, iovecBase, payload)

	conn := s.conn

	log.Printf("(sendmsgOverScion) Sending in %v on %v:%d - %v\n", localAddr.IA, localAddr.Host.IP, s.localPortSCION, addr.SvcNone)
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
				SrcPort: s.localPortSCION,             //ev kann das hier benutzt werden JOP ist UDP Port
				DstPort: uint16(remoteAddr.Host.Port), //ev kann das hier benutzt werden JOP so ist es
				Payload: payload,                      //[]byte("Hello, world!"),
			},
		},
	}

	//ALWAYS create TX timestamp..--- change this
	fakeKernelSentTime := time.Now() //HW time komplett anders
	//fakeHardwareSentTime := time.Now() //HW time komplett anders
	err = conn.WriteTo(pkt, remoteAddr.NextHop)
	if err != nil {
		log.Printf("(sendmsgOverScion) [%d] Failed to write packet: %v\n", err)
		s.sent <- int(-1)
		return
	}
	if !nonblocking {
		s.sent <- int(iovecLen)
	}

	sendMsg := false
	var msgTS sendMsgTS

	sendMsg = true
	msgTS.tsType = tskernelhardware
	msgTS.payload = payload
	msgTS.sentTo = remoteAddr

	//add TS's: Src needs to be adpted afte SCION provides the correct TS's
	if s.createTxTimestamp {
		sendMsg = true
		var ts3 C.struct_scm_timestamping
		//kernel ts
		ts3.ts[0].tv_sec = C.long(fakeKernelSentTime.Unix())
		ts3.ts[0].tv_nsec = C.long(fakeKernelSentTime.UnixNano() - fakeKernelSentTime.Unix()*1e9)
		//hardware ts
		ts3.ts[2].tv_sec = C.long(0)  //C.long(fakeHardwareSentTime.Unix())
		ts3.ts[2].tv_nsec = C.long(0) //C.long(fakeHardwareSentTime.UnixNano() - fakeHardwareSentTime.Unix()*1e9)
		log.Printf("(sendmsgOverScion fd=%v) \t-----> ts3=%v", s.Fd, ts3)
		msgTS.ts3 = ts3
	}

	if sendMsg {
		log.Printf("(sendmsgOverScion fd=%v) Calling s.sendQueueTS <- msgTS", s.Fd)
		s.sendQueueTS <- msgTS
	} else {
		log.Printf("(sendmsgOverScion fd=%v) Will not create any messages for Timestamps.", s.Fd)
	}
	log.Printf("(sendmsgOverScion) \t----->Done")

}

// SCIONgorecvmmsg collects the received messages and returns them.... but ist not the one actively receiving the stuff
//export SCIONgorecvmmsg
func SCIONgorecvmmsg(_fd C.int, vmessages C.mmsghdrPtr, vlen C.uint, flags C.int, tmo C.timespecPtr) C.int {
	fd := int(_fd)
	s, exists := fdstatus[fd]
	if !exists {
		log.Fatal("(SCIONgorecvmmsg) Non-existing fdstatus[%d]\n", fd)
		return C.int(-1)
	}

	log.Printf("(SCIONgorecvmmsg) Receiving messages for i.e. %v:%v", localAddrStr, s.localPortSCION)

	//Do something with this info... is more than needed... motivated by printMMSGHDR()
	var receiveFlag int
	var receiveFlagStr string
	var scionType int
	var scionTypeStr string
	var dataEncapLayer2 bool
	var receiveNTP bool
	var returnTxTS bool
	if flags&C.MSG_ERRQUEUE > 0 {
		receiveFlag = int(C.SCION_MSG_ERRQUEUE)
		receiveFlagStr = "C.SCION_MSG_ERRQUEUE"
		scionType = int(C.SCION_IP_TX_ERR_MSG)
		scionTypeStr = "C.SCION_IP_TX_ERR_MSG"
		receiveNTP = false
		dataEncapLayer2 = true
		returnTxTS = true
	} else {
		receiveFlag = int(C.SCION_FILE_INPUT)
		receiveFlagStr = "C.SCION_FILE_INPUT"
		scionType = int(C.SCION_IP_RX_NTP_MSG)
		scionTypeStr = "SCION_IP_RX_NTP_MSG"
		receiveNTP = true
		dataEncapLayer2 = false
	}
	log.Printf("(SCIONgorecvmmsg) ----> receiveFlag = %v (%v)", receiveFlag, receiveFlagStr)
	log.Printf("(SCIONgorecvmmsg) ----> scionType = %v (%v)", scionType, scionTypeStr)
	log.Printf("(SCIONgorecvmmsg) ----> receiveNTP?  %v", receiveNTP)
	log.Printf("(SCIONgorecvmmsg) ----> dataEncapLayer2?  %v", dataEncapLayer2)

	n := len(s.rcvQueueNTPTS)
	log.Printf("(SCIONgorecvmmsg) ----> number of received messages on fd=%v is %v", fd, n)
	nError := len(s.sendQueueTS)
	log.Printf("(SCIONgorecvmmsg) ----> number of received ERROR-messages on fd=%v is %v", fd, nError)
	/*if nError > 0 {
		sendMsgTS := <-s.sendQueueTS
		log.Printf("(SCIONgorecvmmsg) ----> sendMsgTS=%v", sendMsgTS)
	}*/

	//TODO VLEN check

	updatedElemmsgvec := 0
	if returnTxTS && nError > 0 {

		sendMsgTS := <-s.sendQueueTS
		log.Printf("(SCIONgorecvmmsg) ----> sendMsgTS=%v", sendMsgTS)

		//var msgvec *([3]C.struct_mmsghdr) = ([3]C.struct_mmsghdr)(&unsafe.Pointer(vmessages))
		var msgvec *([C.VLEN]C.struct_mmsghdr) = (*[C.VLEN]C.struct_mmsghdr)(unsafe.Pointer(vmessages))
		var msghdr *C.struct_msghdr

		//msghdr = &msgvec[updatedElemmsgvec].msg_hdr
		for i := 0; i < 2; i++ {
			msghdr = &msgvec[i].msg_hdr

			msghdr.msg_namelen = C.uint(0)
			//msghdr.msg_name is null

			//theoretisch gibt es hier mehrere
			//msghdr.msg_iov.iov_base = sendMsgTS.payload
			log.Printf("&msgvec[%d].msg_hdr=%v", i, msghdr)
			log.Printf("msghdr.msg_iov.iov_len=%v", msghdr.msg_iov.iov_len)
			log.Printf("msghdr.msg_iov.iov_base=%v", msghdr.msg_iov.iov_base)

			/*
				add the ntp packet
			*/
			//msghdr.msg_iov.iov_base
			var bufferPtr *[C.IOVLEN]C.char
			bufferPtr = (*[C.IOVLEN]C.char)(msghdr.msg_iov.iov_base)
			var offsetNTP int
			var pktLen int
			pktLen += len(sendMsgTS.payload) //should be 48
			/* Jeweils bei Bufferals Prefix und bei (msgvec[i].msg_len + X)*/
			//1. MACs => add 12
			offsetNTP += 12
			pktLen += 12
			//2 NO VLAN TAGS

			//3 Add IPv4 ethertype
			bufferPtr[offsetNTP] = 0x08
			bufferPtr[offsetNTP+1] = 0x00
			offsetNTP += 2
			pktLen += 2

			//TODO Use SCION pkg somehome directly... Bytes....
			//4 Add Destination address and port for IPv4 UDP headers
			bufferPtr[offsetNTP] = 69
			var ihl int
			ihl = int((bufferPtr[offsetNTP] & 0xf) * 4) //==20 for ipv4

			bufferPtr[offsetNTP+9] = 17
			//ipv4 in network byte order
			bufferPtr[offsetNTP+16] = 10
			bufferPtr[offsetNTP+17] = 80
			bufferPtr[offsetNTP+18] = 45
			bufferPtr[offsetNTP+19] = -128
			//port in network byte order
			bufferPtr[offsetNTP+ihl+2] = 0   //shoud be [22]
			bufferPtr[offsetNTP+ihl+3] = 123 //shoud be [23]

			offsetNTP += ihl + 8 //should be 42
			pktLen += ihl + 8    //should be 90

			//copy ntp packet :-(
			for a, b := range sendMsgTS.payload {

				log.Printf("a=%v b=%v", a, b)
				bufferPtr[a+offsetNTP] = C.char(b)
			}
			updatedElemmsgvec++

			msgvec[i].msg_len = C.uint(pktLen)
			log.Printf("msgvec[%d].msg_len=%v", i, msgvec[i].msg_len)

			/*
				Add Ancillary data
			*/
			//ADD TIMESTAMPS
			var cmsg *C.struct_cmsghdr
			cmsg = cmsgFirstHdr(msghdr)
			cmsg.cmsg_len = 64                  //unsigned long 8bytes
			cmsg.cmsg_level = C.SOL_SOCKET      //int 4bytes
			cmsg.cmsg_type = C.SCM_TIMESTAMPING //int 4bytes

			var cmsgDataPtr *C.uchar
			cmsgDataPtr = cmsgData(cmsg)

			//ACHTUNG: Kopiere hier Kernel und HW rein... unklar ob Chrony logik damit klarkommt
			//====> nein verwirft dann beide TS wenn HW "ungültig ist"
			//habe sie beim erstellen entfernt
			*(*C.struct_scm_timestamping)(unsafe.Pointer(cmsgDataPtr)) = sendMsgTS.ts3

			log.Printf("cmsg.cmsg_len-TYPE = %T", cmsg.cmsg_len)
			log.Printf("cmsg.cmsg_level-TYPE = %T", cmsg.cmsg_level)

			//ADD IP_PKTINFO
			cmsg = cmsgNextHdr(msghdr, cmsg)
			cmsg.cmsg_len = 28
			cmsg.cmsg_level = C.IPPROTO_IP
			cmsg.cmsg_type = C.IP_PKTINFO
			cmsgDataPtr = cmsgData(cmsg)

			(*C.struct_in_pktinfo)(unsafe.Pointer(cmsgDataPtr)).ipi_ifindex = 2
			var aaa C.struct_in_addr
			var bbb C.struct_in_addr
			//remove this c-call
			aaa.s_addr = C.htonl(173026643) //10.80.45.83??
			bbb.s_addr = C.htonl(173026688) //10.80.45.128??
			(*C.struct_in_pktinfo)(unsafe.Pointer(cmsgDataPtr)).ipi_spec_dst = aaa
			(*C.struct_in_pktinfo)(unsafe.Pointer(cmsgDataPtr)).ipi_addr = bbb

			/*
				memcpy(&ipi, CMSG_DATA(cmsg), sizeof(ipi));
				DEBUG_LOG("\t\t\t\t\tipi.ipi_ifindex=%d (Interface index)", ipi.ipi_ifindex);
				DEBUG_LOG("\t\t\t\t\tipi.ipi_spec_dst.s_addr=%s (Local address.. wrong->? Routing destination address)", inet_ntoa(ipi.ipi_spec_dst));
				DEBUG_LOG("\t\t\t\t\tipi.ipi_addr.s_addr=%s (Header destination address)", inet_ntoa(ipi.ipi_addr));
			*/

			//TODO Länge der Daten setzen..

		}
	}

	return C.int(updatedElemmsgvec)

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
