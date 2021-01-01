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
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"syscall"
	"time"
	"unsafe"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/daemon"
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
--->SCIONselect: busy-wait loop....... überlege ob chrony timeouts relevant sind für Logik...
*/

/*
go build -buildmode=c-shared -o scion_api.so *.go
*/

const pktLengtLayer2 = 90

//datastructure for SCIONselect
type fdset struct {
	fd             int
	exists         bool
	readSelected   bool
	writeSelected  bool
	exceptSelected bool
	readReady      bool
	writeReady     bool
	exceptReady    bool
}

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
	sdc                daemon.Connector
	pds                *snet.DefaultPacketDispatcherService
	ps                 []snet.Path
	selectedPath       snet.Path
	ctx                context.Context
	cancel             context.CancelFunc //defer cancel()
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
	rxKERNELts         bool //use this
	rxHWts             bool //use this
	isNTPServer        bool
	isbound            bool
}

type rcvMsgNTPTS struct {
	tsType int         //TS type.... not needed?
	pkt    snet.Packet //call like this should never fail (is checked befor added): rcvMsgNTPTS.pkt.Payload.(snet.UDPPayload)
	ov     net.UDPAddr
	ts3    C.struct_scm_timestamping
}

/* Remark: ts3 have to be separated (if HW-TS isn't accepted, chrony's logic drops packets without considering Kernel TS in it)
Further: There are two messages needed for a correct message count in select (C-Library createse two separate messages: TS creation for Kernel/HW takes different amount of time)
*/
type sendMsgTS struct {
	tsType int //TS type.... not needed?
	pkt    *snet.Packet
	//payload []byte
	ts3    C.struct_scm_timestamping
	sentTo *snet.UDPAddr
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

var ctx context.Context

func init() {
	log.Printf("(Init) Changing logging behaviour....")

	log.SetFlags(log.Lshortfile | log.Ldate | log.Ltime | log.LUTC)

	//bug in C.GODEBUG???... can't activate it anymore... always existing and zero..
	//Use go clean --cache
	if C.GODEBUG == 0 {
		//if C.GODEBUGNEW == 0 {
		log.Printf("(Init) log.* Output has been disabled as #define GODEBUGNEW 0 is set")
		log.SetOutput(ioutil.Discard)
	}
	log.Printf("(Init) ....logging behaviour has been changed")

	//Add default configuration
	sciondAddr = daemon.DefaultAPIAddress
	localAddrStr = "1-ff00:0:112,10.80.45.83" //TODO parse the local address from somewhere
	localAddr, _ = snet.ParseUDPAddr(localAddrStr)
	localAddr.Host.Port = 0 //ignore user defined srcport

	ctx = context.Background()
}

var sciondAddr string

// SetSciondAddr Sets the daemon address
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
	//TODO add err
	localAddr.Host.Port = 0 //ignore user defined srcport
	return C.int(1)
}

var fdstatus = make(map[int]FDSTATUS)

var clientMapping = make(map[string](*snet.UDPAddr))

var fdList = make(map[int]int)
var maxFD = 1024

//SCIONgoconnect creates the needed objects to call/recv data from a scion connections.
//Attention: This doesn't start a receive method!
//The send ntp packets as a client: call socket(), connect(), setsockopt(), send*(), *will also start receive method
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

	//s.ctx = context.Background()
	s.ctx, s.cancel = context.WithCancel(ctx)

	s.sdc, err = daemon.NewService(sciondAddr).Connect(s.ctx)
	if err != nil {
		log.Printf("(SCIONgoconnect) Failed to create SCION connector:", err)
		return C.int(-1)
	}
	s.pds = &snet.DefaultPacketDispatcherService{
		Dispatcher: reconnect.NewDispatcherService(reliable.NewDispatcher("")),
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: daemon.RevHandler{Connector: s.sdc},
		},
	}

	s.ps, err = s.sdc.Paths(s.ctx, s.rAddr.IA, localAddr.IA, daemon.PathReqFlags{Refresh: true})
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

//SCIONgobind Used to start recv Logic: now all socket options should be set
//export SCIONstartntp
func SCIONstartntp() C.int {
	for _, s := range fdstatus {
		if s.isbound {
			if !s.rcvLogicStarted {
				log.Printf("(SCIONstartntp) Starting Rcv-Go-Routine for fd=%v!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!", s.Fd)
				//s := fdstatus[fd]
				s.rcvLogicStarted = true
				fdstatus[s.Fd] = s
				hallo := fdstatus[s.Fd]
				log.Printf("(SCIONstartntp) Starting Rcv-Go-Routine for fd=%v", hallo.Fd)

				go hallo.rcvLogic()
			}

		}
	}
	return C.int(0)
}

//SCIONgobind tbd....
//export SCIONgobind
func SCIONgobind(_fd C.int, _port C.uint16_t) C.int {
	fd := int(_fd)
	s, exists := fdstatus[fd]
	if !exists {
		log.Printf("(SCIONgobind) There is no state available for fd=%d\n", fd)
		return C.int(-1)
	}

	port := int(_port)

	var err error

	if int(s.Sinfo.connectionType) == int(C.IS_NTP_SERVER) {
		s.isNTPServer = true
	}

	s.ctx, s.cancel = context.WithCancel(ctx)

	s.sdc, err = daemon.NewService(sciondAddr).Connect(s.ctx)
	if err != nil {
		log.Printf("(SCIONgobind) Failed to create SCION connector:", err)
		return C.int(-1)
	}
	s.pds = &snet.DefaultPacketDispatcherService{
		Dispatcher: reconnect.NewDispatcherService(reliable.NewDispatcher("")),
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: daemon.RevHandler{Connector: s.sdc},
		},
	}

	//
	bindAddr, err := snet.ParseUDPAddr(localAddrStr)
	if err != nil {
		log.Fatal("(SCIONgobind) Failed to parse local Address:", err)
		return C.int(-1) //should never return
	}
	bindAddr.Host.Port = port //set the correct port

	s.conn, s.localPortSCION, err = s.pds.Register(s.ctx, bindAddr.IA, bindAddr.Host, addr.SvcNone)
	if err != nil {
		log.Printf("(SCIONgobind)  Failed to register client socket:", err)
		return C.int(-1)
	}

	log.Printf("localAddr.IA=%v, localAddr.Host=%v", localAddr.IA, localAddr.Host)
	log.Printf("bindAddr.IA=%v, bindAddr.Host=%v", bindAddr.IA, bindAddr.Host)

	s.isbound = true
	s.sent = make(chan int)
	s.doneRcv = make(chan struct{})
	s.rcvQueueNTPTS = make(chan rcvMsgNTPTS, int(C.MSGBUFFERSIZESERVER))
	s.sendQueueTS = make(chan sendMsgTS, int(C.MSGBUFFERSIZESERVER))

	fdstatus[fd] = s //store it back
	log.Printf("(SCIONgobind) Registered Port %v for fd=%v. rcvLogic() not started!", port, fd)

	//TODO: ACHTUNG SETTINGS sockopt sind hier nicht gesetzt
	//log.Printf("(SCIONgobind) Starting Rcv-Go-Routine")
	//go s.rcvLogic() //bei send drin...

	return C.int(0) //TODO -1 for errors
}

func (s *FDSTATUS) rcvLogic() {
	log.Printf("(rcvLogic fd=%v) Started", s.Fd)
	for {
		if cancelled(s.doneRcv) {
			log.Printf("(rcvLogic fd=%v) I have been cancelled. Returning.", s.Fd)
			break
		}

		var rcvMsgNTPTS rcvMsgNTPTS

		//var pkt snet.Packet
		//var ov net.UDPAddr
		second := time.Now().Add(time.Second)
		s.conn.SetReadDeadline(second)
		//log.Printf("(rcvLogic fd=%v) Calling s.conn.ReadFrom()", s.Fd)
		err := s.conn.ReadFrom(&rcvMsgNTPTS.pkt, &rcvMsgNTPTS.ov)
		//log.Printf("(rcvLogic fd=%v) \t|----> s.conn.ReadFrom() returned", s.Fd)
		if err != nil {
			//log.Printf("(rcvLogic fd=%v) \t---->Failed to read packet: %v", s.Fd, err)
			continue
		}
		fakeHardwareRxTime := time.Now() //HW time komplett anders
		fakeKernelRxTime := time.Now()   //HW time komplett anders
		log.Printf("(rcvLogic fd=%v) ----> Received Packet!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!", s.Fd)

		//var ts3 C.struct_scm_timestamping

		if s.rxKERNELts {
			rcvMsgNTPTS.tsType = tskernel
			//kernel ts
			rcvMsgNTPTS.ts3.ts[0].tv_sec = C.long(fakeKernelRxTime.Unix())
			rcvMsgNTPTS.ts3.ts[0].tv_nsec = C.long(fakeKernelRxTime.UnixNano() - fakeKernelRxTime.Unix()*1e9)
		}

		if s.rxHWts {
			rcvMsgNTPTS.tsType = tshardware
			if s.rxKERNELts {
				rcvMsgNTPTS.tsType = tskernelhardware
			}
			//kernel ts
			rcvMsgNTPTS.ts3.ts[2].tv_sec = C.long(fakeHardwareRxTime.Unix())
			rcvMsgNTPTS.ts3.ts[2].tv_nsec = C.long(fakeHardwareRxTime.UnixNano() - fakeHardwareRxTime.Unix()*1e9)
		}

		//Needed? If the payload can be extracted there should be a message
		_, ok := rcvMsgNTPTS.pkt.Payload.(snet.UDPPayload)
		if !ok {
			continue //return //continue
		}

		/* the only thing really important comes here.. */
		log.Printf("(rcvLogic fd=%v) ----> s.rcvQueueNTPTS <- rcvMsgNTPTS!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!", s.Fd)
		s.rcvQueueNTPTS <- rcvMsgNTPTS
	}
	s.rcvLogicStarted = false
	log.Printf("(rcvLogic fd=%v) ----> Finished recv my message. Returning.", s.Fd)

}

//SCIONgosetsockopt gets called each time a setsockopt() is executed.
//Settings are encoded inside of Sinfo. Some of the options are explicitely set in go's memory (redundant).
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
	s.txKERNELts = s.createTxTimestamp
	//s.txHWts = s.createTxTimestamp //change this logic
	s.rxKERNELts = s.createRxTimestamp
	//s.rxHWts = s.createRxTimestamp //change this logic

	fdstatus[fd] = s //store it back

	log.Printf("(SCIONgosetsockopt) Called for socket %d. Checking settings...\n", fd)
	log.Printf("(SCIONgosetsockopt) \t|---->  createTxTimestamp=%v", s.createTxTimestamp)
	log.Printf("(SCIONgosetsockopt) \t|---->  createRxTimestamp=%v", s.createRxTimestamp)

	/*On success, zero is returned for the standard options.  On error, -1
	is returned, and errno is set appropriately.*/
	return C.int(0)
}

//SCIONgosocket creates the needed datastructure to keep state in the SCION-GO-World.
//sinfo is a pointer into C's memory.
//export SCIONgosocket
func SCIONgosocket(domain C.int, _type C.int, protocol C.int, sinfo C.fdInfoPtr) C.int {
	fd := int(sinfo.fd)
	log.Printf("(SCIONgosocket) Creating \"socket\" fd=%d\n", fd)

	_, exists := fdstatus[fd]
	if exists {
		log.Printf("(SCIONgosocket) ERROR Already existing entry for fd=%d,fd")
		return C.int(-1) //TODOdefine correct behaviour
	}

	newState := FDSTATUS{Fd: fd, Sinfo: sinfo}
	//store it
	fdstatus[fd] = newState

	//code snippets
	/*
		domainS := int(sinfo.domain)
		typeS := int(sinfo._type)
		protocolS := int(sinfo.protocol)
		connectionTypeS := int(sinfo.connectionType)
		fmt.Printf("\tdomain=%d type=%d protocol=%d\n", domain, _type, protocol)
		fmt.Printf("fd=%d domainS=%d typeS=%d protocolS=%d connectionTypeS=%d\nsinfo=%v\n", fd, domainS, typeS, protocolS, connectionTypeS, sinfo)
	*/
	d := int(fdstatus[fd].Sinfo.domain)
	t := int(fdstatus[fd].Sinfo._type)
	p := int(fdstatus[fd].Sinfo.protocol)
	log.Printf("(SCIONgosocket) ----> domain=%v type=%v protocol=%v", d, t, p)
	if t == int(C.SOCK_DGRAM|C.SOCK_CLOEXEC|C.SOCK_NONBLOCK) {
		log.Printf("(SCIONgosocket) ----> type == C.SOCK_DGRAM|C.SOCK_CLOEXEC|C.SOCK_NONBLOCK")
	}
	if int(fdstatus[fd].Sinfo._type&C.SOCK_DGRAM) == C.SOCK_DGRAM {
		log.Printf("(SCIONgosocket) ----> type => C.SOCK_DGRAM")
	}
	if int(fdstatus[fd].Sinfo._type&C.SOCK_NONBLOCK) == C.SOCK_NONBLOCK {
		log.Printf("(SCIONgosocket) ----> type => C.SOCK_NONBLOCK")
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

	if s.cancel != nil {
		s.cancel()
	}
	if s.sdc != nil {
		//unklar ob dass alle connections killt... weil ich Backgroundcontext genommen habe,
		s.sdc.Close(s.ctx)
	}

	//close dispatcher???? s.pds

	delete(fdstatus, int(fd))

	//TODO close() returns zero on success.  On error, -1 is returned, and errno
	//is set appropriately.
	return C.int(0)
}

type fdsetType syscall.FdSet

// copyright https://golang.hotexamples.com/de/site/file?hash=0x5e82324c621245310a74ced33fa9cd3627abb2d8c84e55d16acb46c1de2ba57f&fullName=linuxdvb/filter.go&project=ziutek/dvb

func (s *fdsetType) Set(fd uintptr) {
	bits := 8 * unsafe.Sizeof(s.Bits[0])
	if fd >= bits*uintptr(len(s.Bits)) {
		panic("fdset: fd out of range")
	}
	n := fd / bits
	m := fd % bits
	s.Bits[n] |= 1 << m
}
func (s *fdsetType) Clr(fd uintptr) {
	bits := 8 * unsafe.Sizeof(s.Bits[0])
	if fd >= bits*uintptr(len(s.Bits)) {
		panic("fdset: fd out of range")
	}
	n := fd / bits
	m := fd % bits
	s.Bits[n] &^= 1 << m
}
func (s *fdsetType) IsSet(fd uintptr) bool {
	bits := 8 * unsafe.Sizeof(s.Bits[0])
	if fd >= bits*uintptr(len(s.Bits)) {
		panic("fdset: fd out of range")
	}
	n := fd / bits
	m := fd % bits
	return s.Bits[n]&(1<<m) != 0
}

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
//export SCIONselect
func SCIONselect(nfds C.int, readfds C.fdsetPtr, writefds C.fdsetPtr, exceptfds C.fdsetPtr, timeout C.timevalPtr) C.int {
	start := time.Now()
	var tvsec C.__time_t
	var tvusec C.__suseconds_t

	highestFd := int(nfds) - 1

	var blocking bool
	var t time.Duration
	var ticker <-chan time.Time
	var tickTime time.Duration
	if timeout == nil {
		log.Printf("timeout seems to be NULL => select() will block indefinitely")
		blocking = true
		tickTime = 500 * time.Millisecond
		ticker = time.Tick(tickTime)
	} else {
		tvsec = timeout.tv_sec
		tvusec = timeout.tv_usec
		t = time.Duration(tvsec)*time.Second + time.Duration(tvusec)*time.Microsecond
		tickTime = t / 20
		if tickTime > 500*time.Millisecond {
			tickTime = 500 * time.Millisecond
		}
		ticker = time.Tick(tickTime)
	}

	log.Printf("(SCIONselect) blocking=%v tvsec=%v  tvusec=%v timeout=%v highestFd=%v tickTime=%v", blocking, tvsec, tvusec, t, highestFd, tickTime)

	//Parse fdset: this is a condensated representation of c's fdsets
	var rset *fdsetType
	if readfds != nil {
		rset = (*fdsetType)(unsafe.Pointer(readfds))
	}
	var wset *fdsetType
	if writefds != nil {
		wset = (*fdsetType)(unsafe.Pointer(writefds))
	}
	var eset *fdsetType
	if exceptfds != nil {
		eset = (*fdsetType)(unsafe.Pointer(exceptfds))
	}

	/*
		Add fd to fdsets if 1+ bits are set
		Logic: SCIONselect() will test all fd's in this set and remove any bits corresponding to "notready fd's"
	*/
	fdsets := make([]*fdset, 0, highestFd)
	for fd := 1; fd <= highestFd; fd++ {
		var fdPtr uintptr
		fdPtr = uintptr(fd)

		_, exists := fdstatus[fd] //we can ignore them: Assumption: We are still in chronyd's main thread => while we are in SCIONselect, there cannot be created any new states. If this is not true anymore, check it at the beginning of the loop. Relevant for very long running timeouts.

		var rIsSet, eIsSet, wIsSet bool
		if readfds != nil {
			rIsSet = rset.IsSet(fdPtr)
		}
		if writefds != nil {
			wIsSet = wset.IsSet(fdPtr)
		}
		if exceptfds != nil {
			eIsSet = eset.IsSet(fdPtr)
		}

		if rIsSet || eIsSet || wIsSet {
			//add set to slice
			fdsets = append(fdsets,
				&fdset{
					fd:             fd,
					exists:         exists,
					readSelected:   rIsSet,
					writeSelected:  wIsSet,
					exceptSelected: eIsSet,
					readReady:      false,
					writeReady:     false,
					exceptReady:    false,
				})
		}

	}

	numOfBitsSet := 0
	for {

		numOfBitsSet = 0 //numOfBitsSet is always zero here

		for _, fdset := range fdsets {
			if !fdset.exists { //optimization: prevents fdstatus[fdset.fd] calls
				continue
			}
			s, exists := fdstatus[fdset.fd]
			if !exists {
				continue //should never happen
			}

			var readMsg int
			var errorMsg int
			//Only get the state for an fd if it was asked for
			if fdset.readSelected {
				readMsg = len(s.rcvQueueNTPTS) //read input
				if readMsg > 0 {
					fdset.readReady = true
					numOfBitsSet++
				}
			}
			if fdset.exceptSelected {
				errorMsg = len(s.sendQueueTS) //exceptions
				if errorMsg > 0 {
					fdset.exceptReady = true
					numOfBitsSet++
				}
			}

			if readMsg+errorMsg > 0 {
				log.Printf("(SCIONselect) ----> fd=%v: readMsg=%v errorMsg=%v", fdset.fd, readMsg, errorMsg)
			}
		}

		//blocking means no timeout. The ticker is just here to prevent a busyloop
		if numOfBitsSet == 0 && (time.Since(start) < t || blocking) {
			//Sleep
			<-ticker
			//log.Printf("(SCIONselect) received a tick.... starting over")
		} else {
			//we have at least 1 bit set and can return
			break
		}
	}

	if numOfBitsSet > 0 {
		log.Printf("(SCIONselect) ----> Returning because numOfBitsSet=%v", numOfBitsSet)
	} else {
		log.Printf("(SCIONselect) ----> Returning because of a timeout")
	}

	//Writting the result back into C's-Datastructures
	for _, fdset := range fdsets {

		var fdPtr uintptr
		fdPtr = uintptr(fdset.fd)

		/*
			the readfds has been given to select() => rset exists
			for this fd is the flag is selected, => Ready flag has been manipulated
			but it is not ready
			=> we deactivate it
		*/
		if readfds != nil && fdset.readSelected && !fdset.readReady {
			rset.Clr(fdPtr)
		}
		if writefds != nil && fdset.writeSelected && !fdset.writeReady {
			wset.Clr(fdPtr)
		}
		if exceptfds != nil && fdset.exceptSelected && !fdset.exceptReady {
			eset.Clr(fdPtr)
		}

	}

	return C.int(numOfBitsSet) //Todo err to errno?
}

//export SCIONgosendmsg
func SCIONgosendmsg(_fd C.int, message C.msghdrConstPtr, flags C.int, _remoteAddrString *C.char) C.ssize_t {
	fd := int(_fd)
	_, exists := fdstatus[fd]
	if !exists {
		log.Fatal("(SCIONgosendmsg) Non-existing fdstatus[%d]\n", fd) //change this to fatal?
		return C.ssize_t(-1)                                          //TODO correct return value for sendmsg()?
	}

	if !fdstatus[fd].rcvLogicStarted {
		log.Printf("(SCIONgosendmsg) Starting Rcv-Go-Routine !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
		s := fdstatus[fd]
		s.rcvLogicStarted = true
		fdstatus[fd] = s
		go s.rcvLogic()
	}

	s := fdstatus[fd]

	msg := *(*syscall.Msghdr)(unsafe.Pointer(message))
	ntp := *(*NTP_Packet)(unsafe.Pointer(msg.Iov.Base))

	var remoteAddrString string
	if s.isNTPServer {
		remoteAddrString = C.GoString(_remoteAddrString)
		log.Printf("(SCIONgosendmsg) sending ntp packet %v to %v i.e. %v\n", ntp, remoteAddrString, "fake scion")
	}
	if s.connected {
		log.Printf("(SCIONgosendmsg) sending ntp packet %v to %v i.e. %v\n", ntp, fdstatus[fd].remoteAddress, fdstatus[fd].remoteAddressSCION)
	}

	go s.sendmsgOverScion(msg.Iov, remoteAddrString)

	//if the call is blocking, this channel will get the value after msg has been sent
	bytesSent := <-s.sent
	return C.ssize_t(bytesSent)

}

func (s *FDSTATUS) sendmsgOverScion(iovec *syscall.Iovec, remoteAddrString string) {
	log.Printf("(sendmsgOverScion fd=%v) Started", s.Fd)

	nonblocking := int(s.Sinfo._type&C.SOCK_NONBLOCK) == C.SOCK_NONBLOCK

	var err error
	var remoteAddr *snet.UDPAddr
	if s.connected {
		remoteAddr = s.rAddr
	} else if s.isNTPServer {
		//= make(map[string](*snet.UDPAddr))
		//remoteAddrString := "fake me"
		var exists bool
		remoteAddr, exists = clientMapping[remoteAddrString]
		if !exists {
			log.Printf("(SCIONgosendmsg) Non-existing entry clientMapping[%v]", remoteAddrString)
			s.sent <- int(-1)
			return
		}
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
	fakeKernelSentTime := time.Now()   //HW time komplett anders
	fakeHardwareSentTime := time.Now() //HW time komplett anders
	err = conn.WriteTo(pkt, remoteAddr.NextHop)
	if err != nil {
		log.Printf("(sendmsgOverScion) [%d] Failed to write packet: %v\n", err)
		s.sent <- int(-1)
		return
	}

	//if there is a blocking call, it will return now
	if !nonblocking {
		s.sent <- int(iovecLen)
	}

	sendMsg := false
	var msgTS sendMsgTS

	sendMsg = true
	msgTS.pkt = pkt
	//msgTS.payload = payload
	msgTS.sentTo = remoteAddr

	//add TS's: Src needs to be adpted afte SCION provides the correct TS's
	if s.txKERNELts {
		msgTS.tsType = tskernel //not needed
		sendMsg = true
		var ts3 C.struct_scm_timestamping
		//kernel ts
		ts3.ts[0].tv_sec = C.long(fakeKernelSentTime.Unix())
		ts3.ts[0].tv_nsec = C.long(fakeKernelSentTime.UnixNano() - fakeKernelSentTime.Unix()*1e9)
		log.Printf("(sendmsgOverScion fd=%v) \t-----> ts3(Kernel)=%v", s.Fd, ts3)
		msgTS.ts3 = ts3
		log.Printf("(sendmsgOverScion fd=%v) Calling s.sendQueueTS <- msgTS", s.Fd)
		s.sendQueueTS <- msgTS
	}
	if s.txHWts {
		msgTS.tsType = tshardware //not needed
		sendMsg = true
		var ts3 C.struct_scm_timestamping
		//hardware ts
		ts3.ts[2].tv_sec = C.long(fakeHardwareSentTime.Unix())
		ts3.ts[2].tv_nsec = C.long(fakeHardwareSentTime.UnixNano() - fakeHardwareSentTime.Unix()*1e9)
		log.Printf("(sendmsgOverScion fd=%v) \t-----> ts3(HW)=%v", s.Fd, ts3)
		msgTS.ts3 = ts3
		log.Printf("(sendmsgOverScion fd=%v) Calling s.sendQueueTS <- msgTS", s.Fd)
		s.sendQueueTS <- msgTS
	}

	if !sendMsg {
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
	} else { //flags 0 => file input I guess
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

	nMsg := len(s.rcvQueueNTPTS)
	log.Printf("(SCIONgorecvmmsg) ----> number of received messages on fd=%v is %v", fd, nMsg)
	nErrorMsg := len(s.sendQueueTS)
	log.Printf("(SCIONgorecvmmsg) ----> number of received ERROR-messages on fd=%v is %v", fd, nErrorMsg)

	//TODO VLEN check
	//PORT IP,....
	updatedElemmsgvec := 0
	if returnTxTS && nErrorMsg > 0 {
		//TODO Länge der Daten setzen..
		for i := 0; i < nErrorMsg && i < int(vlen); i++ {
			sendMsgTS := <-s.sendQueueTS
			pld, ok := sendMsgTS.pkt.Payload.(snet.UDPPayload)
			if !ok {
				log.Printf("(SCIONgorecvmmsg) ----> There was an error parsing the udp payload. Skipping this packet!")
				continue
			}
			payloadMsg := pld.Payload
			log.Printf("(SCIONgorecvmmsg) ----> sendMsgTS=%v", sendMsgTS)

			//TODO C.VLEN should be variable i.e. equal to vlen
			var msgvec *([C.VLEN]C.struct_mmsghdr) = (*[C.VLEN]C.struct_mmsghdr)(unsafe.Pointer(vmessages))
			var msghdr *C.struct_msghdr
			msghdr = &msgvec[i].msg_hdr
			var msgControllen C.size_t //keep track off added data

			//Buffer löschen????
			var msgContrLen int
			msgContrLen = int(msghdr.msg_controllen)
			log.Printf("(SCIONgorecvmmsg) ----> msghdr.msg_control=%v msghdr.msg_controllen=%v msgContrLen=%v", msghdr.msg_control, msghdr.msg_controllen, msgContrLen)

			//chang this: What we need is msgContrLen. Reason: cmsgNextHdr fails if memory is not nulled
			var bufferPtrDelete *([256]C.char)
			bufferPtrDelete = (*([256]C.char))(msghdr.msg_control)
			log.Printf("%v", bufferPtrDelete)
			for i := 0; i < 256 && i < msgContrLen; i++ {
				bufferPtrDelete[i] = 0x00
			}

			msghdr.msg_namelen = C.uint(0)
			//msghdr.msg_name is null

			//theoretisch gibt es hier mehrere
			//msghdr.msg_iov.iov_base = sendMsgTS.payload
			log.Printf("(SCIONgorecvmmsg) ----> &msgvec[%d].msg_hdr=%v", i, msghdr)
			log.Printf("(SCIONgorecvmmsg) ----> msghdr.msg_iov.iov_len=%v", msghdr.msg_iov.iov_len)
			log.Printf("(SCIONgorecvmmsg) ----> msghdr.msg_iov.iov_base=%v", msghdr.msg_iov.iov_base)

			/*
				add the ntp packet
			*/
			//msghdr.msg_iov.iov_base
			var bufferPtr *[C.IOVLEN]C.char
			bufferPtr = (*[C.IOVLEN]C.char)(msghdr.msg_iov.iov_base)
			var offsetNTP int
			var pktLen int
			pktLen += len(payloadMsg) //should be 48
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

			//ipv4 in network byte order: THIS should be THE Destination IP and Port
			/*
				bufferPtr[offsetNTP+16] = 10
				bufferPtr[offsetNTP+17] = 80
				bufferPtr[offsetNTP+18] = 45
				bufferPtr[offsetNTP+19] = -128
			*/
			dstipIPTest := sendMsgTS.pkt.Destination.Host.IP().To4()
			var dstIPTest C.uint32_t = C.uint32_t(binary.LittleEndian.Uint32(dstipIPTest))
			//writes destIp in network byte order into bufferPtr[offsetNTP+16]-bufferPtr[offsetNTP+19]
			*(*C.uint32_t)(unsafe.Pointer(&bufferPtr[offsetNTP+16])) = dstIPTest

			//port in network byte order
			bufferPtr[offsetNTP+ihl+2] = 0   //shoud be [22]
			bufferPtr[offsetNTP+ihl+3] = 123 //shoud be [23]
			//var dstPort C.uint16_t
			//dstPort = *(*C.uint16_t)(unsafe.Pointer(&bufferPtr[offsetNTP+ihl+2]))
			*(*C.uint16_t)(unsafe.Pointer(&bufferPtr[offsetNTP+ihl+2])) = C.htons(C.uint16_t(pld.DstPort))

			offsetNTP += ihl + 8 //should be 42
			pktLen += ihl + 8    //should be 90

			//copy ntp packet :-(
			for a, b := range payloadMsg {
				//log.Printf("a=%v b=%v", a, b)
				bufferPtr[a+offsetNTP] = C.char(b)
			}

			msgvec[i].msg_len = C.uint(pktLen)
			log.Printf("(SCIONgorecvmmsg) ----> msgvec[%d].msg_len=%v", i, msgvec[i].msg_len)

			/*
								Add Ancillary data

								To create ancillary data, first initialize the msg_controllen
				       member of the msghdr with the length of the control message
				       buffer.  Use CMSG_FIRSTHDR() on the msghdr to get the first
				       control message and CMSG_NXTHDR() to get all subsequent ones.  In
				       each control message, initialize cmsg_len (with CMSG_LEN()), the
				       other cmsghdr header fields, and the data portion using
				       CMSG_DATA().  Finally, the msg_controllen field of the msghdr
				       should be set to the sum of the CMSG_SPACE() of the length of all
				       control messages in the buffer.  For more information on the
				       msghdr, see recvmsg(2).
			*/

			var cmsg *C.struct_cmsghdr
			var cmsgDataPtr *C.uchar

			//ADD TIMESTAMPS
			cmsg = cmsgFirstHdr(msghdr)
			dataSize := unsafe.Sizeof(sendMsgTS.ts3)
			cmsg.cmsg_len = cmsgLen(C.size_t(dataSize))
			msgControllen += cmsgSpace(C.size_t(dataSize))
			log.Printf("(SCIONgorecvmmsg) ----> dataSize=%v cmsg.cmsg_len=%v msgControllen=%v", dataSize, cmsg.cmsg_len, msgControllen)
			//cmsg.cmsg_len = 64                  //unsigned long 8bytes
			cmsg.cmsg_level = C.SOL_SOCKET      //int 4bytes
			cmsg.cmsg_type = C.SCM_TIMESTAMPING //int 4bytes
			cmsgDataPtr = cmsgData(cmsg)

			//ACHTUNG: Kopiere hier Kernel und HW rein... unklar ob Chrony logik damit klarkommt
			//====> nein verwirft dann beide TS wenn HW "ungültig ist"
			//habe sie beim erstellen entfernt
			//Allenfalls sollte man hier memcpy() nehmen.....
			*(*C.struct_scm_timestamping)(unsafe.Pointer(cmsgDataPtr)) = sendMsgTS.ts3

			log.Printf("(SCIONgorecvmmsg) ----> cmsg.cmsg_len = %v", cmsg.cmsg_len)
			log.Printf("(SCIONgorecvmmsg) ----> cmsg.cmsg_level = %v", cmsg.cmsg_level)

			//ADD IP_PKTINFO
			cmsg = cmsgNextHdr(msghdr, cmsg)
			var iDontWantThis C.struct_in_pktinfo
			dataSize = unsafe.Sizeof(iDontWantThis)
			cmsg.cmsg_len = cmsgLen(C.size_t(dataSize))
			msgControllen += cmsgSpace(C.size_t(dataSize))
			log.Printf("(SCIONgorecvmmsg) ----> dataSize=%v cmsg.cmsg_len=%v msgControllen=%v", dataSize, cmsg.cmsg_len, msgControllen)
			//cmsg.cmsg_len = 28
			cmsg.cmsg_level = C.IPPROTO_IP
			cmsg.cmsg_type = C.IP_PKTINFO
			cmsgDataPtr = cmsgData(cmsg)

			srcipIP := sendMsgTS.pkt.Source.Host.IP().To4()
			var srcIP C.uint32_t = C.uint32_t(binary.LittleEndian.Uint32(srcipIP))

			dstipIP := sendMsgTS.pkt.Destination.Host.IP().To4()
			var dstIP C.uint32_t = C.uint32_t(binary.LittleEndian.Uint32(dstipIP))

			(*C.struct_in_pktinfo)(unsafe.Pointer(cmsgDataPtr)).ipi_ifindex = s.Sinfo.if_index
			(*C.struct_in_pktinfo)(unsafe.Pointer(cmsgDataPtr)).ipi_spec_dst.s_addr = srcIP
			(*C.struct_in_pktinfo)(unsafe.Pointer(cmsgDataPtr)).ipi_addr.s_addr = dstIP //TODO: activate this line and remove the next one
			//(*C.struct_in_pktinfo)(unsafe.Pointer(cmsgDataPtr)).ipi_addr.s_addr = C.htonl(173026688) //10.80.45.128

			/*
				memcpy(&ipi, CMSG_DATA(cmsg), sizeof(ipi));
				DEBUG_LOG("\t\t\t\t\tipi.ipi_ifindex=%d (Interface index)", ipi.ipi_ifindex);
				DEBUG_LOG("\t\t\t\t\tipi.ipi_spec_dst.s_addr=%s (Local address.. wrong->? Routing destination address)", inet_ntoa(ipi.ipi_spec_dst));
				DEBUG_LOG("\t\t\t\t\tipi.ipi_addr.s_addr=%s (Header destination address)", inet_ntoa(ipi.ipi_addr));
			*/

			//TODO msg_controllen
			msghdr.msg_controllen = msgControllen

			updatedElemmsgvec++
		}
		return C.int(updatedElemmsgvec)
	}

	//TODO: IP reaktivieren sobald korrekter Sender. d.h. ohne ntpscionendpoint ((*C.struct_sockaddr_in)(unsafe.Pointer(msghdr.msg_name)).sin_addr.s_addr)
	if receiveNTP && nMsg > 0 {
		//log.Printf("(SCIONgorecvmmsg) Receive NTP packet needs to be implemented!!!!!!!!!!!!!!!!")
		for i := 0; i < nMsg && i < int(vlen); i++ {
			rcvMsgNTPTS := <-s.rcvQueueNTPTS
			pld, ok := rcvMsgNTPTS.pkt.Payload.(snet.UDPPayload)
			if !ok {
				log.Printf("(SCIONgorecvmmsg) ----> There was an error parsing the udp payload. Skipping this packet!")
				continue
			}

			//log.Printf("(SCIONgorecvmmsg) ----> rcvMsgNTPTS=%v", rcvMsgNTPTS)

			//TODO C.VLEN should be variable i.e. equal to vlen
			var msgvec *([C.VLEN]C.struct_mmsghdr) = (*[C.VLEN]C.struct_mmsghdr)(unsafe.Pointer(vmessages))
			var msghdr *C.struct_msghdr
			msghdr = &msgvec[i].msg_hdr
			var msgControllen C.size_t

			ipIP := rcvMsgNTPTS.pkt.Source.Host.IP().To4()
			var srcIP C.uint32_t = C.uint32_t(binary.LittleEndian.Uint32(ipIP))
			msghdr.msg_namelen = C.uint(16)
			(*C.struct_sockaddr)(unsafe.Pointer(msghdr.msg_name)).sa_family = C.AF_INET
			//(*C.struct_sockaddr_in)(unsafe.Pointer(msghdr.msg_name)).sin_addr.s_addr = C.htonl(173026688) //TODO: NÖTIG FÜR FAKE INPUT activate this value "srcIP" directly
			(*C.struct_sockaddr_in)(unsafe.Pointer(msghdr.msg_name)).sin_addr.s_addr = srcIP
			(*C.struct_sockaddr_in)(unsafe.Pointer(msghdr.msg_name)).sin_port = C.htons(C.uint16_t(pld.SrcPort))

			/* as Chrony-Scion NTP server we have to keep track of the sender */
			if s.isNTPServer {

				//Get some space? :-(
				remoteAddr := &snet.UDPAddr{
					NextHop: &net.UDPAddr{},
					Host:    &net.UDPAddr{},
				}

				remoteAddr.Host.IP = rcvMsgNTPTS.pkt.Source.Host.IP()
				remoteAddr.Host.Port = int(pld.SrcPort)

				remoteAddr.IA = rcvMsgNTPTS.pkt.Source.IA

				//use the same path back to the client
				remoteAddr.Path = rcvMsgNTPTS.pkt.Path.Copy()
				remoteAddr.Path.Reverse()
				remoteAddr.NextHop = &rcvMsgNTPTS.ov

				log.Printf("(SCIONgorecvmmsg) ----> remoteAddr.IA = %v", remoteAddr.IA)
				log.Printf("(SCIONgorecvmmsg) ----> remoteAddr.Host = %v", remoteAddr.Host)
				log.Printf("(SCIONgorecvmmsg) ----> remoteAddr.NextHop = %v", remoteAddr.NextHop)
				log.Printf("(SCIONgorecvmmsg) ----> remoteAddr.Path = %v", remoteAddr.Path)

				clientMapping[remoteAddr.Host.String()] = remoteAddr

			}

			//log.Printf("(SCIONgorecvmmsg) ----> needed \t%v", C.htonl(173026688)) //10.80.45.128
			//log.Printf("(SCIONgorecvmmsg) ----> having \t%v", srcIP)

			payload := rcvMsgNTPTS.pkt.Payload.(snet.UDPPayload).Payload
			payloadLen := len(payload)
			msgvec[i].msg_len = C.uint(payloadLen) //48? depends on extensions
			log.Printf("(SCIONgorecvmmsg) ----> msgvec[%d].msg_len=%v", i, msgvec[i].msg_len)
			/*
			   payloadLen := len(pld.Payload)
			   ntpSize := int(unsafe.Sizeof(NTP_Packet{})) //minimum size header 48 bytes???

			   //adhoc security.... improve this
			   if payloadLen < ntpSize {
			   	fmt.Printf("(rcvLogic fd=%v) \t---->payload can't be a NTP packet (%d < %d) (IGNORING THIS...\n", payloadLen, ntpSize)
			   }
			*/

			/*
				add the ntp packet
			*/
			var bufferPtr *[C.IOVLEN]C.char
			bufferPtr = (*[C.IOVLEN]C.char)(msghdr.msg_iov.iov_base)
			//copy ntp packet :-(
			for a, b := range payload {
				//log.Printf("a=%v b=%v", a, b)
				bufferPtr[a] = C.char(b)
			}

			/*
				Add Ancillary data
			*/
			var cmsg *C.struct_cmsghdr
			var cmsgDataPtr *C.uchar

			// Add SCM_TIMESTAMPING_PKTINFO
			cmsg = cmsgFirstHdr(msghdr)
			var tspktinfo C.struct_scm_ts_pktinfo
			dataSize := unsafe.Sizeof(tspktinfo)
			cmsg.cmsg_len = cmsgLen(C.size_t(dataSize))
			msgControllen += cmsgSpace(C.size_t(dataSize))
			log.Printf("(SCIONgorecvmmsg) ----> dataSize=%v cmsg.cmsg_len=%v msgControllen=%v", dataSize, cmsg.cmsg_len, msgControllen)
			//cmsg.cmsg_len = 32
			cmsg.cmsg_level = C.SOL_SOCKET
			cmsg.cmsg_type = C.SCM_TIMESTAMPING_PKTINFO
			cmsgDataPtr = cmsgData(cmsg)
			(*C.struct_scm_ts_pktinfo)(unsafe.Pointer(cmsgDataPtr)).if_index = C.uint(s.Sinfo.if_index)
			(*C.struct_scm_ts_pktinfo)(unsafe.Pointer(cmsgDataPtr)).pkt_length = C.uint(pktLengtLayer2)

			// Add SO_TIMESTAMPING
			cmsg = cmsgNextHdr(msghdr, cmsg)
			dataSize = unsafe.Sizeof(rcvMsgNTPTS.ts3)
			cmsg.cmsg_len = cmsgLen(C.size_t(dataSize))
			msgControllen += cmsgSpace(C.size_t(dataSize))
			log.Printf("(SCIONgorecvmmsg) ----> dataSize=%v cmsg.cmsg_len=%v msgControllen=%v", dataSize, cmsg.cmsg_len, msgControllen)
			//cmsg.cmsg_len = 64
			cmsg.cmsg_level = C.SOL_SOCKET
			cmsg.cmsg_type = C.SCM_TIMESTAMPING
			cmsgDataPtr = cmsgData(cmsg)
			*(*C.struct_scm_timestamping)(unsafe.Pointer(cmsgDataPtr)) = rcvMsgNTPTS.ts3

			//ADD IP_PKTINFO
			cmsg = cmsgNextHdr(msghdr, cmsg)
			var iDontWantThis C.struct_in_pktinfo
			dataSize = unsafe.Sizeof(iDontWantThis)
			cmsg.cmsg_len = cmsgLen(C.size_t(dataSize))
			msgControllen += cmsgSpace(C.size_t(dataSize))
			log.Printf("(SCIONgorecvmmsg) ----> dataSize=%v cmsg.cmsg_len=%v msgControllen=%v", dataSize, cmsg.cmsg_len, msgControllen)
			//cmsg.cmsg_len = 28
			cmsg.cmsg_level = C.IPPROTO_IP
			cmsg.cmsg_type = C.IP_PKTINFO
			cmsgDataPtr = cmsgData(cmsg)

			ipIP = rcvMsgNTPTS.pkt.Destination.Host.IP().To4()
			var dstIP C.uint32_t = C.uint32_t(binary.LittleEndian.Uint32(ipIP))
			(*C.struct_in_pktinfo)(unsafe.Pointer(cmsgDataPtr)).ipi_ifindex = s.Sinfo.if_index
			//var aaa C.struct_in_addr
			//var bbb C.struct_in_addr
			//remove this c-call.... PARSE correct source address
			//aaa.s_addr = dstIP //C.htonl(173026643) //10.80.45.83??
			//bbb.s_addr = dstIP //C.htonl(173026643) //10.80.45.83??
			//should this always be the same for ipi_spec_dst and ipi_addr
			(*C.struct_in_pktinfo)(unsafe.Pointer(cmsgDataPtr)).ipi_spec_dst.s_addr = dstIP
			(*C.struct_in_pktinfo)(unsafe.Pointer(cmsgDataPtr)).ipi_addr.s_addr = dstIP

			msghdr.msg_controllen = msgControllen

			updatedElemmsgvec++
		}

		return C.int(updatedElemmsgvec)
	}

	log.Printf("(SCIONgorecvmmsg) ----> Unimplemented/unknown case... returning no messages!!!!!!")
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
