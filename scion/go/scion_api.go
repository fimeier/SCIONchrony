package main

// #include "../../config.h"
// #include "../../ntp.h"
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
// #include "../../scion.h"
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
	"github.com/scionproto/scion/go/lib/topology/underlay"
)

/* TODO:
-FDSTATUS in Map..... s, exists := fdstatus[fd] s.ändern.... dann zurückspeichern.... buggy
-------->array mit fd als index auf struct ptr
--------> work with fdstatus[fd] or its copy....

*/

// Increasing Counter for Logging purposes
var idRoutineRead int

//datastructure for SCIONselect
type fdset struct {
	fd                int
	exists            bool
	checkBothWorlds   bool
	readSelected      bool
	writeSelected     bool
	exceptSelected    bool
	readReady         bool
	writeReady        bool
	exceptReady       bool
	readReadyCworld   bool
	writeReadyCworld  bool
	exceptReadyCworld bool
}

//FDSTATUS contains EVERYTHING
type FDSTATUS struct {
	idRoutineRead int //useful for debugging
	//idRoutineSend      int         //inactive
	Fd    int         //fd corresponds to the socket number as used by chrony (could also be a pseudo fd)
	Sinfo C.fdInfoPtr //Pointer to fdInfo c-Struct

	sent               chan int //emulates sendmsg() interface by returning blocking or non blocking the number of bytes sent
	remoteAddress      string   //IP address as string
	remoteAddressSCION string   //Scion address as string
	rAddr              *snet.UDPAddr

	sdc daemon.Connector                     //same as the global one
	pds *snet.DefaultPacketDispatcherService //same as the global one

	ps             []snet.Path //set by SCIONgoconnect()
	selectedPath   snet.Path   //set by SCIONgoconnect()
	ctx            context.Context
	cancel         context.CancelFunc //SCIONgoclose will call cancel()
	conn           snet.PacketConn
	localPortSCION uint16 //the port returned by Register()

	connected bool //if set => SCIONgoconnect() finished without errors

	doneRcv       chan struct{} //close this to stop everything related to receiving
	rcvQueueNTPTS chan rcvMsgNTPTS
	sendQueueTS   chan sendMsgTS

	rcvLogicStarted bool

	txKERNELts bool //use this
	txHWts     bool //use this

	rxKERNELts bool //use this
	rxHWts     bool //use this

	scionTimestampingMode addr.HostSVC // something like addr.TxKernelHwRxKernelHw. Stored here so that it needs to be "calculated" only once

	isNTPServer    bool //identifies the scion ntp server (not the same as isbound!) <= there should only be one
	isbound        bool //identifies a socket SCIONgobind() has been called
	registerCalled bool //identifies a socket Register() has been called
	bindAddr       *snet.UDPAddr
}

type rcvMsgNTPTS struct {
	//tsType int //TS type.... not needed?
	//Todo Change to pointer?
	pkt snet.Packet //call like this should never fail (is checked befor added): rcvMsgNTPTS.pkt.Payload.(snet.UDPPayload)
	ov  net.UDPAddr
	ts3 C.struct_scm_timestamping

	//use this once finished... Ide is struggling on chrony with nested structs in cgo projects
	//--->common.PacketTSExtensionClient<-----

	KernelTS syscall.Timespec
	// HwTS contains a hardware timestamp
	HwTS syscall.Timespec
	// InterfaceID is equal to struct scm_ts_pktinfo.if_index (if in use)
	//
	// Rx timestamps will fill this in
	InterfaceID uint32
	// PktLengthL2 is equal to struct scm_ts_pktinfo.pkt_length (if in use)
	//
	// Rx timestamps will fill this in
	PktLengthL2 uint32
	// Ipi is equal to Inet4Pktinfo struct
	//
	// Hint: Using Ipi.Ifindex as this used by Rx AND Tx timestamps
	Ipi syscall.Inet4Pktinfo
}

/* Remark: ts3 have to be separated (if HW-TS isn't accepted, chrony's logic drops packets without considering Kernel TS in it)
Further: There are two messages needed for a correct message count in select (C-Library createse two separate messages: TS creation for Kernel/HW takes different amount of time)
*/
type sendMsgTS struct {
	//tsType int //TS type.... not needed?
	pkt *snet.Packet
	//payload []byte
	ts3 C.struct_scm_timestamping
	//sentTo *snet.UDPAddr //wird das jemals ausgelesen?

	//use this once finished... Ide is struggling on chrony with nested structs in cgo projects
	//--->common.PacketTSExtensionClient<-----

	KernelTS syscall.Timespec
	// HwTS contains a hardware timestamp
	HwTS syscall.Timespec
	// InterfaceID is equal to struct scm_ts_pktinfo.if_index (if in use)
	//
	// Rx timestamps will fill this in
	InterfaceID uint32
	// PktLengthL2 is equal to struct scm_ts_pktinfo.pkt_length (if in use)
	//
	// Rx timestamps will fill this in
	PktLengthL2 uint32
	// Ipi is equal to Inet4Pktinfo struct
	//
	// Hint: Using Ipi.Ifindex as this used by Rx AND Tx timestamps
	Ipi syscall.Inet4Pktinfo
}

/*
const (
	tskernelhardware = iota + 1
	tskernel
	tshardware
	rxkernelhardware
	rxkernel
	rxhardware
)
*/

/*
type NTP_int64 struct {
	hi uint32
	lo uint32
}

type NTP_Packet struct {
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

	//header length == 48 => extensions are not used
	//extensions [C.NTP_MAX_EXTENSIONS_LENGTH]uint8
}
*/

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

	if C.GODEBUG == 0 {
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

//fdstatus provides informations for a (virtual) fd == key
//
//Hint: Contains the data itself and not a pointer
//Reason: An fd can be created, used, delete AND recreated multiple times
//=> there can be some goroutines still running on the "old" entry, while we delete it and recreate it
//=> this should prevent raceconditions (there are probably better designs...)
var fdstatus = make(map[int]FDSTATUS)

// ClientMapping stores client addresses connecting over scion
//
// Assumptions: A client or node will contact us first. Then we keep track of the mapping.
// Otherwise the mapping exists somewhere in Chrony and we do not need to manage it
type ClientMapping struct {
	Addr      *snet.UDPAddr
	TimeAdded time.Time //just needed to allow a client to reconnect over normal "UDP connection" without restarting Chrony (And to get some memory back)
}

// ClientMappingTimeout specifies a timeout
const ClientMappingTimeout = 60 * time.Second //TODO: I guess this can also be smaller. But there is no point in doing it while debuggin

const clientMappingDeleteTimeout = ClientMappingTimeout //could be something longer

// IsScionNode arg tbd
//
// returns 1 == scion node
// return 0 == scion node, but old entry <= maybe not used (compare clientMappingDeleteTimeout)
// return -1 == not a scion node
//export IsScionNode
func IsScionNode(_remoteAddrString *C.char) (status C.int) {

	remoteAddrString := C.GoString(_remoteAddrString)

	cMap, exists := clientMapping[remoteAddrString]
	if exists {
		// scion node, but old entry
		if cMap.TimeAdded.Add(ClientMappingTimeout).Before(time.Now()) {
			// remove old entries
			if cMap.TimeAdded.Add(clientMappingDeleteTimeout).Before(time.Now()) {
				delete(clientMapping, remoteAddrString)
			}
			return 0
		}
		//scion node
		return 1
	}
	// not a scion node
	return -1
}

//var clientMapping = make(map[string](*snet.UDPAddr))
var clientMapping = make(map[string]ClientMapping)

var fdList = make(map[int]int)
var maxFD = 1024

//SCIONgoconnect creates the needed objects to call/recv data from a scion connections.
//Attention: This doesn't start a receive method! And probably no Register() call
//To send ntp packets as a client, Chrony calls: socket(), connect(), setsockopt(), send*(), *will also start receive method
//export SCIONgoconnect
func SCIONgoconnect(_fd C.int, callRegister C.int) C.int {

	fd := int(_fd)
	s, exists := fdstatus[fd]
	if !exists {
		log.Printf("(SCIONgoconnect) There is no state available for fd=%d\n", fd)
		return C.int(-1)
	}

	initScion()

	var err error

	s.remoteAddress = C.GoString(C.charPtr(unsafe.Pointer(&s.Sinfo.remoteAddress)))
	s.remoteAddressSCION = C.GoString(C.charPtr(unsafe.Pointer(&s.Sinfo.remoteAddressSCION)))

	s.rAddr, err = snet.ParseUDPAddr(s.remoteAddressSCION)
	if err != nil {
		log.Printf("(SCIONgoconnect) Couldn't parse \"%v\" go error: %v", s.remoteAddressSCION, err)
		return C.int(-1)
	}

	s.ctx, s.cancel = context.WithCancel(ctx)

	s.sdc = sdc
	s.pds = pds

	s.ps, err = s.sdc.Paths(s.ctx, s.rAddr.IA, localAddr.IA, daemon.PathReqFlags{Refresh: true})
	if err != nil {
		log.Printf("(SCIONgoconnect) Failed to lookup core paths: %v:", err)
		return C.int(-1)
	}

	//TODO: ACHTUNG DAS CRASHT WENN CONNECTION DOWN!!!! Should be okay now? Or was this err check always there?
	log.Printf("(SCIONgoconnect) Available paths to %v:\n", s.rAddr.IA)
	for _, p := range s.ps {
		log.Printf("(SCIONgoconnect)  \t%v\n", p)
	}

	s.selectedPath = s.ps[0]
	log.Printf("(SCIONgoconnect)  Selected path to %v: %v\n", s.rAddr.IA, s.selectedPath)

	s.rAddr.Path = s.selectedPath.Path()
	s.rAddr.NextHop = s.selectedPath.UnderlayNextHop()

	//THis should be the default behaviour after a call to UnerlayNextHop()
	if s.rAddr.NextHop == nil {
		s.rAddr.NextHop = s.rAddr.Copy().Host
		s.rAddr.NextHop.Port = underlay.EndhostPort
	}

	s.registerCalled = false

	//DIesen Teil hier sollte ich ausgliedern.... damit  addr.TxKernelHwRxKernelHw mit s.scionTimestampingMode ersetzt werden kann
	//TODO Art der TS's ist hier eigneltich nciht klar....
	if int(callRegister) == 1 {
		s.conn, s.localPortSCION, err = s.pds.Register(s.ctx, localAddr.IA, localAddr.Host, s.scionTimestampingMode)
		if err != nil {
			log.Printf("(SCIONgoconnect)  Failed to register client socket: %v", err)
			return C.int(-1)
		}
		s.registerCalled = true
	}

	s.connected = true
	s.sent = make(chan int)
	s.doneRcv = make(chan struct{})
	s.rcvQueueNTPTS = make(chan rcvMsgNTPTS, int(C.MSGBUFFERSIZE))
	s.sendQueueTS = make(chan sendMsgTS, int(C.MSGBUFFERSIZE))

	fdstatus[fd] = s //store it back
	log.Printf("(SCIONgoconnect) Created Connection. rcvLogic() not started")

	//TODO: ACHTUNG SETTINGS sockopt sind hier nicht gesetzt
	//log.Printf("(SCIONgoconnect) Starting Rcv-Go-Routine")
	//go s.rcvLogic() //bei send drin...

	return C.int(0) //TODO -1 for errors
}

var scionStarted bool
var sdc daemon.Connector
var pds *snet.DefaultPacketDispatcherService

func initScion() {
	if scionStarted {
		return
	}

	/* Start the Daemon Service here: One for all?*/
	var err error
	sdc, err = daemon.NewService(sciondAddr).Connect(ctx)
	if err != nil {
		log.Printf("(initScion) Failed to create SCION connector: %v", err)
		return
	}

	/* Start the Dispatcher Service here: One for all?*/
	pds = &snet.DefaultPacketDispatcherService{
		Dispatcher: reconnect.NewDispatcherService(reliable.NewDispatcher("")),
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: nil,
		},
	}

	scionStarted = true
}

// SCIONstartntp Used to call Scion's Register() and to start recv Logic: now all socket options should be set.
//
// Compare the listing at the end.
//export SCIONstartntp
func SCIONstartntp() C.int {
	initScion()
	var err error
	for _, s := range fdstatus {

		if s.isbound { //we could have more then one port: NTP-Server, Client-Interface, ...

			if s.registerCalled == false {
				//As THE Server we do activate Tx-TS's. It is also possible to do this while sending,
				//but for this we need to transmit an additional bit (similar to how we communicate the oob data)
				//Compare sendmsgOverScion and the corresponding part in Scionproto (search for 4242666 in this document)
				//
				if s.isNTPServer {
					s.txKERNELts = true
					s.txHWts = s.rxHWts
					switch s.scionTimestampingMode {
					case addr.RxKernel:
						s.scionTimestampingMode = addr.TxKernelRxKernel
					case addr.RxKernelHw:
						s.scionTimestampingMode = addr.TxKernelHwRxKernelHw
					}

				}
				s.conn, s.localPortSCION, err = s.pds.Register(s.ctx, s.bindAddr.IA, s.bindAddr.Host, s.scionTimestampingMode)
				if err != nil {
					log.Printf("(SCIONstartntp)  Failed to register client socket:  %v", err)
					return C.int(-1)
				}
				s.registerCalled = true
				fdstatus[s.Fd] = s
				log.Printf("(SCIONgobind)--> bindAddr.IA=%v, bindAddr.Host=%v s.scionTimestampingMode=%v s.txHWts=%v s.txKERNELts=%v s.rxHWts=%v s.rxKERNELts=%v", s.bindAddr.IA, s.bindAddr.Host, s.scionTimestampingMode, s.txHWts, s.txKERNELts, s.rxHWts, s.rxKERNELts)

			}

			if !s.rcvLogicStarted {
				s.rcvLogicStarted = true
				idRoutineRead++
				s.idRoutineRead = idRoutineRead
				fdstatus[s.Fd] = s
				catchMeGo := fdstatus[s.Fd]
				log.Printf("(SCIONstartntp) Starting Rcv-Go-Routine for fd=%v", catchMeGo.Fd)
				go catchMeGo.rcvLogic()
			}

		}
	}
	return C.int(0)

	/* Compare this to understand how Scion is calling the different functions to setup up the "NTP-server-socket"
			=> Observe the last setsocketopt()-call: finally we know the TS-Settings

	   2021-01-27T10:10:05Z scion.c:218:(SCION_socket) Creating socket with domain=2 type=526338 protocol=0
	   2021-01-27T10:10:05Z scion.c:243:(SCION_socket) ----> domain = AF_INET
	   2021-01-27T10:10:05Z scion.c:260:(SCION_socket) ----> type = SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK
	   2021-01-27T10:10:05Z scion.c:278:(SCION_socket) ----> fd = 8 (received from system, using this for SCION)
	   2021/01/27 10:10:05 scion_api.go:734: (SCIONgosocket) Creating "socket" fd=8
	   2021/01/27 10:10:05 scion_api.go:760: (SCIONgosocket) ----> domain=2 type=526338 protocol=0
	   2021/01/27 10:10:05 scion_api.go:762: (SCIONgosocket) ----> type == C.SOCK_DGRAM|C.SOCK_CLOEXEC|C.SOCK_NONBLOCK
	   2021/01/27 10:10:05 scion_api.go:765: (SCIONgosocket) ----> type => C.SOCK_DGRAM
	   2021/01/27 10:10:05 scion_api.go:768: (SCIONgosocket) ----> type => C.SOCK_NONBLOCK
	   2021-01-27T10:10:05Z scion.c:303:(SCION_setsockopt)     Setting options fd=8 level=1 optname=6
	   2021-01-27T10:10:05Z scion.c:343:(SCION_setsockopt)     |----> level = SOL_SOCKET
	   2021-01-27T10:10:05Z scion.c:360:(SCION_setsockopt)     |----> optname = SO_BROADCAST
	   2021-01-27T10:10:05Z scion.c:388:(SCION_setsockopt)     |----> optval = 1 => activate option
	   2021-01-27T10:10:05Z scion.c:450:(SCION_setsockopt)     |----> Info: We always set the socket options in the c-world
	   2021-01-27T10:10:05Z scion.c:303:(SCION_setsockopt)     Setting options fd=8 level=0 optname=8
	   2021-01-27T10:10:05Z scion.c:321:(SCION_setsockopt)     |----> level = IPPROTO_IP
	   2021-01-27T10:10:05Z scion.c:326:(SCION_setsockopt)     |----> optname = IP_PKTINFO
	   2021-01-27T10:10:05Z scion.c:388:(SCION_setsockopt)     |----> optval = 1 => activate option
	   2021-01-27T10:10:05Z scion.c:450:(SCION_setsockopt)     |----> Info: We always set the socket options in the c-world
	   2021-01-27T10:10:05Z scion.c:303:(SCION_setsockopt)     Setting options fd=8 level=1 optname=2
	   2021-01-27T10:10:05Z scion.c:343:(SCION_setsockopt)     |----> level = SOL_SOCKET
	   2021-01-27T10:10:05Z scion.c:348:(SCION_setsockopt)     |----> optname = SO_REUSEADDR
	   2021-01-27T10:10:05Z scion.c:388:(SCION_setsockopt)     |----> optval = 1 => activate option
	   2021-01-27T10:10:05Z scion.c:450:(SCION_setsockopt)     |----> Info: We always set the socket options in the c-world
	   2021-01-27T10:10:05Z scion.c:303:(SCION_setsockopt)     Setting options fd=8 level=1 optname=15
	   2021-01-27T10:10:05Z scion.c:343:(SCION_setsockopt)     |----> level = SOL_SOCKET
	   2021-01-27T10:10:05Z scion.c:352:(SCION_setsockopt)     |----> optname = SO_REUSEPORT
	   2021-01-27T10:10:05Z scion.c:388:(SCION_setsockopt)     |----> optval = 1 => activate option
	   2021-01-27T10:10:05Z scion.c:450:(SCION_setsockopt)     |----> Info: We always set the socket options in the c-world
	   2021-01-27T10:10:05Z scion.c:303:(SCION_setsockopt)     Setting options fd=8 level=0 optname=15
	   2021-01-27T10:10:05Z scion.c:321:(SCION_setsockopt)     |----> level = IPPROTO_IP
	   2021-01-27T10:10:05Z scion.c:330:(SCION_setsockopt)     |----> optname = IP_FREEBIND
	   2021-01-27T10:10:05Z scion.c:388:(SCION_setsockopt)     |----> optval = 1 => activate option
	   2021-01-27T10:10:05Z scion.c:450:(SCION_setsockopt)     |----> Info: We always set the socket options in the c-world
	   2021-01-27T10:10:05Z scion.c:486:(SCION_bind)   Binding fd=8
	   2021-01-27T10:10:05Z scion.c:496:(SCION_bind)   |----> 0.0.0.0:123
	   2021-01-27T10:10:34Z scion.c:500:(SCION_bind)   |----> calling SCIONgobind() as this is is Chrony's NTP-Server Socket
	   2021/01/27 10:11:05 scion_api.go:512: (SCIONgobind)--> bindAddr.IA=1-ff00:0:112, bindAddr.Host=10.80.45.83:123
	   2021/01/27 10:11:05 scion_api.go:521: (SCIONgobind)--> Registered Port 123 for fd=8. rcvLogic() not started!
	   2021-01-27T10:11:08Z scion.c:503:(SCION_bind)   |----> SCIONgobind() return-state: 0
	   2021-01-27T10:13:09Z scion.c:506:(SCION_bind)   |----> SCIONgobind() Also bound normal port. Combined return state: 0
	   2021-01-27T10:14:10Z socket.c:495:(open_ip_socket) Opened UDPv4 socket fd=8 local=0.0.0.0:123
	   2021-01-27T10:14:19Z scion.c:303:(SCION_setsockopt)     Setting options fd=8 level=1 optname=45
	   2021-01-27T10:14:19Z scion.c:343:(SCION_setsockopt)     |----> level = SOL_SOCKET
	   2021-01-27T10:14:19Z scion.c:364:(SCION_setsockopt)     |----> optname = SO_SELECT_ERR_QUEUE
	   2021-01-27T10:14:19Z scion.c:388:(SCION_setsockopt)     |----> optval = 1 => activate option
	   2021-01-27T10:14:19Z scion.c:450:(SCION_setsockopt)     |----> Info: We always set the socket options in the c-world
	   2021-01-27T10:14:19Z scion.c:303:(SCION_setsockopt)     Setting options fd=8 level=1 optname=37
	   2021-01-27T10:14:19Z scion.c:343:(SCION_setsockopt)     |----> level = SOL_SOCKET
	   2021-01-27T10:14:19Z scion.c:356:(SCION_setsockopt)     |----> optname = SO_TIMESTAMPING
	   2021-01-27T10:14:19Z scion.c:388:(SCION_setsockopt)     |----> optval = 25692 => activate option
	   2021-01-27T10:14:19Z scion.c:399:(SCION_setsockopt)     |---->  This is the option to activate RX-Timestamps (HW/Kernel)
	   2021-01-27T10:14:19Z scion.c:450:(SCION_setsockopt)     |----> Info: We always set the socket options in the c-world
	   2021/01/27 10:14:19 scion_api.go:717: (SCIONgosetsockopt) |--> Called for socket 8. Checking settings...
	   2021/01/27 10:14:19 scion_api.go:718: (SCIONgosetsockopt) |--> createTxTimestamp=false
	   2021/01/27 10:14:19 scion_api.go:719: (SCIONgosetsockopt) |--> createRxTimestamp=true
	   2021/01/27 10:14:19 scion_api.go:720: (SCIONgosetsockopt) |--> enableHwTimestamp=true
	   2021/01/27 10:14:19 scion_api.go:721: (SCIONgosetsockopt) |--> scionTimestampingMode=UNKNOWN M (0xaaa1)
	*/
}

//SCIONgobind emulates a bind() call.
//
// callRegister "bool": compare comment in SCIONstartntp.
// The assumption is, that callRegister will always be 0. At least as long as we do not open a scion-connection for the client interface.
// Once we do it, we will be happy to directly start everythin at this point here (rcvlogic, Register()...)
//export SCIONgobind
func SCIONgobind(_fd C.int, _port C.uint16_t, callRegister C.int) C.int {
	fd := int(_fd)
	s, exists := fdstatus[fd]
	if !exists {
		log.Printf("(SCIONgobind) There is no state available for fd=%d\n", fd)
		return C.int(-1)
	}

	initScion()

	port := int(_port)

	var err error

	if int(s.Sinfo.connectionType) == int(C.IS_NTP_SERVER) {
		s.isNTPServer = true
	}

	s.ctx, s.cancel = context.WithCancel(ctx)

	s.sdc = sdc
	s.pds = pds

	s.bindAddr, err = snet.ParseUDPAddr(localAddrStr)
	if err != nil {
		log.Fatal("(SCIONgobind) Failed to parse local Address:", err)
		return C.int(-1) //should never return
	}
	s.bindAddr.Host.Port = port //set the correct port

	//Chrony's NTP-Server will not call this. Compare SCIONstartntp()
	if int(callRegister) == 1 {
		s.conn, s.localPortSCION, err = s.pds.Register(s.ctx, s.bindAddr.IA, s.bindAddr.Host, s.scionTimestampingMode)
		if err != nil {
			log.Printf("(SCIONgobind)  Failed to register client socket:  %v", err)
			return C.int(-1)
		}

		log.Printf("(SCIONgobind)--> bindAddr.IA=%v, bindAddr.Host=%v", s.bindAddr.IA, s.bindAddr.Host)
	}
	s.registerCalled = false
	s.isbound = true
	s.sent = make(chan int)
	s.doneRcv = make(chan struct{})
	s.rcvQueueNTPTS = make(chan rcvMsgNTPTS, int(C.MSGBUFFERSIZESERVER))
	s.sendQueueTS = make(chan sendMsgTS, int(C.MSGBUFFERSIZESERVER))

	fdstatus[fd] = s //store it back
	log.Printf("(SCIONgobind)--> Registered Port %v for fd=%v. rcvLogic() not started!", port, fd)

	//Chrony's NTP-Server will not call this. Compare SCIONstartntp()
	if int(callRegister) == 1 {
		s.registerCalled = true
		s.rcvLogicStarted = true
		idRoutineRead++
		s.idRoutineRead = idRoutineRead
		fdstatus[fd] = s
		log.Printf("(SCIONgobind)--> Starting Rcv-Go-Routine for fd=%v with idRoutineRead=%v", fd, idRoutineRead)
		go s.rcvLogic()
	}

	return C.int(0) //TODO -1 for errors
}

func (s *FDSTATUS) rcvLogic() {
	var nMessagesReceived int
	var nErrQueueMsgsReceived int

	log.Printf("(rcvLogic fd=%v idRoutineRead=%v) Started", s.Fd, s.idRoutineRead)

	for {
		var rcvMsgNTPTS rcvMsgNTPTS

		//Just here to find missing go-Routines
		/*
			second := time.Now().Add(1000 * time.Millisecond) //time.Time{}
			s.conn.SetReadDeadline(second)
		*/

		log.Printf("(rcvLogic fd=%v idRoutineRead=%v) Calling s.conn.ReadFrom() s.isNTPServer=%v nMessagesReceived=%v nErrQueueMsgsReceived=%v(until now)", s.Fd, s.idRoutineRead, s.isNTPServer, nMessagesReceived, nErrQueueMsgsReceived)
		err := s.conn.ReadFrom(&rcvMsgNTPTS.pkt, &rcvMsgNTPTS.ov)
		if err != nil {

			//checking if this was an error or if we have been cancelled
			if cancelled(s.doneRcv) {
				log.Printf("(rcvLogic fd=%v idRoutineRead=%v) I have been cancelled. Returning.", s.Fd, s.idRoutineRead)
				break
			}
			log.Printf("(rcvLogic fd=%v) \t---->Failed to read packet: %v", s.Fd, err)
			//TODO decide if we really want to continue
			continue
		}

		/*
			This is an ERR_QUEUE_MSG probably a TX timestamp!!!
		*/
		if rcvMsgNTPTS.ov.IP == nil {
			nErrQueueMsgsReceived++
			log.Printf("(rcvLogic fd=%v idRoutineRead=%v) ----> Received ERR_QUEUE_MSG: Kernel-TS=%v HW-TS=%v", s.Fd, s.idRoutineRead, rcvMsgNTPTS.pkt.KernelTS, rcvMsgNTPTS.pkt.HwTS)

			var msgTS sendMsgTS

			//Needed? If the payload can be extracted there should be a message
			_, ok := rcvMsgNTPTS.pkt.Payload.(snet.UDPPayload)
			if !ok {
				continue //return //continue
			}

			msgTS.pkt = &rcvMsgNTPTS.pkt

			//Why ts3 and also KenelTS and HwTS
			//only one of ts[0], ts[2] will be non zero
			//we do not need to know witch one in the SCIONgorecvmmsg()
			//msgTS.KernelTS and msgTS.HwTS are stored because I return them now and can be useful for desing changes
			var ts3 C.struct_scm_timestamping
			//kernel ts
			ts3.ts[0].tv_sec = C.long(rcvMsgNTPTS.pkt.KernelTS.Sec)
			ts3.ts[0].tv_nsec = C.long(rcvMsgNTPTS.pkt.KernelTS.Nsec)
			//hardware ts
			ts3.ts[2].tv_sec = C.long(rcvMsgNTPTS.pkt.HwTS.Sec)
			ts3.ts[2].tv_nsec = C.long(rcvMsgNTPTS.pkt.HwTS.Nsec)
			msgTS.ts3 = ts3

			msgTS.KernelTS = rcvMsgNTPTS.pkt.KernelTS
			msgTS.HwTS = rcvMsgNTPTS.pkt.HwTS

			msgTS.InterfaceID = rcvMsgNTPTS.pkt.InterfaceID
			msgTS.PktLengthL2 = rcvMsgNTPTS.pkt.PktLengthL2
			msgTS.Ipi = rcvMsgNTPTS.pkt.Ipi

			if s.txKERNELts && rcvMsgNTPTS.pkt.KernelTS.Sec != 0 {
				log.Printf("(rcvLogic fd=%v idRoutineRead=%v) ----> Calling s.sendQueueTS <- msgTS ts3(Kernel)=%v", s.Fd, s.idRoutineRead, ts3)
				s.sendQueueTS <- msgTS
			}
			if s.txHWts && rcvMsgNTPTS.pkt.HwTS.Sec != 0 {
				log.Printf("(rcvLogic fd=%v idRoutineRead=%v) ----> Calling s.sendQueueTS <- msgTS ts3(HW)=%v", s.Fd, s.idRoutineRead, ts3)
				s.sendQueueTS <- msgTS
			}
			if !s.txHWts && msgTS.HwTS.Sec != 0 { //should not happen
				log.Printf("(rcvLogic fd=%v idRoutineRead=%v) ----> Received a Tx-HW-Ts but will not forward it, as it hasn't been requested %v\n", s.Fd, s.idRoutineRead, msgTS.HwTS)
			}

		} else {
			/*
				This is a normal message... probably an NTP message and Rx Timestamps!!!
			*/

			nMessagesReceived++
			log.Printf("(rcvLogic fd=%v idRoutineRead=%v) ----> Received NTP Packet: Kernel-TS=%v HW-TS=%v", s.Fd, s.idRoutineRead, rcvMsgNTPTS.pkt.KernelTS, rcvMsgNTPTS.pkt.HwTS)

			//Needed? If the payload can be extracted there should be a message
			_, ok := rcvMsgNTPTS.pkt.Payload.(snet.UDPPayload)
			if !ok {
				continue //return //continue
			}

			rcvMsgNTPTS.KernelTS = rcvMsgNTPTS.pkt.KernelTS
			rcvMsgNTPTS.HwTS = rcvMsgNTPTS.pkt.HwTS

			rcvMsgNTPTS.InterfaceID = rcvMsgNTPTS.pkt.InterfaceID
			rcvMsgNTPTS.PktLengthL2 = rcvMsgNTPTS.pkt.PktLengthL2
			rcvMsgNTPTS.Ipi = rcvMsgNTPTS.pkt.Ipi

			if s.rxKERNELts {
				//a kernel ts
				rcvMsgNTPTS.ts3.ts[0].tv_sec = C.long(rcvMsgNTPTS.pkt.KernelTS.Sec)
				rcvMsgNTPTS.ts3.ts[0].tv_nsec = C.long(rcvMsgNTPTS.pkt.KernelTS.Nsec)
				log.Printf("(rcvLogic fd=%v idRoutineRead=%v) ----> Returning Kernel-Ts %v", s.Fd, s.idRoutineRead, rcvMsgNTPTS.KernelTS)
			}

			if s.rxHWts {
				//a hw ts
				rcvMsgNTPTS.ts3.ts[2].tv_sec = C.long(rcvMsgNTPTS.pkt.HwTS.Sec)
				rcvMsgNTPTS.ts3.ts[2].tv_nsec = C.long(rcvMsgNTPTS.pkt.HwTS.Nsec)
				log.Printf("(rcvLogic fd=%v idRoutineRead=%v) ----> Returning Hw-Ts %v", s.Fd, s.idRoutineRead, rcvMsgNTPTS.HwTS)
			}

			if !s.txHWts && rcvMsgNTPTS.HwTS.Sec != 0 {
				//Hint: We do not add it to ts3 and therefore will not distrub the client if it is looking at those values
				log.Printf("(rcvLogic fd=%v idRoutineRead=%v) ----> Received a Rx-HW-Ts but it hasn't been requested %v (expected if the option is activated in Scionproto\n", s.Fd, s.idRoutineRead, rcvMsgNTPTS.HwTS)
			}

			/* the only thing really important comes here.. */
			s.rcvQueueNTPTS <- rcvMsgNTPTS
		}
	}
	s.rcvLogicStarted = false
	log.Printf("(rcvLogic fd=%v idRoutineRead=%v) ----> Finished recv my message. Returning.", s.Fd, s.idRoutineRead)

}

//SCIONgosetsockopt gets called each time a setsockopt() is executed for So_TIMESTAMPING options.
//Settings are encoded inside of Sinfo. Some of the options are explicitely set in go's memory (redundant).
//export SCIONgosetsockopt
func SCIONgosetsockopt(_fd C.int) C.int {
	fd := int(_fd)
	s, exists := fdstatus[fd]
	if !exists {
		log.Fatalf("(SCIONgosetsockopt) Non-existing fdstatus[%v]\n", fd) //change this to fatal?
		return C.int(-1)
	}

	/*Will be set everytime the function is called....
	int level_optname_value[SCION_LE_LEN][SCION_OPTNAME_LEN]; //optval !=0 0==disabled contains all the other informations
	*/
	createTxTimestamp := int(s.Sinfo.createTxTimestamp) == 1
	createRxTimestamp := int(s.Sinfo.createRxTimestamp) == 1
	enableHwTimestamp := int(s.Sinfo.createHwTimestamp) == 1

	s.txKERNELts = createTxTimestamp
	s.txHWts = createTxTimestamp && enableHwTimestamp
	s.rxKERNELts = createRxTimestamp
	s.rxHWts = createRxTimestamp && enableHwTimestamp

	if createTxTimestamp && createRxTimestamp && enableHwTimestamp {
		s.scionTimestampingMode = addr.TxKernelHwRxKernelHw
	} else if createTxTimestamp && createRxTimestamp {
		s.scionTimestampingMode = addr.TxKernelRxKernel
	} else if createRxTimestamp && enableHwTimestamp {
		s.scionTimestampingMode = addr.RxKernelHw
	} else if createRxTimestamp {
		s.scionTimestampingMode = addr.RxKernel
	} else {
		s.scionTimestampingMode = addr.SvcNone
	}

	fdstatus[fd] = s //store it back

	log.Printf("(SCIONgosetsockopt) |--> Called for socket %d. Checking settings...\n", fd)
	log.Printf("(SCIONgosetsockopt) |--> createTxTimestamp=%v", createTxTimestamp)
	log.Printf("(SCIONgosetsockopt) |--> createRxTimestamp=%v", createRxTimestamp)
	log.Printf("(SCIONgosetsockopt) |--> enableHwTimestamp=%v", enableHwTimestamp)
	log.Printf("(SCIONgosetsockopt) |--> scionTimestampingMode=%v", s.scionTimestampingMode)

	/*On success, zero is returned for the standard options.  On error, -1
	is returned, and errno is set appropriately.*/
	return C.int(0)
}

//SCIONgosocket creates the needed datastructure to keep state in the SCION-GO-World.
//sinfo is a pointer into C's memory. domain, _type and protocol aren't used at the moment, as the are contained in sinfo
//Hint: Interface is designed to allow for future changes
//export SCIONgosocket
func SCIONgosocket(domain C.int, _type C.int, protocol C.int, sinfo C.fdInfoPtr) C.int {
	fd := int(sinfo.fd)
	log.Printf("(SCIONgosocket) Creating \"socket\" fd=%d\n", fd)

	_, exists := fdstatus[fd]
	if exists {
		log.Printf("(SCIONgosocket) ERROR Already existing entry for fd=%v", fd)
		return C.int(-1) //TODOdefine correct behaviour
	}

	newState := FDSTATUS{Fd: fd, Sinfo: sinfo, scionTimestampingMode: addr.SvcNone}
	//store it
	fdstatus[fd] = newState

	//code snippets: What we could do
	/*
		domainS := int(sinfo.domain)
		typeS := int(sinfo._type)
		protocolS := int(sinfo.protocol)
		connectionTypeS := int(sinfo.connectionType)
		fmt.Printf("\tdomain=%d type=%d protocol=%d\n", domain, _type, protocol)
		fmt.Printf("fd=%d domainS=%d typeS=%d protocolS=%d connectionTypeS=%d\nsinfo=%v\n", fd, domainS, typeS, protocolS, connectionTypeS, sinfo)
	*/
	//Just debugging and pretty printing
	if C.GODEBUG == 1 {
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
	}

	return C.int(newState.Fd)
}

// SCIONgoclose closes all routines working with this (virtual) fd and delete any datastructures created to keep state
//
//export SCIONgoclose
func SCIONgoclose(_fd C.int) C.int {
	fd := int(_fd)
	log.Printf("(SCIONgoclose) \"Closing socket\" %d\n", fd)
	s, exists := fdstatus[fd]
	if !exists {
		log.Fatalf("(SCIONgoclose) Non-existing fdstatus[%d]\n", fd) //change this to fatal?
		return C.int(-1)
	}
	if s.doneRcv != nil {
		log.Printf("(SCIONgoclose) ----> closing doneRcv channel for idRoutineRead=%v", s.idRoutineRead)
		close(s.doneRcv)
	}

	if s.cancel != nil {
		//This will force any blocking read call to return
		s.cancel()
	}

	if s.conn != nil {
		log.Printf("(SCIONgoclose) ----> s.conn.Close() for idRoutineRead=%v", s.idRoutineRead)
		s.conn.Close()
	}

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

As a simple solution: checkNTPfile and checkNTPexcept are used to tell recevmsg to also check the c-world
We always call the go world, this will be correct in most cases and it always returns.
Keep in mind, this is just a test. I want to get rid of everything that comes into play when we have to receive tx-ts over scion.
*/
//export SCIONselect
func SCIONselect(nfds C.int, readfds C.fdsetPtr, writefds C.fdsetPtr, exceptfds C.fdsetPtr, timeout C.timevalPtr, checkNTPfile *C.int, checkNTPexcept *C.int) C.int {
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

		//tickTime = 2 * time.Second

		ticker = time.Tick(tickTime)
	} else {
		tvsec = timeout.tv_sec
		tvusec = timeout.tv_usec
		t = time.Duration(tvsec)*time.Second + time.Duration(tvusec)*time.Microsecond
		tickTime = t / 20
		if tickTime > 500*time.Millisecond {
			tickTime = 500 * time.Millisecond
		}

		lowerBound := time.Duration(300)
		if tickTime < lowerBound*time.Millisecond {
			tickTime = lowerBound * time.Millisecond
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

		var checkBothWorlds bool
		s, exists := fdstatus[fd] //we can ignore them: Assumption: We are still in chronyd's main thread => while we are in SCIONselect, there cannot be created any new states. If this is not true anymore, check it at the beginning of the loop. Relevant for very long running timeouts.
		if exists {
			if s.isNTPServer {
				checkBothWorlds = true
				//log.Printf("(SCIONselect) ACHTUNG: checkBothWorlds kann für NTP Server nicht aktiviert werden, da recv (noch) nicht vorbereitet")
			}
		} //What was the other case? :-) We don't care. We could continue here if dualmode is disabled

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
					fd:                fd,
					exists:            exists,          //if they don't exist => must be a c-Sockets
					checkBothWorlds:   checkBothWorlds, //also check c-Sockets: for the NTPServer relevant
					readSelected:      rIsSet,
					writeSelected:     wIsSet,
					exceptSelected:    eIsSet,
					readReady:         false,
					writeReady:        false,
					exceptReady:       false,
					readReadyCworld:   false,
					writeReadyCworld:  false,
					exceptReadyCworld: false,
				})
		}

	}

	if int(C.SCIONUDPDUALMODE) == 1 {
		log.Printf("(SCIONselect) ----> SCIONUDPDUALMODE enabled.... checking c-world")
	}

	numOfBitsSet := 0
	for {

		//startSelect := time.Now()

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
					if fdset.readReadyCworld != true {
						numOfBitsSet++
					}
				}
			}
			if fdset.exceptSelected {
				errorMsg = len(s.sendQueueTS) //exceptions
				if errorMsg > 0 {
					fdset.exceptReady = true
					if fdset.writeReadyCworld != true {
						numOfBitsSet++
					}
				}
			}

			if readMsg+errorMsg > 0 {
				log.Printf("(SCIONselect) ----> fd=%v: readMsg=%v errorMsg=%v", fdset.fd, readMsg, errorMsg)
			}
		}

		//Experimental: Achtung behaviour unklar: Socket kann in Scion, C oder beiden bestehen
		//Prüfe aktuell einfach Sockets die nur in C-Bestehen => fdset.exists sollte nicht bestehen
		//Todo prüfe ob das mit dem rückschreiben so funktioniert, bzw ob es etwas killt
		if int(C.SCIONUDPDUALMODE) == 1 { //also check C-World socket's for incomming data
			//log.Printf("(SCIONselect) ----> SCIONUDPDUALMODE enabled.... checking c-world")

			//GOlang FD_ZERO() needed?
			var cRead syscall.FdSet
			var cWrit syscall.FdSet
			var cExec syscall.FdSet

			cr := (*fdsetType)(unsafe.Pointer(&cRead))
			cw := (*fdsetType)(unsafe.Pointer(&cWrit))
			ce := (*fdsetType)(unsafe.Pointer(&cExec))

			var ctimeout syscall.Timeval
			ctimeout.Sec = 0
			ctimeout.Usec = 0

			//create a copy of c's fdset
			for _, fdset := range fdsets {
				/*var cause string
				if !fdset.exists { //optimization: prevents fdstatus[fdset.fd] calls
					cause = "c-world only socket"
				}
				if fdset.checkBothWorlds {
					cause = "exists in both worlds"
				}*/

				var fdPtr uintptr
				fdPtr = uintptr(fdset.fd)

				if fdset.readSelected {
					//log.Printf("(SCIONselect) ----> fd=%v %s with activated SCH_FILE_INPUT", fdset.fd, cause)
					cr.Set(fdPtr)
				}
				if fdset.writeSelected {
					//log.Printf("(SCIONselect) ----> fd=%v %s with activated SCH_FILE_OUTPUT", fdset.fd, cause)
					cw.Set(fdPtr)
				}
				if fdset.exceptSelected {
					//log.Printf("(SCIONselect) ----> fd=%v %s with activated SCH_FILE_EXCEPTION", fdset.fd, cause)
					ce.Set(fdPtr)
				}

			}
			//call select()
			//log.Printf("(SCIONselect) ----> Before calling select: cRead=%v\n", cRead)
			n, err := syscall.Select(int(nfds), &cRead, &cWrit, &cExec, &ctimeout)
			//log.Printf("(SCIONselect) ----> After calling select: cRead=%v", cRead)
			if err != nil {
				log.Printf("(SCIONselect) ----> syscall.Select() returned n=%v err=%v", n, err)
			}

			//evaluate response
			for _, fdset := range fdsets {
				if !fdset.exists || fdset.checkBothWorlds { //a c-world only socket or the NTPServer
					var fdPtr uintptr
					fdPtr = uintptr(fdset.fd)
					var didSomeThing bool

					if cr.IsSet(fdPtr) {
						fdset.readReadyCworld = true
						if fdset.readReady != true {
							numOfBitsSet++
							didSomeThing = true
						}
						if fdset.checkBothWorlds { //this is the NTPServer
							*checkNTPfile = C.int(1)
						}
					}

					if cw.IsSet(fdPtr) {
						fdset.writeReadyCworld = true
						if fdset.writeReady != true {
							numOfBitsSet++
							didSomeThing = true
						}
					}

					if ce.IsSet(fdPtr) {
						fdset.exceptReadyCworld = true
						if fdset.exceptReady != true {
							numOfBitsSet++
							didSomeThing = true
						}
						if fdset.checkBothWorlds { //this is the NTPServer
							*checkNTPexcept = C.int(1)
						}
					}
					if didSomeThing {
						log.Printf("(SCIONselect) ----> evaluation for fd=%v r=%v w=%v e=%v", fdset.fd, fdset.readReadyCworld, fdset.writeReadyCworld, fdset.exceptReadyCworld)
					}
				}
			}

		}

		//selectDuration := time.Now()
		//elapsed := selectDuration.Sub(startSelect)

		//blocking means no timeout. The ticker is just here to prevent a busyloop
		if numOfBitsSet == 0 && (time.Since(start) < t || blocking) {
			//Sleep
			//log.Printf("(SCIONselect) Waiting for next tick.... highestFd=%v timeout=%v tickTime=%v Select-execution-took=%v", highestFd, t, tickTime, elapsed)
			<-ticker
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
		if int(C.SCIONUDPDUALMODE) == 1 {
			if readfds != nil && fdset.readSelected && !fdset.readReady && !fdset.readReadyCworld {
				rset.Clr(fdPtr)
			}
			if writefds != nil && fdset.writeSelected && !fdset.writeReady && !fdset.writeReadyCworld {
				wset.Clr(fdPtr)
			}
			if exceptfds != nil && fdset.exceptSelected && !fdset.exceptReady && !fdset.exceptReadyCworld {
				eset.Clr(fdPtr)
			}
		} else {
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

	}

	return C.int(numOfBitsSet) //Todo err to errno?
}

//export SCIONgosendmsg
func SCIONgosendmsg(_fd C.int, message C.msghdrConstPtr, flags C.int, _remoteAddrString *C.char, _requestTxTimestamp C.int) C.ssize_t {
	fd := int(_fd)
	_, exists := fdstatus[fd]
	if !exists {
		log.Fatalf("(SCIONgosendmsg) Non-existing fdstatus[%d]\n", fd) //change this to fatal?
		return C.ssize_t(-1)                                           //TODO correct return value for sendmsg()?
	}

	if !fdstatus[fd].registerCalled {
		s := fdstatus[fd]
		var err error
		s.conn, s.localPortSCION, err = s.pds.Register(s.ctx, localAddr.IA, localAddr.Host, s.scionTimestampingMode)
		if err != nil {
			log.Printf("(SCIONgosendmsg) Failed to register client socket: %v. This can happen if the requested timestamping mode (%v) isn't supported!", err, s.scionTimestampingMode)
			return C.ssize_t(-1)
		}
		s.registerCalled = true
		fdstatus[s.Fd] = s
		log.Printf("(SCIONgosendmsg)--> Called Register() localAddr.IA=%v, localAddr.Host=%v s.scionTimestampingMode=%v", localAddr.IA, localAddr.Host, s.scionTimestampingMode)

	}

	if !fdstatus[fd].rcvLogicStarted {
		log.Printf("(SCIONgosendmsg) Starting Rcv-Go-Routine !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
		s := fdstatus[fd]
		s.rcvLogicStarted = true
		idRoutineRead++
		if s.idRoutineRead != 0 {
			log.Fatalf("(SCIONgosendmsg) There is already a rcvLogic() running fdstatus[%d] idRoutineRead=%v\n", fd, idRoutineRead)
		}
		s.idRoutineRead = idRoutineRead
		fdstatus[fd] = s
		go s.rcvLogic()
	}

	s := fdstatus[fd]

	msg := *(*syscall.Msghdr)(unsafe.Pointer(message))

	var remoteAddrString string
	if s.isNTPServer {
		remoteAddrString = C.GoString(_remoteAddrString)
	}

	var requestTxTimestamp bool
	requestTxTimestamp = int(_requestTxTimestamp) > 0

	go s.sendmsgOverScion(msg.Iov, remoteAddrString, requestTxTimestamp)

	//if the call is blocking, this channel will get the value after msg has been sent
	bytesSent := <-s.sent
	return C.ssize_t(bytesSent)

}

func (s *FDSTATUS) sendmsgOverScion(iovec *syscall.Iovec, remoteAddrString string, requestTxTimestamp bool) {
	log.Printf("(sendmsgOverScion fd=%v) Started", s.Fd)

	/* // serach for 4242666 in this document
	//we could add this to the packet and forward it to the client
	tsMode := addr.SvcNone
	if requestTxTimestamp {
		log.Printf("(sendmsgOverScion fd=%v) |----> We have to activate Tx-Timestamps for this packet\n", s.Fd)
		switch s.scionTimestampingMode {
		case addr.RxKernel:
			tsMode = addr.TxKernelRxKernel
		case addr.RxKernelHw:
			tsMode = addr.TxKernelHwRxKernelHw
			//If we already have a Tx we do not change it.
		case addr.TxKernelRxKernel:
			tsMode = addr.TxKernelRxKernel
		case addr.TxKernelHwRxKernelHw:
			tsMode = addr.TxKernelHwRxKernelHw
		}
	}
	*/

	nonblocking := int(s.Sinfo._type&C.SOCK_NONBLOCK) == C.SOCK_NONBLOCK

	var err error
	var remoteAddr *snet.UDPAddr
	if s.connected {
		remoteAddr = s.rAddr
	} else if s.isNTPServer {
		//= make(map[string](*snet.UDPAddr))
		//remoteAddrString := "fake me"
		var exists bool
		cMap, exists := clientMapping[remoteAddrString]
		//remoteAddr, exists = clientMapping[remoteAddrString]
		if !exists {
			log.Printf("(SCIONgosendmsg) Non-existing entry clientMapping[%v]", remoteAddrString)
			s.sent <- int(-1)
			return
		}
		remoteAddr = cMap.Addr
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

	payload := C.GoBytes(unsafe.Pointer(iovecBase), C.int(iovecLen))

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

	err = s.conn.WriteTo(pkt, remoteAddr.NextHop)
	if err != nil {
		log.Printf("(sendmsgOverScion) [fd=%d] Failed to write packet: %v\n", s.Fd, err)
		s.sent <- int(-1)
		return
	}

	//if there is a blocking call, it will return now the number of sent bytes
	//Why we use a channel instead of just returning int(iovecLen): In the initial design there where more tasks after the WriteTo call
	//still possible... probably we will send the messages out with a separate socket and receive some Tx timestamps
	if !nonblocking {
		s.sent <- int(iovecLen)
	}

	log.Printf("(sendmsgOverScion) \t----->Done")
}

// SCIONgorecvmmsg collects the received messages and returns them.... but ist not the one actively receiving the stuff
//export SCIONgorecvmmsg
func SCIONgorecvmmsg(_fd C.int, vmessages C.mmsghdrPtr, vlen C.uint, flags C.int, tmo C.timespecPtr) C.int {
	fd := int(_fd)
	s, exists := fdstatus[fd]
	if !exists {
		log.Fatalf("(SCIONgorecvmmsg) Non-existing fdstatus[%d]\n", fd)
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
	//PORT IP,... .
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
			//log.Printf("%v", bufferPtrDelete)
			for i := 0; i < 256 && i < msgContrLen; i++ { //Quasi memset einfach ohne C-call (Prüfe was schneller ist)
				bufferPtrDelete[i] = 0x00
			}
			//log.Printf("%v", bufferPtrDelete)

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
			//bufferPtr[offsetNTP+ihl+2] = 0   //shoud be [22]
			//bufferPtr[offsetNTP+ihl+3] = 123 //shoud be [23]
			*(*C.uint16_t)(unsafe.Pointer(&bufferPtr[offsetNTP+ihl+2])) = C.htons(C.uint16_t(pld.DstPort))

			offsetNTP += ihl + 8 //should be 42
			pktLen += ihl + 8    //should be 90

			//copy ntp packet :-( Quasi memset einfach ohne C-call (Pürfe was schneller ist)
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
			//====> nein verwirft dann beide TS wenn HW "ungültig ist" => aktuell ist nur immer ts3[0] oder ts3[2] gesetzt
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

			(*C.struct_in_pktinfo)(unsafe.Pointer(cmsgDataPtr)).ipi_ifindex = C.int(sendMsgTS.Ipi.Ifindex) //s.Sinfo.if_index
			//TODO use NEW stuff directly
			(*C.struct_in_pktinfo)(unsafe.Pointer(cmsgDataPtr)).ipi_spec_dst.s_addr = srcIP //NEU: sendMsgTS.Ipi.Spec_dst
			(*C.struct_in_pktinfo)(unsafe.Pointer(cmsgDataPtr)).ipi_addr.s_addr = dstIP     //NEU: sendMsgTS.Ipi.Addr

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

			//Buffer löschen????
			var msgContrLen int
			msgContrLen = int(msghdr.msg_controllen)
			log.Printf("(SCIONgorecvmmsg) ----> msghdr.msg_control=%v msghdr.msg_controllen=%v msgContrLen=%v", msghdr.msg_control, msghdr.msg_controllen, msgContrLen)

			//chang this: What we need is msgContrLen. Reason: cmsgNextHdr fails if memory is not nulled
			var bufferPtrDelete *([256]C.char)
			bufferPtrDelete = (*([256]C.char))(msghdr.msg_control)
			//log.Printf("%v", bufferPtrDelete)
			for i := 0; i < 256 && i < msgContrLen; i++ { //Quasi memset einfach ohne C-call (Prüfe was schneller ist)
				bufferPtrDelete[i] = 0x00
			}
			//log.Printf("%v", bufferPtrDelete)

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

				clientMap := ClientMapping{Addr: remoteAddr, TimeAdded: time.Now()}
				clientMapping[remoteAddr.Host.String()] = clientMap

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
			(*C.struct_scm_ts_pktinfo)(unsafe.Pointer(cmsgDataPtr)).if_index = C.uint(rcvMsgNTPTS.InterfaceID)   //C.uint(s.Sinfo.if_index)
			(*C.struct_scm_ts_pktinfo)(unsafe.Pointer(cmsgDataPtr)).pkt_length = C.uint(rcvMsgNTPTS.PktLengthL2) //C.uint(pktLengtLayer2)

			// Add SO_TIMESTAMPING
			cmsg = cmsgNextHdr(msghdr, cmsg) //gib NULL zurück ohne delete (same problem: without deleting the memory the cmsg will calculate wrong bounds and retunr NULL)
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
			(*C.struct_in_pktinfo)(unsafe.Pointer(cmsgDataPtr)).ipi_ifindex = C.int(rcvMsgNTPTS.Ipi.Ifindex) //s.Sinfo.if_index
			//should this always be the same for ipi_spec_dst and ipi_addr: Probably!
			//TODO use NEW stuff directly
			(*C.struct_in_pktinfo)(unsafe.Pointer(cmsgDataPtr)).ipi_spec_dst.s_addr = dstIP //NEU: rcvMsgNTPTS.Ipi.Spec_dst
			(*C.struct_in_pktinfo)(unsafe.Pointer(cmsgDataPtr)).ipi_addr.s_addr = dstIP     //NEU: rcvMsgNTPTS.Ipi.Addr

			msghdr.msg_controllen = msgControllen

			updatedElemmsgvec++
		}

		return C.int(updatedElemmsgvec)
	}

	log.Printf("(SCIONgorecvmmsg) ----> Unimplemented/unknown case... returning no messages!!!!!!")
	return C.int(updatedElemmsgvec)
}

/* eigentlich nur ein "cast" */
//func copyCstructMSGHDR(message C.msghdrConstPtr) (msg syscall.Msghdr) {

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
/*
	msg = *(*syscall.Msghdr)(unsafe.Pointer(message))
	//s, _ := json.MarshalIndent(msg, "", "\t")
	//fmt.Println(string(s))

	return msg

}
*/

/* eigentlich nur ein "cast" */
/*
func copyCstructNTP(iovec *syscall.Iovec) (ntp NTP_Packet) {
	ntp = *(*NTP_Packet)(unsafe.Pointer(iovec.Base))
	return ntp
}
*/

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
func GetFreeFD() int {
	for fd := 1; fd <= maxFD; fd++ {
		if fdList[fd] == 0 {
			fdList[fd] = 1
			return fd
		}

	}
	return -1
}
*/

/*
func DeleteFD(fd int) {
	fdList[fd] = 0
}
*/
