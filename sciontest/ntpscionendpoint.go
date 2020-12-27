package main

// #include "../ntp.h"
import "C"

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"unsafe"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/sock/reliable/reconnect"
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

type ntpHandler struct {
	fdUnix uint16
}

func (h ntpHandler) Handle(pkt *snet.Packet) error {

	fmt.Println("ntpHandler called :-D")

	return nil
}

func runServer(sciondAddr string, localAddr snet.UDPAddr) {
	var err error
	ctx := context.Background()

	fmt.Printf("sciondAddr = %v", sciondAddr)
	fmt.Printf("localAddr = %v", localAddr)

	//var service sciond.Service
	//service.Address = sciondAddr

	//sdc, err := service.Connect(ctx)

	pds := &snet.DefaultPacketDispatcherService{
		Dispatcher: reconnect.NewDispatcherService(reliable.NewDispatcher("")),
		SCMPHandler: ntpHandler{ //wird nur aufgerufen wenn scmp erhalten wird
			fdUnix: 42,
		},
	}

	conn, localPort, err := pds.Register(ctx, localAddr.IA, localAddr.Host, addr.SvcNone)
	if err != nil {
		log.Fatal("Failed to register server socket:", err)
	}

	log.Printf("Listening in %v on %v:%d - %v\n", localAddr.IA, localAddr.Host.IP, localPort, addr.SvcNone)

	for {
		log.Printf("////////////////////////////////////////////////////// Step 1: receive ntp packet from chronyScion")
		var pkt snet.Packet
		var ov net.UDPAddr
		err := conn.ReadFrom(&pkt, &ov)
		if err != nil {
			log.Printf("\t---->Failed to read packet: %v\n", err)
			continue
		}
		pld, ok := pkt.Payload.(snet.UDPPayload)
		if !ok {
			log.Printf("\t---->Failed to read packet payload\n")
			continue
		}

		payload := pld.Payload
		fmt.Printf("\t---->Received payload: \"%v\"\n", payload)

		payloadLen := len(payload)
		ntpSize := int(unsafe.Sizeof(NTP_Packet{})) //minimum size header 48 bytes???

		//adhoc security.... improve this
		if payloadLen < ntpSize {
			fmt.Printf("\t---->payload can't be a NTP packet (%d < %d)\n", payloadLen, ntpSize)
			continue
		}

		//data leakage? jop
		// Go []byte slice to C array
		// The C array is allocated in the C heap using malloc.
		// It is the caller's responsibility to arrange for it to be
		// freed, such as by calling C.free (be sure to include stdlib.h
		// if C.free is needed).
		ntpHeap := C.CBytes(payload)
		ntp := *(*NTP_Packet)(ntpHeap)
		fmt.Printf("\t---->ntp = %v\n", ntp)
		C.free(ntpHeap)

		log.Printf("////////////////////////////////////////////////////// Step 2: forward ntp packet as common UDP packet to ntp server")
		connUDP, err := net.Dial("udp", "10.80.45.128:123")

		defer connUDP.Close()
		n, err := connUDP.Write(payload)
		fmt.Printf("\t---->n=%v bytes sent using common udp connection\n", n)

		log.Printf("////////////////////////////////////////////////////// Step 3: receive ntp packet response as common UDP packet")
		var buf [512]byte
		n, err = connUDP.Read(buf[0:])
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("\t---->n=%v bytes received using common udp connection\n", n)
		//adhoc security.... improve this
		if n < ntpSize {
			fmt.Printf("\t---->payload can't be a NTP packet (%d < %d)\n", n, ntpSize)
			continue
		}
		//data leakage? JOP
		ntpHeap = C.CBytes(buf[0:n])
		ntp = *(*NTP_Packet)(ntpHeap)
		fmt.Printf("\t---->ntp = %v\n", ntp)
		C.free(ntpHeap)

		log.Printf("////////////////////////////////////////////////////// Step 4: forward received ntp packet to chrony over SCION")

		/* get reverse path */
		reversePath := pkt.Path.Copy()
		reversePath.Reverse()
		reversePathUnderlayNextHop := &ov
		//reversePathUnderlayNextHop.Port = 666

		pktResponse := &snet.Packet{
			PacketInfo: snet.PacketInfo{
				Source: snet.SCIONAddress{
					IA:   localAddr.IA,
					Host: addr.HostFromIP(localAddr.Host.IP),
				},
				Destination: snet.SCIONAddress{
					IA:   pkt.Source.IA,
					Host: addr.HostFromIP(pkt.Source.Host.IP()),
				},
				Path: reversePath, //sp.Path(),
				Payload: snet.UDPPayload{
					SrcPort: localPort,
					DstPort: uint16(pld.SrcPort),
					Payload: buf[0:n],
				},
			},
		}

		log.Printf("\t---->Sending in %v on %v:%d - %v\n", localAddr.IA, localAddr.Host.IP, localPort, addr.SvcNone)
		log.Printf(".\t---->.......Destination:  IP:Port ist in %v on %v:%d - %v\n", pkt.Source.IA, pkt.Source.Host.IP(), pld.SrcPort, addr.SvcNone)

		err = conn.WriteTo(pktResponse, reversePathUnderlayNextHop) //sp.UnderlayNextHop())
		if err != nil {
			log.Printf("\t---->[%d] Failed to write packet: %v\n", err)
		}

	}
}

func main() {
	var sciondAddr string
	var localAddr snet.UDPAddr
	flag.StringVar(&sciondAddr, "sciond", "", "SCIOND address")
	flag.Var(&localAddr, "local", "Local address")
	flag.Parse()

	fmt.Printf("sciond=%v\n", sciondAddr)
	fmt.Printf("local=%#v\n", localAddr)

	runServer(sciondAddr, localAddr)
}
