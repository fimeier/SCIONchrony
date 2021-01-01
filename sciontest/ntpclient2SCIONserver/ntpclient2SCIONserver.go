package main

// #include "../../ntp.h"
import "C"

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"unsafe"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/daemon"
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

func runServer(ctx context.Context, sciondAddr string, localAddr snet.UDPAddr, scionChrony snet.UDPAddr) {
	var err error

	/*

		SCION STUFF

	*/
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sdc, err := daemon.NewService(sciondAddr).Connect(ctx)
	if err != nil {
		log.Fatal("(SCIONgoconnect) Failed to create SCION connector:", err)
	}
	pds := &snet.DefaultPacketDispatcherService{
		Dispatcher: reconnect.NewDispatcherService(reliable.NewDispatcher("")),
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: daemon.RevHandler{Connector: sdc},
		},
	}

	ps, err := sdc.Paths(ctx, scionChrony.IA, localAddr.IA, daemon.PathReqFlags{Refresh: true})
	if err != nil {
		log.Fatal("ailed to lookup core paths: %v:", err)
	}

	log.Printf("(SCIONgoconnect) Available paths to %v:\n", scionChrony.IA)
	for _, p := range ps {
		log.Printf("\t%v\n", p)
	}

	selectedPath := ps[0]
	log.Printf("(SCIONgoconnect)  Selected path to %v: %v\n", scionChrony.IA, selectedPath)

	scionChrony.Path = selectedPath.Path()
	scionChrony.NextHop = selectedPath.UnderlayNextHop()

	conn, localPortSCION, err := pds.Register(ctx, localAddr.IA, localAddr.Host, addr.SvcNone)
	if err != nil {
		log.Fatal("(SCIONgoconnect)  Failed to register client socket:", err)
	}

	/*

		UDP stuff

	*/
	locAddrUDP, err := net.ResolveUDPAddr("udp", "10.80.45.83:123")
	connUDP, err := net.ListenUDP("udp", locAddrUDP)
	if err != nil {
		log.Fatal(err)
	}
	defer connUDP.Close()

	log.Printf("connUDP.Addr().String()=%v", connUDP.LocalAddr())

	log.Printf("Listening in %v on %v:%d - %v\nand on 10.80.45.83:123 for incomming udp packets", localAddr.IA, localAddr.Host.IP, localPortSCION, addr.SvcNone)

	for {

		log.Printf("////////////////////////////////////////////////////// Step 1: receive ntp packet as common UDP packet")
		var buf [512]byte
		n, udpCLientAddr, err := connUDP.ReadFromUDP(buf[0:])
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("\t----> n=%v bytes received using common udp connection\n", n)

		log.Printf("////////////////////////////////////////////////////// Step 2: forward received ntp packet to chrony over SCION")

		pkt := &snet.Packet{
			PacketInfo: snet.PacketInfo{
				Source: snet.SCIONAddress{
					IA:   localAddr.IA,
					Host: addr.HostFromIP(localAddr.Host.IP), //addr.HostFromIP(udpCLientAddr.IP), //forward the "IP": nop
				},
				Destination: snet.SCIONAddress{
					IA:   scionChrony.IA,
					Host: addr.HostFromIP(scionChrony.Host.IP),
				},
				Path: scionChrony.Path,
				Payload: snet.UDPPayload{
					SrcPort: localPortSCION, //uint16(udpCLientAddr.Port), //forward the PORT: nop geht nicht...
					DstPort: uint16(scionChrony.Host.Port),
					Payload: buf[0:n],
				},
			},
		}

		log.Printf("\t----> Forwarding UDP Message over SCION to Chrony-Scion")

		err = conn.WriteTo(pkt, scionChrony.NextHop)
		if err != nil {
			log.Printf("\t---->[%d] Failed to write packet: %v\n", err)
		}

		log.Printf("////////////////////////////////////////////////////// Step 3: receive response from chronyScion")
		var pktResponse snet.Packet
		var ovResponse net.UDPAddr
		err = conn.ReadFrom(&pktResponse, &ovResponse)
		if err != nil {
			log.Printf("\t---->Failed to read packet: %v\n", err)
			continue
		}
		pld, ok := pktResponse.Payload.(snet.UDPPayload)
		if !ok {
			log.Printf("\t---->Failed to read packet payload\n")
			continue
		}

		payload := pld.Payload
		fmt.Printf("\t----> Received payload from Chrony-Scion: \"%v\"\n", payload)

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
		fmt.Printf("\t ----> Printing the ntp before forwarding it = %v\n", ntp)
		C.free(ntpHeap)

		log.Printf("////////////////////////////////////////////////////// Step 4: forward ntp packet as common UDP packet to ntp server")
		n, err = connUDP.WriteToUDP(payload, udpCLientAddr)
		fmt.Printf("\t---->n =%v bytes sent using common udp connection\n", n)

	}
}

func main() {
	var sciondAddr string
	var localAddr snet.UDPAddr
	var scionChrony snet.UDPAddr
	flag.StringVar(&sciondAddr, "sciond", "", "SCIOND address")
	flag.Var(&localAddr, "local", "Local address")
	flag.Var(&scionChrony, "scionChrony", "The Scion Address of the NTP Chronyd")

	flag.Parse()

	fmt.Printf("sciond=%v\n", sciondAddr)
	fmt.Printf("local=%v\n", localAddr)
	fmt.Printf("scionChrony=%v\n", scionChrony)

	runServer(context.Background(), sciondAddr, localAddr, scionChrony)
}
