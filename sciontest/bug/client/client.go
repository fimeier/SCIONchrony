package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/sock/reliable/reconnect"
)

func runServerUDP(remoteAddr snet.UDPAddr) {

	fmt.Println("udp connecting addr=%v", remoteAddr.Host.String())
	remAddrUDP, err := net.ResolveUDPAddr("udp", remoteAddr.Host.String())
	connUDP, err := net.DialUDP("udp", nil, remAddrUDP)
	if err != nil {
		log.Fatal(err)
	}
	defer connUDP.Close()

	nMessages := 1
	for nMessages <= 10 {

		sendMe := []byte("Hallo this is a message " + strconv.Itoa(nMessages))
		fmt.Println("sending msg: ", string(sendMe))

		_, err := connUDP.Write(sendMe)
		if err != nil {
			log.Printf("Failed to create SCION connector:", err)
			return
		}
		nMessages++

	}
}

func runServer(sciondAddr string, localAddr snet.UDPAddr, remoteAddr snet.UDPAddr) {
	var err error

	fmt.Println("sciondAddr = %v", sciondAddr)
	fmt.Println("localAddr = %v", localAddr)
	fmt.Println("remoteAddr = %v", remoteAddr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // ?-D

	sdc, err := daemon.NewService(sciondAddr).Connect(ctx)
	if err != nil {
		log.Printf("Failed to create SCION connector:", err)
		return
	}
	pds := &snet.DefaultPacketDispatcherService{
		Dispatcher: reconnect.NewDispatcherService(reliable.NewDispatcher("")),
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: daemon.RevHandler{Connector: sdc},
		},
	}

	ps, err := sdc.Paths(ctx, remoteAddr.IA, localAddr.IA, daemon.PathReqFlags{Refresh: true})
	if err != nil {
		log.Printf("Failed to lookup core paths: %v:", err)
		return
	}

	log.Printf("Available paths to %v:\n", remoteAddr.IA)
	for _, p := range ps {
		log.Printf("\t%v\n", p)
	}

	selectedPath := ps[0]
	log.Printf(" Selected path to %v: %v\n", remoteAddr.IA, selectedPath)

	remoteAddr.Path = selectedPath.Path()
	remoteAddr.NextHop = selectedPath.UnderlayNextHop()

	conn, localPortSCION, err := pds.Register(ctx, localAddr.IA, localAddr.Host, addr.SvcNone)
	if err != nil {
		log.Printf("(SCIONgoconnect)  Failed to register client socket:", err)
		return
	}

	fmt.Println("localPortSCION=%v", localPortSCION)

	var nMessagesReceived int
	for nMessagesReceived < 10 {

		sendMe := "Hallo this is a message " + strconv.Itoa(nMessagesReceived)

		payload := []byte(sendMe)

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
					SrcPort: localPortSCION,
					DstPort: uint16(remoteAddr.Host.Port),
					Payload: payload,
				},
			},
		}

		fmt.Println("Sending message: ", string(payload))

		err = conn.WriteTo(pkt, remoteAddr.NextHop)
		if err != nil {
			fmt.Println("Failed to write packet: %v\n", err)
			return
		}
		nMessagesReceived++
	}

}

//go run client.go -sciond=127.0.0.12:30255 -localAddr=1-ff00:0:110,10.80.45.83 -remoteAddr=1-ff00:0:112,10.80.45.83:12345

func main() {
	var sciondAddr string
	flag.StringVar(&sciondAddr, "sciond", "", "SCIOND address")

	var localAddr snet.UDPAddr
	flag.Var(&localAddr, "localAddr", "Local address")

	var remoteAddr snet.UDPAddr
	flag.Var(&remoteAddr, "remoteAddr", "remote address")

	doSCION := flag.Bool("doSCION", false, "doSCION?")

	flag.Parse()

	if *doSCION {
		runServer(sciondAddr, localAddr, remoteAddr)
	} else {
		runServerUDP(remoteAddr)
	}
}
