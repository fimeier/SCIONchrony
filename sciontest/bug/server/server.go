package main

import "C"
import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/sock/reliable/reconnect"
)

func runServerUDP(bindAddr snet.UDPAddr) {

	fmt.Println("udp bind addr=", bindAddr.Host.String())

	locAddrUDP, err := net.ResolveUDPAddr("udp", bindAddr.Host.String())
	connUDP, err := net.ListenUDP("udp", locAddrUDP)
	if err != nil {
		log.Fatal(err)
	}
	defer connUDP.Close()

	nMessagesReceived := 0
	var buf [512]byte
	for {

		fmt.Println("call connUDP()")
		deadline := time.Now().Add(time.Second) //time.Time{}
		connUDP.SetReadDeadline(deadline)
		n, _, err := connUDP.ReadFromUDP(buf[0:])
		fmt.Println("returned from connUDP()")
		if err != nil {
			log.Printf("----> Failed to read packet: %v", err)

			sleep := 1000 * time.Millisecond
			log.Printf("----> sleeping %v nMessagesReceived=%v", sleep, nMessagesReceived)
			time.Sleep(sleep)

			continue
		}
		fmt.Printf("\t----> n=%v bytes received. msg = %s\n", n, buf)
		nMessagesReceived++
	}
}

func runServer(sciondAddr string, bindAddr snet.UDPAddr) {
	var err error

	fmt.Println("sciondAddr = %v", sciondAddr)
	fmt.Println("localAddr = %v", bindAddr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // ?-D

	sdc, err := daemon.NewService(sciondAddr).Connect(ctx)
	if err != nil {
		log.Printf("(SCIONgobind) Failed to create SCION connector:", err)
		return
	}
	pds := &snet.DefaultPacketDispatcherService{
		Dispatcher: reconnect.NewDispatcherService(reliable.NewDispatcher("")),
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: daemon.RevHandler{Connector: sdc},
		},
	}

	conn, localPortSCION, err := pds.Register(ctx, bindAddr.IA, bindAddr.Host, addr.SvcNone)
	if err != nil {
		log.Printf("(SCIONgobind)  Failed to register client socket:", err)
		return
	}

	fmt.Println("localPortSCION", localPortSCION)

	var nMessagesReceived int
	for {

		var pkt snet.Packet
		var ov net.UDPAddr

		deadline := time.Now().Add(3000 * time.Millisecond) //time.Time{} //t
		conn.SetReadDeadline(deadline)

		fmt.Printf("call ReadFrom(:%v) nMessagesReceived=%v(until now)\n", localPortSCION, nMessagesReceived)
		err := conn.ReadFrom(&pkt, &ov)
		//fmt.Println("returned from ReadFrom()")
		if err != nil {
			/*log.Printf("----> Failed to read packet: %v", err)

			sleep := 3000 * time.Millisecond
			log.Printf("----> sleeping %v nMessagesReceived=%v", sleep, nMessagesReceived)
			time.Sleep(sleep)
			*/
			continue
		}
		nMessagesReceived++
		payload, ok := pkt.Payload.(snet.UDPPayload)
		if !ok {
			continue //return //continue
		}

		fmt.Printf("rcv msg: %v", string(payload.Payload))

	}

}

//go run server.go -sciond=127.0.0.1:30255 -localAddr=1-ff00:0:112,10.80.45.83:12345

func main() {
	var sciondAddr string
	var localAddr snet.UDPAddr
	flag.StringVar(&sciondAddr, "sciond", "", "SCIOND address")
	flag.Var(&localAddr, "localAddr", "Local address")

	doSCION := flag.Bool("doSCION", false, "doSCION?")

	flag.Parse()

	if *doSCION {
		runServer(sciondAddr, localAddr)
	} else {
		runServerUDP(localAddr)
	}
}

/*
go build -buildmode=c-shared -o call_me_api.so *.go
*/
//export CallMe
func CallMe() {
	fmt.Println("WIll now call the SCION Server process")

	localAddr1, _ := snet.ParseUDPAddr("1-ff00:0:112,10.80.45.83:12345")
	fmt.Println("WIll now call the SCION Server process i.e. a go-Routine")
	go runServer("127.0.0.1:30255", *localAddr1)

	localAddr2, _ := snet.ParseUDPAddr("1-ff00:0:112,10.80.45.83:54321")
	fmt.Println("WIll now call the SCION Server process i.e. a go-Routine")
	go runServer("127.0.0.1:30255", *localAddr2)

}
