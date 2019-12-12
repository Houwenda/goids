package analyzer

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
	"time"
)

var (
	snaplen int32         = 1024
	promisc bool          = false
	timeout time.Duration = -1 * time.Second
)

func Watch(interfaces []string, packetChannel chan<- gopacket.Packet) {
	fmt.Println("capturing packets starts")

	for _, device := range interfaces {
		handle, err := pcap.OpenLive(device, snaplen, promisc, timeout)
		if err != nil {
			log.Println("Unable to access device : " + device)
			log.Println(err.Error())
			fmt.Println("Unable to access device : " + device)
			panic("Unable to access device : " + device)
		}
		log.Println("start capturing packets from " + device)
		go Capture(handle, packetChannel)
	}

	// test
	time.Sleep(10 * time.Second)
}

func Capture(handle *pcap.Handle, packetChannel chan<- gopacket.Packet) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		//fmt.Println("into packetChannel : ", packet)
		packetChannel <- packet
	}
}
