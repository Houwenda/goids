package analyzer

import (
	"github.com/google/gopacket"
	"time"
)

func Watch(interfaces []string, packetChannel chan<- gopacket.Packet) {
	time.Sleep(60 * time.Second)
}
