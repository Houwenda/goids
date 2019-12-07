package analyzer

import (
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"log"
	"os"
	"time"
)

var (
	AlarmChannel       chan Incident
	groupPacketChannel []chan *gopacket.Packet
	rulesPerGroup      int
)

type Incident struct {
	Time        time.Time
	Description string
	Detail      struct {
		Type   string
		Rule   PktRule // TODO: create a Rule struct compatible with pktRule and streamRule
		Packet gopacket.Packet
	}
}

/******************************************************
*
* Strict Mode :
* Analyze gives different rules to different groups.
* Analyze gives each group a channel, through which
* it emits the pointer of the packet to each group
* when Analyze receives a packet from Watcher.
* There are several Workers in each group, they try
* to get this packet continuously.
*
* Concurrent Mode :
* Start a new group of goroutines when Analyze
* receives a packet from Watcher
*
******************************************************/
func Analyze(strict bool,
	groupNum int32,
	workerNum int32,
	packetChannel <-chan gopacket.Packet,
	alarmChannel chan Incident,
	pktRulesList []PktRule,
	streamRuleList []StreamRule) {

	//fmt.Println("analyze starts")

	// TODO: stream analyzer

	AlarmChannel = alarmChannel
	rulesPerGroup = len(pktRulesList) / int(groupNum)

	// packet analyzer
	// strict mode
	if strict {
		fmt.Println("analyzer works in strict mode")
		log.Println("analyzer works in strict mode")
		// spawn workers
		StrictAnalyze(groupNum, workerNum, pktRulesList)
		//fmt.Println("groupPacketChannel : ", groupPacketChannel)

		// start emitting packets to each group
		for pkt := range packetChannel {
			tmpPkt := pkt
			for _, pktChannel := range groupPacketChannel {
				pktChannel <- &tmpPkt
			}
		}
	} else { // concurrent mode
		fmt.Println("analyzer works in concurrent mode")
		log.Println("analyzer works in concurrent mode")
		//ConcurrentAnalyze(groupNum, pktRulesList)
		for pkt := range packetChannel {
			//for _, ch := range groupPacketChannel {
			//	ch <- &pkt
			//}
			//for i := 0; i < int(groupNum); i++ {
			//	go PacketAnalyzeWorker(groupPacketChannel[i], pktRulesList[i*rulesPerGroup:i*rulesPerGroup+rulesPerGroup])
			//}
			tmpPkt := pkt
			for i := 0; i < int(groupNum); i++ {
				//fmt.Printf("pkt sent to group %d \n", i)
				go PacketAnalyzeProc(&tmpPkt, pktRulesList[i*rulesPerGroup:i*rulesPerGroup+rulesPerGroup])
			}
		}
	}
}

func StrictAnalyze(groupNum int32, workerNum int32, pktRulesList []PktRule) {
	for i := 0; i < int(groupNum); i++ {
		pktChannel := make(chan *gopacket.Packet)
		groupPacketChannel = append(groupPacketChannel, pktChannel)
		for j := 0; j < int(workerNum); j++ {
			go PacketAnalyzeWorker(pktChannel, pktRulesList[i*rulesPerGroup:i*rulesPerGroup+rulesPerGroup])
		}
		log.Printf("PacketAnalyzerGroup %d \n", i)
	}
}

func ConcurrentAnalyze(groupNum int32, pktRuleList []PktRule) {
	for i := 0; i < int(groupNum); i++ {
		pktChannel := make(chan *gopacket.Packet)
		groupPacketChannel = append(groupPacketChannel, pktChannel)
	}
}

func PacketAnalyzeWorker(pktChannel chan *gopacket.Packet, pktRulesList []PktRule) {
	log.Println("PacketAnalyzeWorker starts")
	fmt.Println("PacketAnalyzeWorker starts", time.Now().Format(time.RFC3339Nano))
	for {
		packet := <-pktChannel
		PacketAnalyzeProc(packet, pktRulesList)
		os.Stdout.Sync()
	}
}

func PacketAnalyzeProc(pkt *gopacket.Packet, pktRuleList []PktRule) {
	//fmt.Println(*pkt)
	packet := *pkt
	if err := packet.ErrorLayer(); err != nil {
		log.Println("Error decoding some part of the packet:", err)
	}
	/*
		if netw := packet.NetworkLayer(); netw != nil {
			if netw.LayerType() == layers.LayerTypeIPv4 {
				ipv4 := netw.(*layers.IPv4)
				fmt.Println("IPv4 : from", ipv4.SrcIP, " to", ipv4.DstIP)
			} else if netw.LayerType() == layers.LayerTypeIPv6 {
				ipv6 := netw.(*layers.IPv6)
				fmt.Println("IPv6 : from", ipv6.SrcIP, " to", ipv6.DstIP)
			}
		}
		if trans := packet.TransportLayer(); trans != nil {
			if trans.LayerType() == layers.LayerTypeTCP {
				fmt.Println("TCP", len(trans.(*layers.TCP).Payload), ": \n", hex.Dump(trans.(*layers.TCP).Payload))
			} else if trans.LayerType() == layers.LayerTypeUDP {
				fmt.Println("UDP : \n", hex.Dump(trans.(*layers.UDP).Payload))
			}
		}
		if app := packet.ApplicationLayer(); app != nil {
			//log.Println(hex.Dump(app.Payload()))
		}
	*/
	for _, tmpLayer := range packet.Layers() {
		switch tmpLayer.LayerType() {
		case layers.LayerTypeIPv4:
			ipv4 := tmpLayer.(*layers.IPv4)
			fmt.Println("IPv4 : from", ipv4.SrcIP, " to", ipv4.DstIP)
		case layers.LayerTypeIPv6:
			ipv6 := tmpLayer.(*layers.IPv6)
			fmt.Println("IPv6 : from", ipv6.SrcIP, " to", ipv6.DstIP)
		case layers.LayerTypeICMPv4:
			icmpv4 := tmpLayer.(*layers.ICMPv4)
			fmt.Println("ICMPv4 : ", hex.Dump(icmpv4.Payload))
		case layers.LayerTypeICMPv6:
			icmpv6 := tmpLayer.(*layers.ICMPv6)
			fmt.Println("ICMPv6 : ", hex.Dump(icmpv6.Payload))
		case layers.LayerTypeTCP:
			tcp := tmpLayer.(*layers.TCP)
			fmt.Println("TCP : from ", tcp.SrcPort, " to", tcp.DstPort, hex.Dump(tcp.Payload))
		case layers.LayerTypeUDP:
			udp := tmpLayer.(*layers.UDP)
			fmt.Println("TCP : from ", udp.SrcPort, " to", udp.DstPort, hex.Dump(udp.Payload))
		case layers.LayerTypeEthernet:
			ethernet := tmpLayer.(*layers.Ethernet)
			fmt.Println("Ethernet : from ", ethernet.SrcMAC, " to", ethernet.DstMAC)
		default:
			fmt.Println("other layer : ", tmpLayer.LayerType())
		}

	}
	fmt.Println()
}
