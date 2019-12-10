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
	AlarmChannel        chan Incident
	groupPacketChannel  []chan *gopacket.Packet
	rulesPerGroup       int
	StreamPacketChannel chan *gopacket.Packet // packet analyzer send packets to stream analyzer
	PacketRuleChannel   chan *PktRule         // packet analyzer sends packet rules to stream analyzer
	PacketRulesList     []PktRule
)

type Incident struct {
	Time        time.Time
	Description string
	Detail      struct {
		Rule    PktRule
		Packets []gopacket.Packet
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
	streamRulesList []StreamRule) {

	//fmt.Println("analyze starts")

	PacketRulesList = pktRulesList

	// stream analyzer
	StreamPacketChannel = make(chan *gopacket.Packet, 100)
	PacketRuleChannel = make(chan *PktRule, 100)
	go StreamAnalyze(StreamPacketChannel, streamRulesList)

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
	log.Println("PacketAnalyzeWorker starts", time.Now().Format(time.RFC3339Nano))
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

func StreamAnalyze(streamPacketChannel chan *gopacket.Packet, streamRules []StreamRule) {

	type pktTime struct {
		packet gopacket.Packet
		time   time.Time
	}

	pktTimeStackDict := make(map[int32][]pktTime)
	// add list to dict
	for _, streamRule := range streamRules {
		pktTimeStackDict[streamRule.Sid] = make([]pktTime, 0)
	}
	//fmt.Println(pktTimeStackDict)

	// check PktRulesList
	// if PktRulesList has stream action rules that
	// are not defined in streamRulesList
	sidList := make([]int32, 0)
	for key, _ := range pktTimeStackDict {
		sidList = append(sidList, key)
	}
	fmt.Println("sidList :", sidList)

	for _, pktRule := range PacketRulesList {
		if pktRule.Action == "stream" {
			isMatch := false
			for _, sid := range sidList {
				if int32(sid) == pktRule.SignatureId.Sid {
					isMatch = true
					break
				}
			}
			if !isMatch {
				fmt.Println("stream action packet rule's sid not found in stream rules")
				log.Fatal("stream action packet rule's sid not found in stream rules")
			}
		}
	}

	// getting packets from pktAnalyzeWorker
	for {
		var pkt *gopacket.Packet
		var pktRule *PktRule
		pkt = <-streamPacketChannel
		tmpPkt := *pkt
		pktRule = <-PacketRuleChannel
		tmpPktRule := *pktRule

		sid := tmpPktRule.SignatureId.Sid
		var tmpPktTime pktTime
		tmpPktTime.packet = tmpPkt
		tmpPktTime.time = time.Now()

		// get current streamRule
		var streamRule StreamRule
		for _, tmpStreamRule := range streamRules {
			if tmpStreamRule.Sid == tmpPktRule.SignatureId.Sid {
				streamRule = tmpStreamRule
			}
		}

		// get packets in given interval
		var tmpPktTimeStack []pktTime
		for _, pktTime := range pktTimeStackDict[sid] {
			switch streamRule.Frequency.interval {
			case "hour":
				if pktTime.time.Add(time.Hour).After(time.Now()) {
					tmpPktTimeStack = append(tmpPktTimeStack, pktTime)
				}
			case "minute":
				if pktTime.time.Add(time.Minute).After(time.Now()) {
					tmpPktTimeStack = append(tmpPktTimeStack, pktTime)
				}
			case "second":
				if pktTime.time.Add(time.Second).After(time.Now()) {
					tmpPktTimeStack = append(tmpPktTimeStack, pktTime)
				}
			}
		}
		tmpPktTimeStack = append(tmpPktTimeStack, tmpPktTime)

		// check number of pktTime in stack
		if len(tmpPktTimeStack) > int(streamRule.Frequency.value) {
			var incident Incident
			incident.Time = tmpPktTime.time
			incident.Description = tmpPktRule.Message
			incident.Detail.Packets = make([]gopacket.Packet, 0)
			for _, pktTime := range tmpPktTimeStack {
				incident.Detail.Packets = append(incident.Detail.Packets, pktTime.packet)
			}
			incident.Detail.Rule = tmpPktRule

			// send incident to alarmer
			AlarmChannel <- incident

			// clear stack
			pktTimeStackDict[sid] = make([]pktTime, 0)
		} else {
			// remove outdated pktTime from stack
			pktTimeStackDict[sid] = tmpPktTimeStack
		}
	}
}
