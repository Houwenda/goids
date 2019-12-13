package analyzer

import (
	"fmt"
	"github.com/google/gopacket"
	"log"
	"os"
	"time"
)

var (
	AlarmChannel        chan Incident
	groupPacketChannel  []chan *gopacket.Packet
	rulesPerGroup       int
	StreamPacketChannel chan gopacket.Packet // packet analyzer send packets to stream analyzer
	PacketRuleChannel   chan PktRule         // packet analyzer sends packet rules to stream analyzer
	PacketRulesList     []PktRule
)

type Incident struct {
	Action      string
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
	StreamPacketChannel = make(chan gopacket.Packet, 100)
	PacketRuleChannel = make(chan PktRule, 100)
	go StreamAnalyzeProc(StreamPacketChannel, streamRulesList)

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
			tmpPkt := new(gopacket.Packet)
			*tmpPkt = pkt
			for _, pktChannel := range groupPacketChannel {
				pktChannel <- tmpPkt
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
			tmpPkt := new(gopacket.Packet)
			*tmpPkt = pkt
			for i := 0; i < int(groupNum); i++ {
				//fmt.Printf("pkt sent to group %d \n", i)
				go PacketAnalyzeProc(tmpPkt, pktRulesList[i*rulesPerGroup:i*rulesPerGroup+rulesPerGroup])
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
