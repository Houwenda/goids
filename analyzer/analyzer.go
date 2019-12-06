package analyzer

import (
	"fmt"
	"github.com/google/gopacket"
	"log"
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

	fmt.Println("analyze starts")

	// TODO: stream analyzer

	AlarmChannel = alarmChannel
	rulesPerGroup = len(pktRulesList) / int(groupNum)

	// packet analyzer
	// strict mode
	if strict {
		fmt.Println("Analyze works in strict mode")
		log.Println("Analyze works in strict mode")
		// spawn workers
		StrictAnalyze(groupNum, workerNum, pktRulesList)

		// start omitting packets to each group
		for pkt := range packetChannel {
			for _, pktChannel := range groupPacketChannel {
				//fmt.Printf("pkt sent to group %d \n", i)
				pktChannel <- &pkt
			}
		}
	} else { // concurrent mode
		fmt.Println("Analyze works in concurrent mode")
		log.Println("Analyze works in concurrent mode")
		//ConcurrentAnalyze(groupNum, pktRulesList)
		for pkt := range packetChannel {
			//for _, ch := range groupPacketChannel {
			//	ch <- &pkt
			//}
			//for i := 0; i < int(groupNum); i++ {
			//	go PacketAnalyzeWorker(groupPacketChannel[i], pktRulesList[i*rulesPerGroup:i*rulesPerGroup+rulesPerGroup])
			//}
			for i := 0; i < int(groupNum); i++ {
				//fmt.Printf("pkt sent to group %d \n", i)
				go PacketAnalyzeProc(&pkt, pktRulesList[i*rulesPerGroup:i*rulesPerGroup+rulesPerGroup])
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
	for {
		packet := <-pktChannel
		PacketAnalyzeProc(packet, pktRulesList)
	}
}

func PacketAnalyzeProc(pkt *gopacket.Packet, pktRuleList []PktRule) {
	//fmt.Println(*pkt)
}
