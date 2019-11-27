package analyzer

import (
	"fmt"
	"github.com/google/gopacket"
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
		Type string
		Rule PktRule // TODO: create a Rule struct compatible with pktRule and streamRule
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
******************************************************/
func Analyze(strict bool,
	groupNum int32,
	workerNum int32,
	packetChannel <-chan gopacket.Packet,
	alarmChannel chan Incident,
	pktRulesList []PktRule,
	streamRuleList []StreamRule) {

	// TODO: stream analyzer

	AlarmChannel = alarmChannel
	rulesPerGroup = len(pktRulesList) / int(groupNum)

	// 	packet analyzer
	// strict mode
	if strict {
		// spawn workers
		StrictAnalyze(groupNum, workerNum, pktRulesList)

		// start omitting packets to each group
		for pkt := range packetChannel {
			for _, pktChannel := range groupPacketChannel {
				pktChannel <- &pkt
			}
		}
	} else {
		// TODO: concurrent analyze mode
		ConcurrentAnalyze(groupNum, pktRulesList)
	}
}

func StrictAnalyze(groupNum int32, workerNum int32, pktRulesList []PktRule) {
	for i := 0; i < int(groupNum); i++ {
		pktChannel := make(chan *gopacket.Packet)
		groupPacketChannel = append(groupPacketChannel, pktChannel)
		for j := 0; j < int(workerNum); j++ {
			go PacketAnalyzeWorker(pktChannel, pktRulesList[i*rulesPerGroup:i*rulesPerGroup+rulesPerGroup])
		}
	}
}

func ConcurrentAnalyze(groupNum int32, pktRuleList []PktRule) {
	for i := 0; i < int(groupNum); i++ {
		pktChannel := make(chan *gopacket.Packet)
		groupPacketChannel = append(groupPacketChannel, pktChannel)
	}
}

func PacketAnalyzeWorker(pktChannel chan *gopacket.Packet, pktRulesList []PktRule) {
	for {
		packet := *<-pktChannel
		fmt.Println(packet)
	}
}
