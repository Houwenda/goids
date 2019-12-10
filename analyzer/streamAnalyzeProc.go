package analyzer

import (
	"fmt"
	"github.com/google/gopacket"
	"log"
	"time"
)

func StreamAnalyzeProc(streamPacketChannel chan *gopacket.Packet, streamRules []StreamRule) {

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
