package analyzer

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	hash2 "hash"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

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
	var packetType string // icmp tcp udp
	var srcIP net.IP      // ipv4 ipv6
	var dstIP net.IP      // ipv4 ipv6
	var srcPort int32
	var dstPort int32
	var payload []byte
	reg, err := regexp.Compile(`\d+`)
	if err != nil {
		fmt.Println(err.Error())
		log.Fatal(err.Error())
	}
	for _, tmpLayer := range packet.Layers() {
		switch tmpLayer.LayerType() {
		case layers.LayerTypeIPv4:
			ipv4 := tmpLayer.(*layers.IPv4)
			srcIP = ipv4.SrcIP
			dstIP = ipv4.DstIP
			//fmt.Println("IPv4 : from", srcIP, " to", dstIP)
		case layers.LayerTypeIPv6:
			ipv6 := tmpLayer.(*layers.IPv6)
			srcIP = ipv6.SrcIP
			dstIP = ipv6.DstIP
			//fmt.Println("IPv6 : from", srcIP, " to", dstIP)
		case layers.LayerTypeICMPv4:
			icmpv4 := tmpLayer.(*layers.ICMPv4)
			packetType = "icmp"
			payload = icmpv4.Payload
			//fmt.Println("ICMPv4 : ", hex.Dump(payload))
		case layers.LayerTypeICMPv6:
			icmpv6 := tmpLayer.(*layers.ICMPv6)
			packetType = "icmp"
			payload = icmpv6.Payload
			//fmt.Println("ICMPv6 : ", hex.Dump(payload))
		case layers.LayerTypeTCP:
			tcp := tmpLayer.(*layers.TCP)
			packetType = "tcp"
			portString := reg.FindString(tcp.SrcPort.String())
			portInt, err := strconv.ParseInt(portString, 10, 32)
			if err != nil {
				fmt.Println(err.Error())
				log.Fatal(err.Error())
			}
			srcPort = int32(portInt)
			portString = reg.FindString(tcp.DstPort.String())
			portInt, err = strconv.ParseInt(portString, 10, 32)
			if err != nil {
				fmt.Println(err.Error())
				log.Fatal(err.Error())
			}
			dstPort = int32(portInt)
			payload = tcp.Payload
			//fmt.Println("TCP : from ", tcpSrcPort, " to", tcpDstPort, hex.Dump(payload))
		case layers.LayerTypeUDP:
			udp := tmpLayer.(*layers.UDP)
			packetType = "udp"
			portString := reg.FindString(udp.SrcPort.String())
			portInt, err := strconv.ParseInt(portString, 10, 32)
			if err != nil {
				fmt.Println(err.Error())
				log.Fatal(err.Error())
			}
			srcPort = int32(portInt)
			portString = reg.FindString(udp.DstPort.String())
			portInt, err = strconv.ParseInt(portString, 10, 32)
			if err != nil {
				fmt.Println(err.Error())
				log.Fatal(err.Error())
			}
			dstPort = int32(portInt)
			payload = udp.Payload
			//fmt.Println("TCP : from ", udpSrcPort, " to", udpDstPort, hex.Dump(payload))
		case layers.LayerTypeEthernet:
			//ethernet := tmpLayer.(*layers.Ethernet)
			//fmt.Println("Ethernet : from ", ethernet.SrcMAC, " to", ethernet.DstMAC)
		default:
			//fmt.Println("other layer : ", tmpLayer.LayerType())
		}

	}
	switch packetType {
	case "icmp":
		fmt.Println(packetType, srcIP, "to", dstIP, "\n", hex.Dump(payload))
	case "tcp":
		fmt.Println(packetType, srcIP, ":", srcPort, "to", dstIP, ":", dstPort, "\n", hex.Dump(payload))
	case "udp":
		fmt.Println(packetType, srcIP, ":", srcPort, "to", dstIP, ":", dstPort, "\n", hex.Dump(payload))
	}

	for _, pktRule := range pktRuleList {

		ruleSrcIP, _ := parseIP(pktRule.Source)
		ruleDstIP, _ := parseIP(pktRule.Destination)

		// matches
		if packetType == pktRule.Protocol && // action
			srcIP != nil &&
			srcIP.Equal(ruleSrcIP) && // source ip
			dstIP != nil &&
			dstIP.Equal(ruleDstIP) && // destination ip
			srcPort >= pktRule.SrcPort.start && // source port
			srcPort < pktRule.SrcPort.end &&
			dstPort >= pktRule.DstPort.start && // destination port
			dstPort < pktRule.SrcPort.end &&
			checkPayload(payload, pktRule) {
			//fmt.Println("packet matches")
			if pktRule.Action == "stream" {
				//fmt.Println("stream packet sent to stream analyzer")
				StreamPacketChannel <- *pkt
				PacketRuleChannel <- pktRule
			} else { // log alert
				var incident Incident
				incident.Action = pktRule.Action
				incident.Description = pktRule.Message
				incident.Time = time.Now()
				incident.Detail.Rule = pktRule
				incident.Detail.Packets = append(incident.Detail.Packets, *pkt)

				fmt.Println("new incident :", incident)
				//AlarmChannel <- incident TODO: remove this after test
			}
		}
	}
}

func checkPayload(payload []byte, pktRule PktRule) bool {

	// content
	distancePointer := 0
	withinPointer := len(payload)
	for _, content := range pktRule.Detection.Content {
		start := 0
		if content.offset > 0 {
			if int32(distancePointer) > content.offset {
				start = int(distancePointer)
			} else {
				start = int(content.offset)
			}
		}

		end := len(payload)
		if content.depth > 0 {
			if int32(withinPointer+len(content.content)) > content.depth {
				end = int(content.depth)
			} else {
				end = withinPointer + len(content.content)
			}
		}
		// search range overflows payload
		if end > len(payload) {
			fmt.Println("search range overflows payload, return false")
			return false
		}
		searchRange := payload[start:end]
		match := 0
		if content.nocase {
			match = strings.Count(strings.ToLower(string(searchRange)),
				strings.ToLower(content.content)) // Boyer-Moore
		} else {
			match = strings.Count(string(searchRange), content.content) // Boyer-Moore
		}
		if match > 0 { // contains substr
			if content.inverse { // inverse result
				return false // not all match
			} else { // straight result
			}
			if content.nocase {
				index := strings.Index(strings.ToLower(string(searchRange)),
					strings.ToLower(content.content))
				distancePointer = index + len(content.content) + int(content.distance)
			} else {
				index := strings.Index(string(searchRange), content.content)
				distancePointer = index +
					len(content.content) +
					int(content.distance)
			}
		} else { // does not contain substr
			if content.inverse {
			} else {
				return false // not all match
			}
		}
	}

	// protected content
	for _, protectedContent := range pktRule.Detection.ProtectedContent {
		start := protectedContent.offset
		end := protectedContent.offset + protectedContent.length
		hashRange := payload[start:end]
		var hash hash2.Hash
		switch protectedContent.hash {
		case "md5":
			hash = md5.New()
		case "sha256":
			hash = sha256.New()
		case "sha512":
			hash = sha512.New()
		}
		_, err := hash.Write(hashRange)
		if err != nil {
			fmt.Println(err.Error())
			log.Fatal(err.Error())
		}
		result := hash.Sum(nil)
		if string(result) == protectedContent.content { // hashes match
			if protectedContent.inverse { // inverse result
				return false
			} else {
			}
		} else { // hashes not match
			if protectedContent.inverse {
			} else {
				return false
			}
		}
	}

	return true
}
