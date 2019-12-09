package analyzer

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// parse packet rules from file
func ParsePktRules(file string, PktRulesList []PktRule) ([]PktRule, error) {
	ruleFile, fileErr := os.Open(file)
	if fileErr != nil {
		log.Println(fileErr.Error())
		return PktRulesList, fileErr
	}
	defer ruleFile.Close()

	/*
		ruleRegex, err := regexp.Compile(`^alert (tcp)|(udp)|(icmp) ((1[0-9][0-9]\.)|(2[0-4][0-9]\.)|(25[0-5]\.)|([1-9][0-9]\.)|([0-9]\.)){3}((1[0-9][0-9])|(2[0-4][0-9])|(25[0-5])|([1-9][0-9])|([0-9])) ((\d{1,5})|(any)) -> ((1[0-9][0-9]\.)|(2[0-4][0-9]\.)|(25[0-5]\.)|([1-9][0-9]\.)|([0-9]\.)){3}((1[0-9][0-9])|(2[0-4][0-9])|(25[0-5])|([1-9][0-9])|([0-9])) ((\d{1,5})|(any)) \( msg:"[^"]+"; flow:[^;]+; file_data;( [^:]+:[^;]+;)+ metadata:[^;]+; classtype:[^;]+; sid:\d{1,6}; rev:\d{1,2};\)`)
		if err != nil {
			log.Println(fileErr.Error())
			return PktRulesList, err
		}
		ruleRegex, err = regexp.Compile(`((alert)|(log)) ((tcp)|(udp)|(icmp)) ((1[0-9][0-9]\.)|(2[0-4][0-9]\.)|(25[0-5]\.)|([1-9][0-9]\.)|([0-9]\.)){3}((1[0-9][0-9])|(2[0-4][0-9])|(25[0-5])|([1-9][0-9])|([0-9])) ((any)|(\d{1,5})) -> ((1[0-9][0-9]\.)|(2[0-4][0-9]\.)|(25[0-5]\.)|([1-9][0-9]\.)|([0-9]\.)){3}((1[0-9][0-9])|(2[0-4][0-9])|(25[0-5])|([1-9][0-9])|([0-9])) ((\d{1,5})|(any)) \(msg:"[^"]+";( flow:[^;]+)?;( file_data;)?(( [^:]+:[^;]+;)|( [ -~]+;))+( metadata:[^;]+;)?( reference:[^;]+;)*( classtype:[^;]+;)?( sid:\d{1,6};)?( rev:\d{1,2};)?\)`)
		if err != nil {
			log.Println(fileErr.Error())
			return PktRulesList, err
		}

	*/

	reader := bufio.NewReader(ruleFile)
	for {
		inputString, readerError := reader.ReadString('\n')
		if readerError == io.EOF {
			break
		}
		if inputString[0] == '#' {
			continue
		}
		inputStringByte := []byte(inputString[:len(inputString)-1])
		log.Printf("The rule is: %s ", inputStringByte)
		/*
			if !ruleRegex.Match(inputStringByte) {
				log.Println("invalid rule syntax at ", inputStringByte)
			}
		*/
		// parse packet rule
		tmpRule, err := parsePacketLine(inputString)
		if err != nil {
			fmt.Println(err.Error())
			return PktRulesList, err
		}
		//tmpRule = PktRule{Action: file, Protocol: inputString} // test

		PktRulesList = append(PktRulesList, tmpRule)
	}
	log.Printf("parsing from %s finished \n", file)

	return PktRulesList, nil
}

func parsePacketLine(inputString string) (PktRule, error) {
	var pktRule PktRule
	tmp := strings.Index(inputString, "(")
	header := inputString[:tmp]
	details := inputString[tmp:]
	//fmt.Println("details :", details)
	headerWordList := strings.Fields(strings.TrimSpace(header))
	//fmt.Println("headerWordList :", headerWordList)

	/**************************************************
	*                  rule header
	* action : what to do when coming through a packet
	* protocol : recognize protocol of packet
	* source/destination : ip address
	* srcPort/dstPort : port
	*
	**************************************************/

	// action
	if headerWordList[0] == "log" || headerWordList[0] == "alert" || headerWordList[0] == "stream" {
		pktRule.Action = headerWordList[0]
	} else {
		return pktRule, errors.New("action error")
	}

	// protocol
	if headerWordList[1] == "tcp" || headerWordList[1] == "udp" || headerWordList[1] == "icmp" {
		pktRule.Protocol = headerWordList[1]
	} else {
		return pktRule, errors.New("protocol error")
	}

	// source
	if _, err := parseIP(headerWordList[2]); err == nil {
		pktRule.Source = headerWordList[2]
	} else if headerWordList[2] == "any" {
		pktRule.Source = "any"
	} else {
		return pktRule, errors.New("source error")
	}

	// srcPort
	if srcPort, err := strconv.ParseInt(headerWordList[3], 10, 32); err == nil && srcPort > 0 && srcPort < 65536 {
		// 80 / 22 / ...
		pktRule.SrcPort.start = int32(srcPort)
		pktRule.SrcPort.end = int32(srcPort) + 1
	} else if headerWordList[3] == "any" {
		// any
		pktRule.SrcPort.start = 0
		pktRule.SrcPort.end = 65536
	} else if result, err := regexp.Match(`\d+:\d+`, []byte(headerWordList[3])); err == nil && result {
		// 1:65535 65535 included / 80:81 81 included
		start := headerWordList[3][:strings.Index(headerWordList[3], ":")]
		end := headerWordList[3][strings.Index(headerWordList[3], ":")+1:]
		startInt, err := strconv.ParseInt(start, 10, 32)
		if err != nil {
			return pktRule, err
		}
		endInt, err := strconv.ParseInt(end, 10, 32)
		if err != nil {
			return pktRule, err
		}
		if startInt >= endInt {
			return pktRule, errors.New("srcPort start greater than end")
		}
		pktRule.SrcPort.start = int32(startInt)
		pktRule.SrcPort.end = int32(endInt) + 1
	} else {
		return pktRule, errors.New("srcPort error")
	}

	// ->
	if headerWordList[4] != "->" {
		return pktRule, errors.New("-> not found in valid position")
	}

	// destination
	if _, err := parseIP(headerWordList[5]); err == nil {
		pktRule.Destination = headerWordList[5]
	} else if headerWordList[5] == "any" {
		pktRule.Destination = "any"
	} else {
		return pktRule, errors.New("destination error")
	}

	// dstPort
	if dstPort, err := strconv.ParseInt(headerWordList[6], 10, 32); err == nil && dstPort > 0 && dstPort < 65536 {
		// 80 / 22 / ...
		pktRule.DstPort.start = int32(dstPort)
		pktRule.DstPort.end = int32(dstPort)
	} else if headerWordList[6] == "any" {
		// any
		pktRule.DstPort.start = 0
		pktRule.DstPort.end = 65536
	} else if result, err := regexp.Match(`\d+:\d+`, []byte(headerWordList[6])); err == nil && result {
		// 1:65535 65535 included / 80:81 81 included
		start := headerWordList[6][:strings.Index(headerWordList[6], ":")]
		end := headerWordList[6][strings.Index(headerWordList[6], ":")+1:]
		startInt, err := strconv.ParseInt(start, 10, 32)
		if err != nil {
			return pktRule, err
		}
		endInt, err := strconv.ParseInt(end, 10, 32)
		if err != nil {
			return pktRule, err
		}
		if startInt >= endInt {
			return pktRule, errors.New("dstPort start greater than end")
		}
		pktRule.DstPort.start = int32(startInt)
		pktRule.DstPort.end = int32(endInt) + 1
	} else {
		return pktRule, errors.New("dstPort error")
	}

	/**********************************************
	*                 rule details
	* msg : description of rule
	* classtype : type of attack activity
	* reference : source of this rule
	* sid : identification of the rule
	* rev : revision number of the rule
	* metadata : additional information about the rule
	*
	***********************************************/
	detailsPhraseList := strings.Split(strings.TrimSpace(details[1:strings.Index(details, ")")]), ";")
	//fmt.Println(detailsPhraseList)

	// content or protected_content
	currentDetectionType := ""

	for _, detailsPhrase := range detailsPhraseList {
		tmp := strings.Index(detailsPhrase, ":")
		if tmp < 0 { // no ":" in phrase
			//fmt.Println(detailsPhrase)
			if detailsPhrase == "nocase" {
				if len(pktRule.Detection.Content) < 1 {
					return pktRule, errors.New("invalid position of nocase")
				}
				pktRule.Detection.Content[len(pktRule.Detection.Content)-1].nocase = true
			}
			continue
		}
		key := detailsPhrase[:tmp]
		key = strings.Replace(key, " ", "", -1)
		value := detailsPhrase[tmp+1:]
		//fmt.Println("key :", key, " value :", value)

		// general rule options
		switch key {
		case "msg":
			pktRule.Message = value
		case "classtype":
			pktRule.Classification = value
		case "reference":
			pktRule.Reference = append(pktRule.Reference, value)
		case "sid":
			sidInt, err := strconv.ParseInt(value, 10, 32)
			if err != nil {
				return pktRule, err
			}
			pktRule.SignatureId.Sid = int32(sidInt)

		case "rev":
			revInt, err := strconv.ParseInt(value, 10, 32)
			if err != nil {
				return pktRule, err
			}
			pktRule.SignatureId.Rev = int32(revInt)

		case "metadata":
			pktRule.Metadata = append(pktRule.Metadata, value)
		}

		// payload detection rule options
		switch key {
		// Content
		case "content":
			/* examples:
			* content:!"PE|00 00|XX"
			* content:"REPEAT"
			* content:"|00 ab cd|"
			*
			* note: only the first part of hex block will be parsed, |ab|PE|00| not supported
			 */
			content := struct {
				content  string
				inverse  bool
				nocase   bool
				depth    int32
				offset   int32
				distance int32
				within   int32
			}{}
			content.nocase = false

			if strings.Count(value[:strings.Index(value, "\"")], "!") == 0 {
				content.inverse = false
			} else if strings.Count(value[:strings.Index(value, "\"")], "!") == 1 {
				content.inverse = true
				value = value[strings.Index(value, "!")+1:]
			} else {
				return pktRule, errors.New("invalid content value :" + value)
			}

			if strings.Count(value, "|") == 0 {
				content.content = strings.Replace(value, "\"", "", -1)
				pktRule.Detection.Content = append(pktRule.Detection.Content, content)
				//pktRule.Detection.Content = append(pktRule.Detection.Content, strings.Replace(value, "\"", "", -1))
			} else if strings.Count(value, "|") == 2 {
				front := strings.Replace(value[:strings.Index(value, "|")], "\"", "", 1)
				middle := strings.Replace(value[strings.Index(value, "|"):strings.LastIndex(value, "|")], "|", "", 1)
				back := strings.Replace(value[strings.LastIndex(value, "|"):], "\"", "", 1)
				back = strings.Replace(back, "|", "", 1)
				//fmt.Println("front :", front, "middle :", middle, "back :", back)
				resultBytes := []byte(front)
				for _, b := range strings.Fields(middle) {
					tmpByte, err := hex.DecodeString(b)
					if err != nil {
						return pktRule, errors.New("invalid content :" + value)
					}
					resultBytes = append(resultBytes, tmpByte[0])
				}
				for i := 0; i < len(back); i++ {
					resultBytes = append(resultBytes, back[i])
				}
				//fmt.Println("resultBytes :", hex.Dump(resultBytes))
				content.content = string(resultBytes)
				pktRule.Detection.Content = append(pktRule.Detection.Content, content)
				//pktRule.Detection.Content = append(pktRule.Detection.Content, string(resultBytes))
			} else {
				return pktRule, errors.New("invalid content value : " + value)
			}
			currentDetectionType = "content"
		case "depth":
			depthInt, err := strconv.ParseInt(value, 10, 32)
			if err != nil {
				return pktRule, err
			}
			if len(pktRule.Detection.Content) < 1 {
				return pktRule, errors.New("invalid position of depth")
			}
			pktRule.Detection.Content[len(pktRule.Detection.Content)-1].depth = int32(depthInt)
		case "offset":
			offsetInt, err := strconv.ParseInt(value, 10, 32)
			if err != nil {
				return pktRule, err
			}
			if currentDetectionType == "content" {
				if len(pktRule.Detection.Content) < 1 {
					return pktRule, errors.New("invalid position of offset")
				}
				pktRule.Detection.Content[len(pktRule.Detection.Content)-1].offset = int32(offsetInt)
			} else if currentDetectionType == "protected_content" {
				if len(pktRule.Detection.ProtectedContent) < 1 {
					return pktRule, errors.New("invalid position of offset")
				}
				pktRule.Detection.ProtectedContent[len(pktRule.Detection.ProtectedContent)-1].offset = int32(offsetInt)
			} else {
				return pktRule, errors.New("invalid position of offset")
			}
		case "distance":
			distanceInt, err := strconv.ParseInt(value, 10, 32)
			if err != nil {
				return pktRule, err
			}
			if len(pktRule.Detection.Content) < 1 {
				return pktRule, errors.New("invalid position of distance")
			}
			pktRule.Detection.Content[len(pktRule.Detection.Content)-1].distance = int32(distanceInt)
		case "within":
			withinInt, err := strconv.ParseInt(value, 10, 32)
			if err != nil {
				return pktRule, err
			}
			if len(pktRule.Detection.Content) < 1 {
				return pktRule, errors.New("invalid position of within")
			}
			pktRule.Detection.Content[len(pktRule.Detection.Content)-1].within = int32(withinInt)

		// ProtectedContent
		case "protected_content":
			/* examples:
			* protected_content:"293C9EA246FF9985DC6F62A650F78986"; hash:md5; offset:0; length:4;
			* protected_content:"56D6F32151AD8474F40D7B939C2161EE2BBF10023F4AF1DBB3E13260EBDC6342"; hash:sha256; offset:0; length:4;
			 */
			protectedContent := struct {
				content string
				inverse bool
				offset  int32
				length  int32
				hash    string
			}{}

			if strings.Count(value[:strings.Index(value, "\"")], "!") == 0 {
				protectedContent.inverse = false
			} else if strings.Count(value[:strings.Index(value, "\"")], "!") == 1 {
				protectedContent.inverse = true
				value = value[strings.Index(value, "!")+1:]
			} else {
				return pktRule, errors.New("invalid content value :" + value)
			}
			protectedContent.content = strings.Replace(value, "\"", "", -1)
			pktRule.Detection.ProtectedContent = append(pktRule.Detection.ProtectedContent, protectedContent)

		case "length":
			lengthInt, err := strconv.ParseInt(value, 10, 32)
			if err != nil {
				return pktRule, err
			}
			if len(pktRule.Detection.ProtectedContent) < 1 {
				return pktRule, errors.New("invalid position of length")
			}
			pktRule.Detection.ProtectedContent[len(pktRule.Detection.ProtectedContent)-1].length = int32(lengthInt)
		case "hash":
			if value == "md5" || value == "sha256" || value == "sha512" {
				if len(pktRule.Detection.ProtectedContent) < 1 {
					return pktRule, errors.New("invalid position of hash")
				}
				pktRule.Detection.ProtectedContent[len(pktRule.Detection.ProtectedContent)-1].hash = value
			} else {
				return pktRule, errors.New("invalid hash method :" + value)
			}
		}
	}

	fmt.Println("pktRule :", pktRule)
	return pktRule, nil
}

func parseIP(inputString string) (net.IP, error) {
	ip := net.ParseIP(inputString)
	if ip.To4() != nil {
		return ip, nil
	} else if ip.To16() != nil {
		return ip, nil
	} else {
		return nil, errors.New("invalid ip")
	}
}

func ParseStreamRules(file string, StreamRulesList []StreamRule) ([]StreamRule, error) {

	ruleFile, fileErr := os.Open(file)
	if fileErr != nil {
		log.Println(fileErr.Error())
		return StreamRulesList, fileErr
	}
	defer ruleFile.Close()

	reader := bufio.NewReader(ruleFile)
	for {
		inputString, readerError := reader.ReadString('\n')
		if readerError == io.EOF {
			break
		}
		if inputString[0] == '#' {
			continue
		}
		inputStringByte := []byte(inputString[:len(inputString)-1])
		log.Printf("The rule is: %s ", inputStringByte)
		/*
			if !ruleRegex.Match(inputStringByte) {
				log.Println("invalid rule syntax at ", inputStringByte)
			}
		*/
		// parse packet rule
		tmpRule, err := ParseStreamLine(inputString[:len(inputString)-1])
		if err != nil {
			fmt.Println(err.Error())
			return StreamRulesList, err
		}
		//tmpRule = PktRule{Action: file, Protocol: inputString} // test

		StreamRulesList = append(StreamRulesList, tmpRule)
	}
	log.Printf("parsing from %s finished \n", file)

	return StreamRulesList, nil
}

func ParseStreamLine(inputString string) (StreamRule, error) {
	var streamRule StreamRule

	phraseList := strings.Split(strings.Replace(inputString, " ", "", -1), ";")
	//fmt.Println(phraseList)
	for _, phrase := range phraseList {
		tmp := strings.Index(phrase, ":")
		if tmp < 0 { // no ":" in phrase
			return streamRule, errors.New("expect \":\" but not found")
		}
		key := phrase[:tmp]
		key = strings.Replace(key, " ", "", -1)
		value := phrase[tmp+1:]
		//fmt.Println("key :", key, " value :", value)

		switch key {
		case "sid":
			sidInt, err := strconv.ParseInt(value, 10, 32)
			if err != nil {
				return streamRule, err
			}
			streamRule.Sid = int32(sidInt)
		case "hour":
			streamRule.Frequency.interval = "hour"
			valueInt, err := strconv.ParseInt(value, 10, 32)
			if err != nil {
				return streamRule, err
			}
			streamRule.Frequency.value = int32(valueInt)
		case "minute":
			streamRule.Frequency.interval = "minute"
			valueInt, err := strconv.ParseInt(value, 10, 32)
			if err != nil {
				return streamRule, err
			}
			streamRule.Frequency.value = int32(valueInt)
		case "second":
			streamRule.Frequency.interval = "second"
			valueInt, err := strconv.ParseInt(value, 10, 32)
			if err != nil {
				return streamRule, err
			}
			streamRule.Frequency.value = int32(valueInt)
		}
	}

	// validate
	if streamRule.Frequency.interval == "" {
		return streamRule, errors.New("invalid interval type")
	}
	if streamRule.Frequency.value < 1 {
		return streamRule, errors.New("invalid frequency")
	}

	fmt.Println("streamRule :", streamRule)
	return streamRule, nil
}
