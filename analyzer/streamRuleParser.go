package analyzer

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
)

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
		case "action":
			if value == "log" || value == "alert" {
				streamRule.Action = value
			} else {
				return streamRule, errors.New("invalid action : " + value)
			}
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

	//fmt.Println("streamRule :", streamRule)
	return streamRule, nil
}
