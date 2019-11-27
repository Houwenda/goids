package analyzer

import (
	"bufio"
	"io"
	"log"
	"os"
	"regexp"
)

// parse packet rules from file
func ParsePktRules(file string, PktRulesList []PktRule) error {
	ruleFile, fileErr := os.Open(file)
	if fileErr != nil {
		log.Println(fileErr.Error())
		return fileErr
	}
	defer ruleFile.Close()

	ruleRegex, err := regexp.Compile(`^alert (tcp)|(udp)|(icmp) ((1[0-9][0-9]\.)|(2[0-4][0-9]\.)|(25[0-5]\.)|([1-9][0-9]\.)|([0-9]\.)){3}((1[0-9][0-9])|(2[0-4][0-9])|(25[0-5])|([1-9][0-9])|([0-9])) ((\d{1,5})|(any)) -> ((1[0-9][0-9]\.)|(2[0-4][0-9]\.)|(25[0-5]\.)|([1-9][0-9]\.)|([0-9]\.)){3}((1[0-9][0-9])|(2[0-4][0-9])|(25[0-5])|([1-9][0-9])|([0-9])) ((\d{1,5})|(any)) \( msg:"[^"]+"; flow:[^;]+; file_data;( [^:]+:[^;]+;)+ metadata:[^;]+; classtype:[^;]+; sid:\d{1,6}; rev:\d{1,2};\)`)
	if err != nil {
		log.Println(fileErr.Error())
		return err
	}
	ruleRegex, err = regexp.Compile(`((alert)|(log)) ((tcp)|(udp)|(icmp)) ((1[0-9][0-9]\.)|(2[0-4][0-9]\.)|(25[0-5]\.)|([1-9][0-9]\.)|([0-9]\.)){3}((1[0-9][0-9])|(2[0-4][0-9])|(25[0-5])|([1-9][0-9])|([0-9])) ((any)|(\d{1,5})) -> ((1[0-9][0-9]\.)|(2[0-4][0-9]\.)|(25[0-5]\.)|([1-9][0-9]\.)|([0-9]\.)){3}((1[0-9][0-9])|(2[0-4][0-9])|(25[0-5])|([1-9][0-9])|([0-9])) ((\d{1,5})|(any)) \(msg:"[^"]+";( flow:[^;]+)?;( file_data;)?(( [^:]+:[^;]+;)|( [ -~]+;))+( metadata:[^;]+;)?( reference:[^;]+;)*( classtype:[^;]+;)?( sid:\d{1,6};)?( rev:\d{1,2};)?\)`)
	if err != nil {
		log.Println(fileErr.Error())
		return err
	}

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
		if !ruleRegex.Match(inputStringByte) {
			log.Println("invalid rule syntax at ", inputStringByte)
		}
		// TODO: parse rule
	}
	log.Printf("parsing from %s finished \n", file)

	return nil
}

// parse packet rules from file
func ParseStreamRules(file string, StreamRulesList []StreamRule) error {

	return nil
}
