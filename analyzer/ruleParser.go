package analyzer

import (
	"bufio"
	"io"
	"log"
	"os"
)

// parse packet rules from file
func ParsePktRules(file string, PktRulesList []PktRule) error {
	ruleFile, fileErr := os.Open(file)
	if fileErr != nil {
		log.Println(fileErr.Error())
	}
	defer ruleFile.Close()
	reader := bufio.NewReader(ruleFile)
	for {
		inputString, readerError := reader.ReadString('\n')
		log.Printf("The line was: %s ", inputString)
		if readerError == io.EOF {
			break
		}
	}
	log.Printf("parsing from %s finished \n", file)

	return nil
}

// parse packet rules from file
func ParseStreamRules(file string, StreamRulesList []StreamRule) error {

	return nil
}
