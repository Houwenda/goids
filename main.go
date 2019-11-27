package main

import (
	"fmt"
	"goids/analyzer"
	"goids/config"
	"log"
	"os"
)

var (
	LogLevels       = []string{"debug", "alert", "record"}
	PktRulesList    = make([]analyzer.PktRule, 0)
	StreamRulesList = make([]analyzer.StreamRule, 0)
)

func init() {

	// get config file path from command line
	var configPath string
	if len(os.Args) != 2 {
		fmt.Println("no config file provided")
		configPath = "/home/hwd/go/src/goids/config/goids.yaml"
	} else {
		configPath = os.Args[1]
	}
	fmt.Println("reading config from " + configPath)

	// parse config
	var c config.Config
	Conf, err := c.Parse(configPath)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	log.Println(Conf.UiConf)
	log.Println(Conf.RulesConf)
	log.Println(Conf.LogConf)
	log.Println(Conf.MultiThreadsConf)
	log.Println(Conf.AlarmConf)
	if err = c.Validate(LogLevels); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	// create logger
	logFile, logError := os.OpenFile(c.LogConf.Path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if logError != nil {
		fmt.Println("unable to open or create log file at " + c.LogConf.Path)
		os.Exit(1)
	}
	log.SetOutput(logFile)
	log.Println("logging starts")

	// TODO: parse rules
	for _, ruleFile := range c.RulesConf.PktRules {
		if err := analyzer.ParsePktRules(ruleFile, PktRulesList); err != nil {
			fmt.Println("error parsing rules file " + ruleFile)
			log.Fatal("error parsing rules file " + ruleFile)
			os.Exit(1)
		}
	}
	for _, ruleFile := range c.RulesConf.StreamRules {
		if err := analyzer.ParseStreamRules(ruleFile, StreamRulesList); err != nil {
			fmt.Println("error parsing rules file " + ruleFile)
			log.Fatal("error parsing rules file " + ruleFile)
			os.Exit(1)
		}
	}

}

func main() {
	fmt.Println("------- goids -------")
	// start http server

	// start alarm module

	// start analyzer module

	// start capturing packets
}
