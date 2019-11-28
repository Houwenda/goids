package main

import (
	"fmt"
	"github.com/google/gopacket"
	"goids/alarm"
	"goids/analyzer"
	"goids/config"
	"log"
	"os"
	"os/user"
	"runtime"
)

var (
	LogLevels       = []string{"debug", "alert", "record"}
	PktRulesList    = make([]analyzer.PktRule, 0)
	StreamRulesList = make([]analyzer.StreamRule, 0)
	Conf            config.Config
)

func init() {

	// user check
	if runtime.GOOS == "linux" {
		user, err := user.Current()
		if err != nil {
			fmt.Println(err.Error())
		}
		if user.Username != "root" {
			fmt.Println("ERROR: Current user is not root. Goids needs root privilege to capture packets. ")
			os.Exit(1)
		}
	} else if runtime.GOOS == "windows" {

	}

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
	//var c config.Config
	Conf, err := Conf.Parse(configPath)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	log.Println(Conf.UiConf)
	log.Println(Conf.RulesConf)
	log.Println(Conf.LogConf)
	log.Println(Conf.AnalyzerConf)
	log.Println(Conf.AlarmConf)
	if err = Conf.Validate(LogLevels); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	// create logger
	if Conf.LogConf.Level == "debug" { // remove past log file
		if err := os.Remove(Conf.LogConf.Path); err != nil {
			fmt.Println("error removing past log file at " + Conf.LogConf.Path)
			os.Exit(1)
		}
	}
	logFile, logError := os.OpenFile(Conf.LogConf.Path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if logError != nil {
		fmt.Println("unable to open or create log file at " + Conf.LogConf.Path)
		os.Exit(1)
	}
	log.SetOutput(logFile)
	log.Println("logging starts")

	// TODO: parse rules
	for _, ruleFile := range Conf.RulesConf.PktRules {
		if err := analyzer.ParsePktRules(ruleFile, PktRulesList); err != nil {
			fmt.Println("error parsing rules file " + ruleFile)
			log.Fatal("error parsing rules file " + ruleFile)
		}
	}
	for _, ruleFile := range Conf.RulesConf.StreamRules {
		if err := analyzer.ParseStreamRules(ruleFile, StreamRulesList); err != nil {
			fmt.Println("error parsing rules file " + ruleFile)
			log.Fatal("error parsing rules file " + ruleFile)
		}
	}

	// set max proc
	runtime.GOMAXPROCS(int(Conf.AnalyzerConf.MaxProc))
}

func main() {
	fmt.Println("------- goids -------")

	alarmChannel := make(chan analyzer.Incident)
	packetChannel := make(chan gopacket.Packet)

	// start http server

	// start alarm module
	go alarm.Alarm(alarmChannel, Conf.AlarmConf)

	// start analyzer module
	go analyzer.Analyze(Conf.AnalyzerConf.StrictModeConf.Enable,
		Conf.AnalyzerConf.GroupNum,
		Conf.AnalyzerConf.StrictModeConf.WorkerNum,
		packetChannel,
		alarmChannel,
		PktRulesList,
		StreamRulesList)

	// start capturing packets
	analyzer.Watch(Conf.AnalyzerConf.Interfaces, packetChannel)

}
