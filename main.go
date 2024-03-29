package main

import (
	"fmt"
	"github.com/google/gopacket"
	"goids/alarm"
	"goids/analyzer"
	"goids/config"
	"goids/wui"
	"log"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"os/user"
	"runtime"
	"syscall"
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
	//log.SetOutput(os.Stdout) // test
	log.Println("logging starts")

	log.Println(Conf.UiConf)
	log.Println(Conf.RulesConf)
	log.Println(Conf.LogConf)
	log.Println(Conf.AnalyzerConf)
	log.Println(Conf.AlarmConf)

	// parse rules
	for _, ruleFile := range Conf.RulesConf.PktRules {
		PktRulesList, err = analyzer.ParsePktRules(ruleFile, PktRulesList)
		if err != nil {
			fmt.Println("error parsing rules file " + ruleFile)
			log.Fatal("error parsing rules file " + ruleFile)
		}
	}
	for _, ruleFile := range Conf.RulesConf.StreamRules {
		StreamRulesList, err = analyzer.ParseStreamRules(ruleFile, StreamRulesList)
		if err != nil {
			fmt.Println("error parsing rules file " + ruleFile)
			log.Fatal("error parsing rules file " + ruleFile)
		}
	}

	// set max proc
	runtime.GOMAXPROCS(int(Conf.AnalyzerConf.MaxProc))
}

func main() {

	// pprof test
	//go func() {
	//	http.ListenAndServe("localhost:6060", nil)
	//}()

	fmt.Println("-------------- goids --------------")
	//return
	alarmChannel := make(chan analyzer.Incident, 100)
	packetChannel := make(chan gopacket.Packet)

	// start http server
	if Conf.UiConf.Enable {
		go wui.Wui(Conf.UiConf)
	}
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

	//quit
	sigs := make(chan os.Signal, 1)
	//done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGSTOP)

	// start capturing packets
	analyzer.Watch(Conf.AnalyzerConf.Interfaces, packetChannel, sigs)

}
