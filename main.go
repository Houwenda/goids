package main

import (
	"fmt"
	"goids/analyzer"
	"goids/config"
	"os"
)

var (
	LogLevels       = []string{"debug", "alert", "record"}
	PktRulesList    = make([]analyzer.PktRule, 0)
	StreamRulesList = make([]analyzer.StreamRule, 0)
)

func init() {

	// TODO: get config file path from command line

	var c config.Config
	Conf, err := c.Parse("/home/hwd/go/src/goids/config/goids.yaml")
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	fmt.Println(Conf.UiConf)
	fmt.Println(Conf.RulesConf)
	fmt.Println(Conf.LogConf)
	fmt.Println(Conf.MultiThreadsConf)
	fmt.Println(Conf.AlarmConf)
	if err = c.Validate(LogLevels); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	// TODO: create logger

	// TODO: parse rules

}

func main() {
	fmt.Println("------- goids -------")
	// start http server

	// start alarm module

	// start analyzer module

	// start capturing packets
}
