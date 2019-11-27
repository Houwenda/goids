package config

import (
	"errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"regexp"
)

type Ui struct {
	Enable   bool   `yaml:"enable"`
	Ip       string `yaml:"ip"`
	Port     int32  `yaml:"port"`
	Location string `yaml:"location"`
}

type Rules struct {
	PktRules    []string `yaml:"pkt_rules,flow"`
	StreamRules []string `yaml:"stream_rules,flow"`
}

type Log struct {
	Path  string `yaml:"path"`
	Level string `yaml:"level"`
}

type StrictMode struct {
	Enable    bool  `yaml:"enable"`
	WorkerNum int32 `yaml:"worker_num"`
}

type Analyzer struct {
	MaxProc        int32      `yaml:"max_proc"`
	GroupNum       int32      `yaml:"group_num"`
	StrictModeConf StrictMode `yaml:"strict_mode"`
	Interfaces     []string   `yaml:"interfaces,flow"`
}

type Mail struct {
	Enable        bool     `yaml:"enable"`
	MaxFreq       int32    `yaml:"max_freq"`
	ServerAddress string   `yaml:"server_address"`
	Username      string   `yaml:"username"`
	AuthKey       string   `yaml:"auth_key"`
	Receivers     []string `yaml:"receivers,flow"`
}

type Alarm struct {
	MailConf Mail     `yaml:"mail"`
	Scripts  []string `yaml:"scripts,flow"`
}

type Config struct {
	UiConf       Ui       `yaml:"ui"`
	RulesConf    Rules    `yaml:"rules"`
	LogConf      Log      `yaml:"log"`
	AnalyzerConf Analyzer `yaml:"analyzer"`
	AlarmConf    Alarm    `yaml:"alarm"`
}

func (c *Config) Parse(path string) (*Config, error) {
	configFile, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// check file existence
	if _, existErr := os.Stat(path); existErr != nil && os.IsNotExist(existErr) {
		return nil, errors.New("config file does not exist at " + path)
	}
	// parse file
	err = yaml.Unmarshal(configFile, c)
	if err != nil {
		return nil, errors.New("config file cannot be parsed, check your syntax ")
	}
	return c, err
}

func (c *Config) Validate(logLevels []string) error {
	// check file existence
	for _, file := range c.RulesConf.PktRules {
		if _, existErr := os.Stat(file); existErr != nil && os.IsNotExist(existErr) {
			return errors.New("packet rule file does not exist at " + file)
		}
	}
	for _, file := range c.RulesConf.StreamRules {
		if _, existErr := os.Stat(file); existErr != nil && os.IsNotExist(existErr) {
			return errors.New("stream rule file does not exist at " + file)
		}
	}
	_, logError := os.OpenFile(c.LogConf.Path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if logError != nil {
		return errors.New("unable to open or create log file at " + c.LogConf.Path)
	}
	// unknown log level
	flag := false
	for _, k := range logLevels {
		if k == c.LogConf.Level {
			flag = true
		}
	}
	if !flag {
		return errors.New("invalid log level : " + c.LogConf.Level)
	}
	// check number
	if c.AnalyzerConf.MaxProc <= 0 {
		return errors.New("invalid max number of processes : ")
	}
	if c.AnalyzerConf.GroupNum <= 0 {
		return errors.New("invalid max number of groups : ")
	}
	if c.AnalyzerConf.StrictModeConf.Enable && c.AnalyzerConf.StrictModeConf.WorkerNum <= 0 {
		return errors.New("invalid max number of workers : ")
	}
	// check url route
	if c.UiConf.Enable {
		if ok, _ := regexp.Match("[0-9a-zA-Z]+", []byte(c.UiConf.Location)); !ok {
			return errors.New("invalid route of dashboard :" + c.UiConf.Location)
		}
	}
	return nil
}
