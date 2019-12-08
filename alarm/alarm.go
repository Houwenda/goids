package alarm

import (
	"fmt"
	"goids/analyzer"
	"goids/config"
	"log"
	"os"
	"os/exec"
)

var IncidentChannels []chan analyzer.Incident

func Alarm(alarmChannel chan analyzer.Incident, alarmConf config.Alarm) {
	fmt.Println("alarmer starts")
	log.Println("alarmer starts")

	// mail alert
	if alarmConf.MailConf.Enable {
		mailIncidentChannel := make(chan analyzer.Incident, 100)
		go Mailer(mailIncidentChannel, alarmConf.MailConf)
		IncidentChannels = append(IncidentChannels, mailIncidentChannel)
	}

	// json file log
	if alarmConf.JsonFileConf.Enable {
		jsonLogIncidentChannel := make(chan analyzer.Incident, 100)
		go JsonLogger(jsonLogIncidentChannel, alarmConf.JsonFileConf)
		IncidentChannels = append(IncidentChannels, jsonLogIncidentChannel)
	}

	// database
	dbIncidentChannel := make(chan analyzer.Incident, 100)
	go Databaser(dbIncidentChannel, alarmConf.DbPath)
	IncidentChannels = append(IncidentChannels, dbIncidentChannel)

	for incident := range alarmChannel {
		fmt.Println(incident)
		log.Println(incident)
		for _, ch := range IncidentChannels {
			ch <- incident
		}
		for _, script := range alarmConf.Scripts {
			go exec.Command(script)
		}
	}
}

func Databaser(dbIncidentChannel chan analyzer.Incident, dbPath string) {

	dbFile, dbError := os.OpenFile(dbPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if dbError != nil {
		fmt.Println("unable to open or create log file at " + dbPath)
		panic("unable to open or create log file at " + dbPath)
	}
	defer dbFile.Close()

	for incident := range dbIncidentChannel {
		fmt.Println("Databaser")
		fmt.Println(incident)

		// TODO: add incident

	}
}
