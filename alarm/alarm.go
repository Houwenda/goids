package alarm

import (
	"fmt"
	"goids/analyzer"
	"goids/config"
	"log"
	"os/exec"
)

var IncidentChannel []chan analyzer.Incident

func Alarm(alarmChannel chan analyzer.Incident, alarmConf config.Alarm) {
	fmt.Println("alarm starts")
	log.Println("alarm starts")

	// mail alert
	if alarmConf.MailConf.Enable {
		mailIncidentChannel := make(chan analyzer.Incident, 2)
		go Mailer(mailIncidentChannel, alarmConf.MailConf)
		IncidentChannel = append(IncidentChannel, mailIncidentChannel)
	}

	// json file log
	if alarmConf.JsonFileConf.Enable {
		jsonLogIncidentChannel := make(chan analyzer.Incident, 2)
		go JsonLogger(jsonLogIncidentChannel, alarmConf.JsonFileConf)
		IncidentChannel = append(IncidentChannel, jsonLogIncidentChannel)
	}

	for incident := range alarmChannel {
		fmt.Println(incident)
		log.Println(incident)
		for _, ch := range IncidentChannel {
			ch <- incident
		}
		for _, script := range alarmConf.Scripts {
			exec.Command(script)
		}
	}
}
