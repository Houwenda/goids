package alarm

import (
	"fmt"
	"goids/analyzer"
	"goids/config"
	"os"
)

func JsonLogger(jsonIncidentChannel <-chan analyzer.Incident, jsonFileConf config.JsonFile) {

	logFile, logError := os.OpenFile(jsonFileConf.Path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if logError != nil {
		fmt.Println("unable to open or create log file at " + jsonFileConf.Path)
		panic("unable to open or create log file at " + jsonFileConf.Path)
	}
	defer logFile.Close()

	for incident := range jsonIncidentChannel {
		fmt.Println("JsonLogger")
		fmt.Println(incident)

		// TODO: add incident

	}
}
