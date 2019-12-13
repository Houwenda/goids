package alarm

import (
	"bufio"
	"encoding/json"
	"fmt"
	"goids/analyzer"
	"goids/config"
	"log"
	"os"
)

func JsonLogger(jsonIncidentChannel <-chan analyzer.Incident, jsonFileConf config.JsonFile) {

	logFile, logError := os.OpenFile(jsonFileConf.Path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if logError != nil {
		fmt.Println("unable to open or create log file at " + jsonFileConf.Path)
		panic("unable to open or create log file at " + jsonFileConf.Path)
	}
	defer logFile.Close()
	jsonWriter := bufio.NewWriter(logFile)

	for incident := range jsonIncidentChannel {
		//fmt.Println("JsonLogger")
		//fmt.Println(incident)

		if jsonFileConf.Level == "alert" && incident.Action == "log" {
			continue
		}

		// add incident
		result, err := json.Marshal(incident)
		if err != nil {
			fmt.Println(err.Error())
			log.Fatal(err.Error())
		}
		//fmt.Println(string(result))
		if _, err := jsonWriter.WriteString(string(result) + ",\n"); err != nil {
			fmt.Println(err.Error())
			log.Fatal(err.Error())
		}
		if err := jsonWriter.Flush(); err != nil {
			fmt.Println(err.Error())
			log.Fatal(err.Error())
		}

	}
}
