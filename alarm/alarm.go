package alarm

import (
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"goids/analyzer"
	"goids/config"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
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

	/* table header
	*  | action | timestamp | description | protocol | source | source port | destination | destination port | \ &&
	*  | metadata | reference | classification | sid | rev |
	 */
	//header := make([]string, 14)
	//header[0] = "action"
	//header[1] = "timestamp"
	//header[2] = "description"
	//header[3] = "protocol"
	//header[4] = "source"
	//header[5] = "source port"
	//header[6] = "destination"
	//header[7] = "destination port"
	//header[8] = "metadata"
	//header[9] = "reference"
	//header[10] = "classification"
	//header[11] = "sid"
	//header[12] = "rev"
	//header[13] = "payload"
	dbWriter := csv.NewWriter(dbFile)
	//if err := dbWriter.Write(header); err != nil {
	//	fmt.Println(err.Error())
	//	log.Fatal("database error " + err.Error())
	//}
	//dbWriter.Flush()

	for incident := range dbIncidentChannel {
		fmt.Println("Databaser")
		fmt.Println(incident)

		// add incident record
		record := make([]string, 14)
		record[0] = incident.Action
		record[1] = incident.Time.String()
		record[2] = strings.Replace(incident.Description, "\"", "", -1)
		record[3] = incident.Detail.Rule.Protocol
		record[4] = incident.Detail.Rule.Source
		if incident.Detail.Rule.SrcPort.End-incident.Detail.Rule.SrcPort.Start == 1 {
			record[5] = strconv.Itoa(int(incident.Detail.Rule.SrcPort.Start))
		} else {
			record[5] = "[ " + strconv.Itoa(int(incident.Detail.Rule.SrcPort.Start)) +
				" ~ " + strconv.Itoa(int(incident.Detail.Rule.SrcPort.End-1)) + " ]"
		}
		record[6] = incident.Detail.Rule.Destination
		if incident.Detail.Rule.DstPort.End-incident.Detail.Rule.DstPort.Start == 1 {
			record[7] = strconv.Itoa(int(incident.Detail.Rule.SrcPort.Start))
		} else {
			record[7] = "[ " + strconv.Itoa(int(incident.Detail.Rule.SrcPort.Start)) +
				" ~ " + strconv.Itoa(int(incident.Detail.Rule.SrcPort.End-1)) + " ]"
		}
		record[8] = ""
		for _, metadata := range incident.Detail.Rule.Metadata {
			record[8] += "- " + metadata + " \n"
		}
		record[9] = ""
		for _, reference := range incident.Detail.Rule.Reference {
			record[9] += "- " + reference + " \n"
		}
		record[10] = incident.Detail.Rule.Classification
		record[11] = strconv.Itoa(int(incident.Detail.Rule.SignatureId.Sid))
		record[12] = strconv.Itoa(int(incident.Detail.Rule.SignatureId.Rev))
		record[13] = ""
		for _, pkt := range incident.Detail.Packets {
			record[13] += hex.EncodeToString(pkt.ApplicationLayer().Payload()) + "\n"
		}
		if err := dbWriter.Write(record); err != nil {
			fmt.Println(err.Error())
			log.Fatal("database error " + err.Error())
		}
		dbWriter.Flush()
	}
}
