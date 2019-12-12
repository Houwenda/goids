package alarm

import (
	"fmt"
	"goids/analyzer"
	"goids/config"
	"gopkg.in/gomail.v2"
	"log"
	"strconv"
	"time"
)

func Mailer(incidentChannel <-chan analyzer.Incident, mailConf config.Mail) {

	m, _ := time.ParseDuration("-" + strconv.FormatInt(int64(mailConf.MaxFreq), 10) + "s")
	timer := time.Now().Add(m)
	m, _ = time.ParseDuration(strconv.FormatInt(int64(mailConf.MaxFreq), 10) + "s")

	sender := mailConf.Username
	authKey := mailConf.AuthKey
	receivers := mailConf.Receivers
	smtpServer := mailConf.ServerAddress
	for incident := range incidentChannel {
		fmt.Println("Mailer")

		if incident.Action == "log" {
			continue
		}

		if timer.Add(m).After(time.Now()) {
			fmt.Println("too many mails in the interval")
			continue
		} else {
			timer = time.Now()
		}

		log.Println("Mailer received incident")
		for _, receiver := range receivers {
			log.Println("receiver : " + receiver)
			m := gomail.NewMessage()
			m.SetHeader("From", sender)
			m.SetHeader("To", receiver)
			m.SetHeader("Subject", "Alert!!! New incident reported by goids.")

			// create details string
			details := "from " + incident.Detail.Rule.Source + " to " + incident.Detail.Rule.Destination +
				" in " + incident.Detail.Rule.Protocol + " </br>\n" +
				"class of activity: " + incident.Detail.Rule.Classification + "</br>\n" +
				"metadata: </br>\n"
			for _, metadata := range incident.Detail.Rule.Metadata {
				details += "&nbsp;&nbsp;- " + metadata + "</br>\n"
			}
			details += "references: </br>\n"
			for _, reference := range incident.Detail.Rule.Reference {
				details += "&nbsp;&nbsp;- " + reference + "</br>\n"
			}
			details += "</br>\n A close inspection is recommended. For more details, check wui/jsonlog/database if they are enabled."

			m.SetBody("text/html", "<body>An incident took place at "+
				incident.Time.String()+
				" . Please pay close attention! </br>\n"+
				"Description: "+incident.Description+". </br>\n</br>\n "+
				"Details: </br>\n"+details+"</body>")

			fmt.Println(incident)

			d := gomail.NewDialer(smtpServer, 25, sender, authKey)

			if err := d.DialAndSend(m); err != nil {
				log.Println(err.Error())
				panic(err.Error())
			} else {
				fmt.Println("mail sent to " + receiver)
				log.Println("mail sent to " + receiver)
			}
		}
	}
}
