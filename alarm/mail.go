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
			m.SetHeader("Subject", "Incident from goids Alert!!! test")
			m.SetBody("text/html", "This is a test from goids. Please pay close attention.")

			// TODO: add incident
			fmt.Println(incident)

			d := gomail.NewDialer(smtpServer, 25, sender, authKey)

			if err := d.DialAndSend(m); err != nil {
				log.Println(err.Error())
				panic(err.Error())
			} else {
				fmt.Println("mail sent to " + receiver)
			}
		}
	}
}
