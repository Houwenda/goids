package wui

import (
	"encoding/csv"
	"fmt"
	"github.com/gobuffalo/packr"
	"github.com/gorilla/mux"
	"goids/config"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

var staticFiles packr.Box
var dbPath string

func Wui(config config.Ui) {

	staticFiles = packr.NewBox("./resources")
	dbPath = config.DbPath

	router := mux.NewRouter()
	router.StrictSlash(true)
	//router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(staticFiles)))
	router.HandleFunc("/"+config.Location, indexHandler)

	srv := &http.Server{
		Handler: router,
		Addr:    config.Ip + ":" + strconv.Itoa(int(config.Port)),
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	fmt.Println("wui running on http://" + config.Ip + ":" + strconv.Itoa(int(config.Port)) + "/" + config.Location)
	srv.ListenAndServe()
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	indexString, err := staticFiles.FindString("index.html")
	if err != nil {
		fmt.Println(err.Error())
		log.Fatal(err.Error())
	}
	tmpl, err := template.New("index").Parse(indexString)
	if err != nil {
		fmt.Println(err.Error())
		log.Fatal(err.Error())
	}

	dbFile, dbError := os.OpenFile(dbPath, os.O_RDONLY|os.O_CREATE, 0666)
	if dbError != nil {
		fmt.Println("unable to open or create log file at " + dbPath)
		panic("unable to open or create log file at " + dbPath)
	}
	defer dbFile.Close()
	dbReader := csv.NewReader(dbFile)
	records, err := dbReader.ReadAll()
	if err != nil {
		fmt.Println(err)
		log.Fatal(err)
	}
	rows := make([]recordStruct, 0)
	for _, record := range records {
		var tmp recordStruct
		tmp.Action = record[0]
		tmp.Timestamp = record[1]
		tmp.Description = record[2]
		tmp.Protocol = record[3]
		tmp.Source = record[4]
		tmp.SrcPort = record[5]
		tmp.Destination = record[6]
		tmp.DstPort = record[7]
		tmp.Metadata = record[8]
		tmp.Reference = record[9]
		tmp.Classification = record[10]
		tmp.Sid = record[11]
		tmp.Rev = record[12]
		tmp.Payload = record[13]
		rows = append(rows, tmp)
	}

	tmpl.Execute(w, rows)
}

type recordStruct struct {
	Action         string
	Timestamp      string
	Description    string
	Protocol       string
	Source         string
	SrcPort        string
	Destination    string
	DstPort        string
	Metadata       string
	Reference      string
	Classification string
	Sid            string
	Rev            string
	Payload        string
}
