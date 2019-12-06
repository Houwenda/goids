package wui

import (
	"fmt"
	"github.com/gobuffalo/packr"
	"github.com/gorilla/mux"
	"goids/config"
	"net/http"
	"strconv"
	"time"
)

func Wui(config config.Ui) {
	fmt.Println("wui starts")

	staticFiles := packr.NewBox("./resources")
	router := mux.NewRouter()
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(staticFiles)))

	srv := &http.Server{
		Handler: router,
		Addr:    config.Ip + ":" + strconv.Itoa(int(config.Port)),
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	fmt.Println("wui running on http://" + config.Ip + ":" + strconv.Itoa(int(config.Port)))
	srv.ListenAndServe()
}
