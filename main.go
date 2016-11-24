package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"runtime"

	"github.com/binaryfigments/dnscheck/controllers"
	"github.com/julienschmidt/httprouter"
)

func init() {
	// Verbose logging with file name and line number
	log.SetFlags(log.Lshortfile)

	// Use all CPU cores
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func main() {
	// Settings
	ListenHost := flag.String("host", "127.0.0.1", "Set the server host")
	ListenPort := flag.String("port", "4004", "Set the server port")

	// Read flags
	flag.Usage = func() {
		fmt.Println("\nUSAGE :")
		flag.PrintDefaults()
	}
	flag.Parse()

	// Loggins
	log.Println("-----------------------------------------")
	log.Println("     Check Domain API written in Go.     ")
	log.Println("-----------------------------------------")
	log.Println("    Listening: http://" + *ListenHost + ":" + *ListenPort + "    ")
	log.Println("-----------------------------------------")

	// Instantiate a new router
	r := httprouter.New()

	dc := controllers.NewDomainController()
	r.GET("/v1/domain/:domain", dc.GetDomain)
	r.POST("/v1/domain", dc.GetDomain)

	// Fire up the server
	http.ListenAndServe(*ListenHost+":"+*ListenPort, r)
}
