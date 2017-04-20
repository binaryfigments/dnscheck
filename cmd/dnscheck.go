package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/binaryfigments/dnscheck"
)

func main() {
	checkHost := flag.String("domain", "", "The domain name to test. (Required)")
	flag.Parse()
	if *checkHost == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	check, err := dnscheck.Run(*checkHost, "8.8.8.8")
	json, err := json.MarshalIndent(check, "", "   ")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("%s\n", json)
	os.Exit(0)
}
