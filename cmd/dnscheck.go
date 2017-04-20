package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/binaryfigments/dnscheck"
)

func main() {
	checkHost := flag.String("domain", "", "The domain name to test. (Required)")
	checkNameserver := flag.String("nameserver", "8.8.8.8", "The nameserver to use.")
	checkOutput := flag.String("output", "json", "What output format: json or text.")
	flag.Parse()
	if *checkHost == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	check, err := dnscheck.Run(*checkHost, *checkNameserver)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	switch *checkOutput {
	case "json":
		json, err := json.MarshalIndent(check, "", "   ")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Printf("%s\n", json)
	case "text":
		fmt.Println("Not done jet...")
	default:
		err := errors.New("Output format is not json or txt.")
		fmt.Println(err)
		os.Exit(1)
	}

	os.Exit(0)
}
