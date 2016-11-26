package controllers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/binaryfigments/dnscheck/models"
	"github.com/julienschmidt/httprouter"

	"golang.org/x/net/publicsuffix"
)

type (
	// DomainController struct
	DomainController struct{}
)

// NewDomainController controller
func NewDomainController() *DomainController {
	return &DomainController{}
}

// GetDomain function
func (dc DomainController) GetDomain(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	h := new(models.Message)
	h.Question.JobTime = time.Now()

	if r.Method == "GET" {
		domain := p.ByName("domain")
		h.Question.JobDomain = domain
	} else {
		domain := r.FormValue("domain")
		h.Question.JobDomain = domain
	}
	domain, err := publicsuffix.EffectiveTLDPlusOne(h.Question.JobDomain)
	if err != nil {
		log.Println("Domain not OK : ", err)
		h.Question.JobStatus = "Failed"
		h.Question.JobMessage = "Domain not OK"
		hj, _ := json.MarshalIndent(h, "", "    ")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(200)
		fmt.Fprintf(w, "%s", hj)
		return
	}

	h.Question.JobTime = time.Now()
	log.Println("[OK] Domain : ", domain)

	// Go check DNS!

	domainstate := checkDomainState(domain)
	if domainstate != "OK" {
		log.Println(domainstate)
		h.Question.JobStatus = "Failed"
		h.Question.JobMessage = domainstate
		hj, _ := json.MarshalIndent(h, "", "    ")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(200)
		fmt.Fprintf(w, "%s", hj)
		return
	}

	/*
	 * TLD and Registry information
	 */

	tld, tldicann := publicsuffix.PublicSuffix(domain)
	h.Answer.Registry.TLD = tld
	h.Answer.Registry.ICANN = tldicann

	// Root nameservers
	// startnameserver := "8.8.8.8"
	startnameserver := "64.6.64.6"
	rootNameservers, err := resolveDomainNS(".", startnameserver)
	if err != nil {
		log.Println("No nameservers found: .", err)
		h.Question.JobStatus = "Failed"
		h.Question.JobMessage = "No nameservers found"
		hj, _ := json.MarshalIndent(h, "", "    ")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(200)
		fmt.Fprintf(w, "%s", hj)
		return
	}
	h.Answer.Nameservers.Root = rootNameservers
	// rootNameserver := rootNameservers[0]

	// TLD nameserver
	registryNameservers, err := resolveDomainNS(tld, startnameserver)
	if err != nil {
		log.Println("No nameservers found: .", err)
		h.Question.JobStatus = "Failed"
		h.Question.JobMessage = "No nameservers found"
		hj, _ := json.MarshalIndent(h, "", "    ")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(200)
		fmt.Fprintf(w, "%s", hj)
		return
	}
	h.Answer.Nameservers.Registry = registryNameservers
	registryNameserver := registryNameservers[0]
	log.Println("[OK] TLD nameserver :", registryNameserver)

	registryNameserverIPs, err := resolveDomainA(registryNameserver)
	registryNameserverIP := registryNameserverIPs[0]
	log.Println("[OK] TLD nameserver IP :", registryNameserverIP)

	// Domain nameservers at Registry
	domainNameservers, err := resolveDomainNS(domain, startnameserver)
	if err != nil {
		log.Println("No nameservers found: .", err)
		h.Question.JobStatus = "Failed"
		h.Question.JobMessage = "No nameservers found"
		hj, _ := json.MarshalIndent(h, "", "    ")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(200)
		fmt.Fprintf(w, "%s", hj)
		return
	}
	h.Answer.Nameservers.Domain = domainNameservers
	domainNameserver := domainNameservers[0]
	log.Println("[OK] TLD nameserver : ", domainNameserver)

	/*
	 * DS and DNSKEY information
	 */

	// Domain nameservers at Hoster
	domainds, err := resolveDomainDS(domain, domainNameserver)
	if err != nil {
		log.Println("Error DS lookup : ", err)
		h.Question.JobStatus = "Failed"
		h.Question.JobMessage = "Error DS lookup"
		hj, _ := json.MarshalIndent(h, "", "    ")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(200)
		fmt.Fprintf(w, "%s", hj)
		return
	}
	h.Answer.DomainDS = domainds

	arecords, err := resolveDomainA(domain)
	h.Answer.DomainA = arecords

	aaaarecords, err := resolveDomainAAAA(domain)
	h.Answer.DomainAAAA = aaaarecords

	mxrecords, err := resolveDomainMX(domain)
	h.Answer.DomainMX = mxrecords

	h.Answer.DSRecordCount = cap(h.Answer.DomainDS)

	var digest uint8
	if cap(h.Answer.DomainDS) != 0 {
		digest = h.Answer.DomainDS[0].DigestType
		log.Println("[OK] DS Information found:", digest)
	}

	dnskey, err := resolveDomainDNSKEY(domain, domainNameserverHoster)
	if err != nil {
		log.Println("DNSKEY lookup failed: .", err)
		/*
			h.Question.JobStatus = "Failed"
			h.Question.JobMessage = "DNSKEY lookup failed"
			hj, _ := json.MarshalIndent(h, "", "    ")
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.WriteHeader(200)
			fmt.Fprintf(w, "%s", hj)
			return
		*/
	}
	log.Println("[OK] DNSKEY record lookup done.")
	h.Answer.DomainDNSKEY = dnskey

	h.Answer.DNSKEYRecordCount = cap(h.Answer.DomainDNSKEY)

	if h.Answer.DSRecordCount > 0 && h.Answer.DNSKEYRecordCount > 0 {
		calculatedDS, err := calculateDSRecord(domain, digest, registryNameserver)
		if err != nil {
			log.Println("DS calc failed: .", err)
		}
		h.Answer.DomainCalcDS = calculatedDS
	}

	h.Question.JobStatus = "OK"
	h.Question.JobMessage = "Job done!"

	hj, _ := json.MarshalIndent(h, "", "    ")
	// hj, _ := json.Marshal(h)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(200)
	fmt.Fprintf(w, "%s", hj)
}
