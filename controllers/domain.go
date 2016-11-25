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
	// domain := h.Question.JobDomain
	h.Question.JobTime = time.Now()
	log.Println("Domain : " + domain)

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

	// RootNS
	rootns, err := resolveDomainNS(".")
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
	h.Answer.RootNS = rootns

	// Fill TLD information.
	tld, tldicann := publicsuffix.PublicSuffix(domain)
	h.Answer.TLD.TLD = tld
	h.Answer.TLD.ICANN = tldicann

	tldns, err := resolveDomainNS(tld)
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
	h.Answer.TLD.Nameservers = tldns

	tldnameserver := tldns[0]
	domainds, err := resolveDomainDS(domain, tldnameserver)
	if err != nil {
		log.Println("Error DS lookup : .", err)
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

	nameservers, err := resolveDomainNS(domain)
	if err != nil {
		log.Println("DNS lookup failed: .", err)
		h.Question.JobStatus = "Failed"
		h.Question.JobMessage = "Nameserver lookup failed"
		hj, _ := json.MarshalIndent(h, "", "    ")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(200)
		fmt.Fprintf(w, "%s", hj)
		return
	}

	h.Answer.DomainNS = nameservers
	domainnameserver := nameservers[0]

	h.Answer.DSRecordCount = cap(h.Answer.DomainDS)

	var digest uint8
	if cap(h.Answer.DomainDS) != 0 {
		digest = h.Answer.DomainDS[0].DigestType
		log.Println("[OK] DS Information found:", digest)
	}

	dnskey, err := resolveDomainDNSKEY(domain, domainnameserver)
	if err != nil {
		log.Println("DNSKEY lookup failed: .", err)
		h.Question.JobStatus = "Failed"
		h.Question.JobMessage = "DNSKEY lookup failed"
		hj, _ := json.MarshalIndent(h, "", "    ")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(200)
		fmt.Fprintf(w, "%s", hj)
		return
	}
	log.Println("[OK] DNSKEY record lookup done.")
	h.Answer.DomainDNSKEY = dnskey

	h.Answer.DNSKEYRecordCount = cap(h.Answer.DomainDNSKEY)

	if h.Answer.DSRecordCount > 0 && h.Answer.DNSKEYRecordCount > 0 {
		calculatedDS, err := calculateDSRecord(domain, digest, domainnameserver)
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
