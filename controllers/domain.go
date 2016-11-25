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

	/*
	 * TLD and Registry information
	 */

	tld, tldicann := publicsuffix.PublicSuffix(domain)
	h.Answer.Registry.TLD = tld
	h.Answer.Registry.ICANN = tldicann

	// Root nameservers
	startnameserver := "8.8.8.8"
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
	rootNameserver, err := resolveDomainA(rootNameservers[0])
	rootNameserverIP := rootNameserver[0]

	// TLD nameserver
	tldNameservers, err := resolveDomainNS(tld, rootNameserverIP)
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
	h.Answer.Nameservers.Registry = tldNameservers
	tldNameserver, err := resolveDomainA(tldNameservers[0])
	tldNameserverIP := tldNameserver[0]

	// Domain nameservers at Registry
	domainNameserversRegistry, err := resolveDomainNS(tld, tldNameserverIP)
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
	h.Answer.Nameservers.DomainRegistry = domainNameserversRegistry
	domainNameserverRegistry, err := resolveDomainA(domainNameserversRegistry[0])
	domainNameserverRegistryIP := domainNameserverRegistry[0]

	// Domain nameservers at Hoster
	domainNameserversHoster, err := resolveDomainNS(tld, domainNameserverRegistryIP)
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
	h.Answer.Nameservers.DomainHoster = domainNameserversHoster

	/*
	 * DS and DNSKEY information
	 */

	// Domain nameservers at Hoster
	domainds, err := resolveDomainDS(domain, domainNameserverRegistryIP)
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

	h.Answer.DSRecordCount = cap(h.Answer.DomainDS)

	var digest uint8
	if cap(h.Answer.DomainDS) != 0 {
		digest = h.Answer.DomainDS[0].DigestType
		log.Println("[OK] DS Information found:", digest)
	}

	dnskey, err := resolveDomainDNSKEY(domain, domainNameserverRegistryIP)
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
		calculatedDS, err := calculateDSRecord(domain, digest, domainNameserverRegistryIP)
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
