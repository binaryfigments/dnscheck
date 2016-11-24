package controllers

/*
 * Todo: Single function
 */

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/binaryfigments/dnscheck/models"
	"github.com/julienschmidt/httprouter"
	"github.com/miekg/dns"

	"golang.org/x/net/publicsuffix"
)

type (
	// DomainController type struc
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

	domain := h.Question.JobDomain
	h.Question.JobTime = time.Now()
	log.Println("Domain ........... : " + domain)

	tld, tldicann := publicsuffix.PublicSuffix(domain)
	h.Answer.DomainTLD = tld
	h.Answer.DomainTLDicann = tldicann

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
	h.Answer.DomainTLDNS = tldns

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

	digest := h.Answer.DomainDS[0].DigestType

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
	dnskey, calculatedDS, err := resolveDomainDNSKEY(domain, digest, domainnameserver)
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
	h.Answer.DomainCalcDS = calculatedDS

	h.Question.JobStatus = "OK"
	h.Question.JobMessage = "Job done!"

	hj, _ := json.MarshalIndent(h, "", "    ")
	// hj, _ := json.Marshal(h)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(200)
	fmt.Fprintf(w, "%s", hj)
}

func resolveDomainA(domain string) ([]string, error) {
	answer := make([]string, 0)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return answer, err
	}
	for _, ain := range in.Answer {
		if a, ok := ain.(*dns.A); ok {
			answer = append(answer, a.A.String())
		}
	}
	return answer, nil
}

func resolveDomainAAAA(domain string) ([]string, error) {
	answer := make([]string, 0)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeAAAA)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return answer, err
	}
	for _, ain := range in.Answer {
		if a, ok := ain.(*dns.AAAA); ok {
			answer = append(answer, a.AAAA.String())
		}
	}
	return answer, nil
}

func resolveDomainMX(domain string) ([]string, error) {
	answer := make([]string, 0)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeMX)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return answer, err
	}
	for _, ain := range in.Answer {
		if a, ok := ain.(*dns.MX); ok {
			answer = append(answer, a.Mx)
		}
	}
	return answer, nil
}

func resolveDomainNS(domain string) ([]string, error) {
	answer := make([]string, 0)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return answer, err
	}
	for _, ain := range in.Answer {
		if a, ok := ain.(*dns.NS); ok {
			answer = append(answer, a.Ns)
		}
	}
	return answer, nil
}

func resolveDomainDS(domain string, nameserver string) ([]*models.DomainDS, error) {
	ds := []*models.DomainDS{}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeDS)
	m.SetEdns0(4096, true)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		return ds, err
	}
	for _, ain := range in.Answer {
		if a, ok := ain.(*dns.DS); ok {
			readkey := new(models.DomainDS)
			readkey.Algorithm = a.Algorithm
			readkey.Digest = a.Digest
			readkey.DigestType = a.DigestType
			readkey.KeyTag = a.KeyTag
			ds = append(ds, readkey)
		}
	}
	return ds, nil
}

func resolveDomainDNSKEY(domain string, digest uint8, nameserver string) ([]*models.DomainDNSKEY, []*models.DomainCalcDS, error) {
	dnskey := []*models.DomainDNSKEY{}
	calculatedDS := []*models.DomainCalcDS{}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeDNSKEY)
	m.SetEdns0(4096, true)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		return dnskey, calculatedDS, err
	}

	for _, ain := range in.Answer {
		if a, ok := ain.(*dns.DNSKEY); ok {
			readkey := new(models.DomainDNSKEY)
			readkey.Algorithm = a.Algorithm
			readkey.Flags = a.Flags
			readkey.Protocol = a.Protocol
			readkey.PublicKey = a.PublicKey
			dnskey = append(dnskey, readkey)

			var alg uint8
			switch a.Algorithm {
			case 5:
				alg = dns.SHA1
			case 7:
				alg = dns.SHA1
			case 8:
				alg = dns.SHA256
			case 10:
				alg = dns.SHA512
			case 13:
				alg = dns.SHA256
			case 14:
				alg = dns.SHA384
			}

			log.Printf("Algorithm ........ : %d \n", alg)
			if alg != 0 {
				calckey := new(models.DomainCalcDS)
				calckey.Algorithm = a.ToDS(digest).Algorithm
				calckey.Digest = a.ToDS(digest).Digest
				calckey.DigestType = a.ToDS(digest).DigestType
				calckey.KeyTag = a.ToDS(digest).KeyTag
				calculatedDS = append(calculatedDS, calckey)
			}
		}
	}

	return dnskey, calculatedDS, err
}
