package controllers

import (
	"fmt"
	"log"

	"github.com/binaryfigments/dnscheck/models"
	"github.com/miekg/dns"
)

func resolveDomainA(domain string) ([]string, error) {
	var answer []string
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, "64.6.64.6:53")
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
	var answer []string
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeAAAA)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, "64.6.64.6:53")
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
	var answer []string
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeMX)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, "64.6.64.6:53")
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

func resolveDomainNS(domain string, nameserver string) ([]string, error) {
	var answer []string
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver+":53")
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
		log.Println("[FAIL] No DS records found.")
		return ds, err
	}
	fmt.Println(cap(in.Answer))
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

func resolveDomainDNSKEY(domain string, nameserver string) ([]*models.DomainDNSKEY, error) {
	dnskey := []*models.DomainDNSKEY{}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeDNSKEY)
	m.SetEdns0(4096, true)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		return dnskey, err
	}
	for _, ain := range in.Answer {
		if a, ok := ain.(*dns.DNSKEY); ok {
			readkey := new(models.DomainDNSKEY)
			readkey.Algorithm = a.Algorithm
			readkey.Flags = a.Flags
			readkey.Protocol = a.Protocol
			readkey.PublicKey = a.PublicKey
			dnskey = append(dnskey, readkey)
		}
	}
	return dnskey, err
}

/*
 * calculateDSRecord function for generating DS records from the DNSKEY.
 * Inpunt: domainname, digest and nameserver from the hoster.
 * Output: one of more structs with DS information
 */

func calculateDSRecord(domain string, digest uint8, nameserver string) ([]*models.DomainCalcDS, error) {
	calculatedDS := []*models.DomainCalcDS{}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeDNSKEY)
	m.SetEdns0(4096, true)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		return calculatedDS, err
	}
	for _, ain := range in.Answer {
		if a, ok := ain.(*dns.DNSKEY); ok {
			calckey := new(models.DomainCalcDS)
			calckey.Algorithm = a.ToDS(digest).Algorithm
			calckey.Digest = a.ToDS(digest).Digest
			calckey.DigestType = a.ToDS(digest).DigestType
			calckey.KeyTag = a.ToDS(digest).KeyTag
			calculatedDS = append(calculatedDS, calckey)
		}
	}
	return calculatedDS, err
}

// checkDomainState
func checkDomainState(domain string) string {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)
	m.SetEdns0(4096, true)
	c := new(dns.Client)

Redo:
	in, _, err := c.Exchange(m, "64.6.64.6:53")

	// in, _, err := c.Exchange(m, "8.8.4.4:53") // Second return value is RTT, not used for now

	if err == nil {
		switch in.MsgHdr.Rcode {
		case dns.RcodeServerFailure:
			return "500, 502, The name server encountered an internal failure while processing this request (SERVFAIL)"
		case dns.RcodeNameError:
			return "500, 503, Some name that ought to exist, does not exist (NXDOMAIN)"
		case dns.RcodeRefused:
			return "500, 505, The name server refuses to perform the specified operation for policy or security reasons (REFUSED)"
		default:
			return "OK"
		}
	} else if err == dns.ErrTruncated {
		c.Net = "tcp"
		goto Redo
	} else {
		return "500, 501, DNS server could not be reached"
	}
}
