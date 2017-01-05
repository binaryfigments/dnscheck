package dnscheck

import (
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

/*
 * Main function
 */

// Run function
func Run(domain string, startnameserver string) (*Message, error) {
	msg := new(Message)
	msg.Question.JobTime = time.Now()
	msg.Question.JobDomain = domain

	controls := []*Controls{}

	// Valid domain name (ASCII or IDN)
	domain, err := idna.ToASCII(domain)
	if err != nil {
		msg.Question.JobStatus = "Failed"
		msg.Question.JobMessage = "Non ASCII or IDN characters in domain."
		return msg, err
	}

	// Validate
	domain, err = publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		msg.Question.JobStatus = "Failed"
		msg.Question.JobMessage = "Domain not OK"
		return msg, err
	}

	// Go check DNS!

	domainstate := checkDomainState(domain)
	if domainstate != "OK" {
		log.Println(domainstate)
		msg.Question.JobStatus = "Failed"
		msg.Question.JobMessage = domainstate
		return msg, err
	}

	/*
	 * TLD and Registry information
	 */

	tld, tldicann := publicsuffix.PublicSuffix(domain)
	msg.Answer.Registry.TLD = tld
	msg.Answer.Registry.ICANN = tldicann

	if msg.Answer.Registry.ICANN == false {
		control := &Controls{
			"DNS-ICANN-001",
			"DNS",
			"TLD is not an ICANN member",
			0,
		}
		controls = append(controls, control)
	} else {
		control := &Controls{
			"DNS-ICANN-001",
			"DNS",
			"TLD is an ICANN member",
			0,
		}
		controls = append(controls, control)
	}

	// Root nameservers
	rootNameservers, err := resolveDomainNS(".", startnameserver)
	if err != nil {
		log.Println("No nameservers found: .", err)
		msg.Question.JobStatus = "Failed"
		msg.Question.JobMessage = "No nameservers found"
		return msg, err
	}
	msg.Answer.Nameservers.Root = rootNameservers

	// TLD nameserver
	registryNameservers, err := resolveDomainNS(tld, startnameserver)
	if err != nil {
		log.Println("No nameservers found: .", err)
		msg.Question.JobStatus = "Failed"
		msg.Question.JobMessage = "No nameservers found"
		return msg, err
	}
	msg.Answer.Nameservers.Registry = registryNameservers
	registryNameserver := registryNameservers[0]

	// Domain nameservers at zone
	domainNameservers, err := resolveDomainNS(domain, startnameserver)
	if err != nil {
		control := &Controls{
			"DNS-NS-001",
			"DNS",
			"No NS records found for domain.",
			-5,
		}
		controls = append(controls, control)
		msg.Question.JobStatus = "Failed"
		msg.Question.JobMessage = "No nameservers found"
		return msg, err
	}
	msg.Answer.Nameservers.Domain = domainNameservers
	domainNameserver := domainNameservers[0]

	/*
	 * DS and DNSKEY information
	 */

	// Domain nameservers at Hoster
	domainds, err := resolveDomainDS(domain, registryNameserver)
	if err != nil {
		msg.Question.JobStatus = "Failed"
		msg.Question.JobMessage = "Error DS lookup"
		return msg, err
	}
	msg.Answer.DomainDS = domainds
	msg.Answer.DSRecordCount = cap(domainds)
	if msg.Answer.DSRecordCount != 0 {
		control := &Controls{
			"DNS-DNSSEC-001",
			"DNS",
			"DS record found at registry.",
			5,
		}
		controls = append(controls, control)
	} else {
		control := &Controls{
			"DNS-DNSSEC-001",
			"DNS",
			"No DS record found at registry.",
			-5,
		}
		controls = append(controls, control)
	}

	domainsoa, err := resolveDomainSOA(domain)
	if err != nil {
		log.Println("No SOA found: ", err)
	}
	msg.Answer.SOA = domainsoa

	arecords, err := resolveDomainA(domain)
	msg.Answer.DomainA = arecords

	aaaarecords, err := resolveDomainAAAA(domain)
	msg.Answer.DomainAAAA = aaaarecords
	if msg.Answer.DomainAAAA != nil {
		control := &Controls{
			"DNS-IPV6-001",
			"DNS",
			"Domain name record in nameserver has an AAAA record for IPv6.",
			5,
		}
		controls = append(controls, control)
	} else {
		control := &Controls{
			"DNS-IPV6-001",
			"DNS",
			"Domain name record in nameserver has no AAAA record for IPv6.",
			-5,
		}
		controls = append(controls, control)
	}

	mxrecords, err := resolveDomainMX(domain)
	msg.Answer.Email.MX = mxrecords
	if msg.Answer.Email.MX == nil {
		control := &Controls{
			"DNS-EMAIL-001",
			"DNS",
			"No MX records found for domain.",
			-2,
		}
		controls = append(controls, control)
	}

	dmarcrecords, err := resolveDomainDMARC(domain)
	msg.Answer.Email.DMARC = dmarcrecords
	if msg.Answer.Email.DMARC != nil {
		control := &Controls{
			"DNS-EMAIL-002",
			"DNS",
			"DMARC is configured on your domain.",
			5,
		}
		controls = append(controls, control)
	} else {
		control := &Controls{
			"DNS-EMAIL-002",
			"DNS",
			"DMARC is not configured on your domain.",
			-5,
		}
		controls = append(controls, control)
	}

	spfrecords, err := resolveDomainSPF(domain)
	msg.Answer.Email.SPF = spfrecords
	if msg.Answer.Email.SPF != nil {
		control := &Controls{
			"DNS-EMAIL-003",
			"DNS",
			"SPF is configured on your domain.",
			5,
		}
		controls = append(controls, control)
	} else {
		control := &Controls{
			"DNS-EMAIL-003",
			"DNS",
			"SPF is not configured on your domain.",
			-5,
		}
		controls = append(controls, control)
	}

	// TLSA records
	tlsas := []*Tlsa{}

	checktlsa := "_443._tcp." + domain
	domainnametlsa, err := resolveTLSARecord(checktlsa)
	if err != nil {
		log.Println("No TLSA found: ", err)
		control := &Controls{
			"DNS-DANE-001",
			"DNS",
			"TLSA record for DANE not found for HTTPS website (" + checktlsa + ").",
			-5,
		}
		controls = append(controls, control)
	} else {
		tlsas = append(tlsas, domainnametlsa)
		control := &Controls{
			"DNS-DANE-001",
			"DNS",
			"TLSA record for DANE found for HTTPS website (" + checktlsa + ").",
			5,
		}
		controls = append(controls, control)
	}

	checkwwwtlsa := "_443._tcp.www." + domain
	domainwwwtlsa, err := resolveTLSARecord(checkwwwtlsa)
	if err != nil {
		log.Println("No TLSA found: ", err)
	} else {
		tlsas = append(tlsas, domainwwwtlsa)

	}

	for _, resource := range msg.Answer.Email.MX {
		// answer = append(answer, resource)
		checktlsamx := "_25._tcp." + strings.TrimSuffix(resource, ".")
		domainmxtlsa, err := resolveTLSARecord(checktlsamx)
		if err != nil {
			log.Println("No TLSA found: ", checktlsamx)
			control := &Controls{
				"DNS-DANE-002",
				"DNS",
				"TLSA record for DANE not found for MX an record (" + checktlsamx + ").",
				-5,
			}
			controls = append(controls, control)
		} else {
			tlsas = append(tlsas, domainmxtlsa)
			control := &Controls{
				"DNS-DANE-002",
				"DNS",
				"TLSA record for DANE found for MX an record (" + checktlsamx + ").",
				5,
			}
			controls = append(controls, control)
		}
	}

	// Add TLSAs to answer struct
	msg.Answer.TLSARecords = tlsas

	var digest uint8
	if cap(msg.Answer.DomainDS) != 0 {
		digest = msg.Answer.DomainDS[0].DigestType
		// log.Println("[OK] DS digest type found:", digest)
	}

	dnskey, err := resolveDomainDNSKEY(domain, domainNameserver)
	if err != nil {
		// log.Println("DNSKEY lookup failed: .", err)
	}
	// log.Println("[OK] DNSKEY record lookup done.")

	msg.Answer.DomainDNSKEY = dnskey
	msg.Answer.DNSKEYRecordCount = cap(msg.Answer.DomainDNSKEY)
	if msg.Answer.DNSKEYRecordCount != 0 {
		control := &Controls{
			"DNS-DNSSEC-003",
			"DNS",
			"DNSKEY found for your domain.",
			5,
		}
		controls = append(controls, control)
	} else {
		control := &Controls{
			"DNS-DNSSEC-003",
			"DNS",
			"DNSKEY not found for your domain.",
			-5,
		}
		controls = append(controls, control)
	}

	if msg.Answer.DSRecordCount > 0 && msg.Answer.DNSKEYRecordCount > 0 {
		calculatedDS, err := calculateDSRecord(domain, digest, domainNameserver)
		if err != nil {
			log.Println("[ERROR] DS calc failed: .", err)
		}
		msg.Answer.DomainCalcDS = calculatedDS
	}

	// Add Controls to struct
	msg.Controls = controls

	msg.Question.JobStatus = "OK"
	msg.Question.JobMessage = "Job done!"

	return msg, err
}

/*
 * Used functions
 * TODO: Rewrite
 */

func resolveDomainA(domain string) ([]string, error) {
	var answer []string
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	c := new(dns.Client)
	m.MsgHdr.RecursionDesired = true
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

func resolveDomainDMARC(domain string) ([]string, error) {
	var answer []string

	resources, err := net.LookupTXT("_dmarc." + domain + ".")
	if err != nil {
		return answer, err
	}

	for _, resource := range resources {
		answer = append(answer, resource)
	}
	return answer, nil
}

func resolveDomainSPF(domain string) ([]string, error) {
	var answer []string

	resources, err := net.LookupTXT(domain)
	if err != nil {
		return answer, err
	}

	for _, resource := range resources {
		if strings.HasPrefix(resource, "v=spf1") {
			answer = append(answer, resource)
		}
	}
	return answer, nil
}

func resolveDomainAAAA(domain string) ([]string, error) {
	var answer []string
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeAAAA)
	m.MsgHdr.RecursionDesired = true
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
	var answer []string
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeMX)
	m.MsgHdr.RecursionDesired = true
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

func resolveDomainNS(domain string, nameserver string) ([]string, error) {
	var answer []string
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	m.MsgHdr.RecursionDesired = true
	m.SetEdns0(4096, true)
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

func resolveDomainDS(domain string, nameserver string) ([]*DomainDS, error) {
	ds := []*DomainDS{}
	m := new(dns.Msg)
	m.MsgHdr.RecursionDesired = true
	m.SetQuestion(dns.Fqdn(domain), dns.TypeDS)
	m.SetEdns0(4096, true)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		log.Println("[FAIL] No DS records found.")
		return ds, err
	}
	// fmt.Println(cap(in.Answer))
	for _, ain := range in.Answer {
		if a, ok := ain.(*dns.DS); ok {
			readkey := new(DomainDS)
			readkey.Algorithm = a.Algorithm
			readkey.Digest = a.Digest
			readkey.DigestType = a.DigestType
			readkey.KeyTag = a.KeyTag
			ds = append(ds, readkey)
		}
	}
	return ds, nil
}

func resolveDomainDNSKEY(domain string, nameserver string) ([]*DomainDNSKEY, error) {
	dnskey := []*DomainDNSKEY{}

	m := new(dns.Msg)
	m.MsgHdr.RecursionDesired = true
	m.SetQuestion(dns.Fqdn(domain), dns.TypeDNSKEY)
	m.SetEdns0(4096, true)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		return dnskey, err
	}
	for _, ain := range in.Answer {
		if a, ok := ain.(*dns.DNSKEY); ok {
			readkey := new(DomainDNSKEY)
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
 * Input: domainname, digest and nameserver from the hoster.
 * Output: one of more structs with DS information
 */

func calculateDSRecord(domain string, digest uint8, nameserver string) ([]*DomainCalcDS, error) {
	calculatedDS := []*DomainCalcDS{}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeDNSKEY)
	m.SetEdns0(4096, true)
	m.MsgHdr.RecursionDesired = true
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		return calculatedDS, err
	}
	for _, ain := range in.Answer {
		if a, ok := ain.(*dns.DNSKEY); ok {
			calckey := new(DomainCalcDS)
			calckey.Algorithm = a.ToDS(digest).Algorithm
			calckey.Digest = a.ToDS(digest).Digest
			calckey.DigestType = a.ToDS(digest).DigestType
			calckey.KeyTag = a.ToDS(digest).KeyTag
			calculatedDS = append(calculatedDS, calckey)
		}
	}
	return calculatedDS, nil
}

// resolveDomainSOA for checking soa
func resolveDomainSOA(domain string) (*Soa, error) {
	answer := new(Soa)
	// answer := *Soa{}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)
	c := new(dns.Client)
	m.MsgHdr.RecursionDesired = true
	in, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return answer, err
	}
	for _, ain := range in.Answer {
		if soa, ok := ain.(*dns.SOA); ok {
			answer.Serial = soa.Serial   // uint32
			answer.Ns = soa.Ns           // string
			answer.Expire = soa.Expire   // uint32
			answer.Mbox = soa.Mbox       // string
			answer.Minttl = soa.Minttl   // uint32
			answer.Refresh = soa.Refresh // uint32
			answer.Retry = soa.Retry     // uint32
		}
	}
	return answer, nil
}

// resolveTLSARecord for checking soa
func resolveTLSARecord(record string) (*Tlsa, error) {
	answer := new(Tlsa)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(record), dns.TypeTLSA)
	c := new(dns.Client)
	m.MsgHdr.RecursionDesired = true
	in, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return answer, err
	}
	for _, ain := range in.Answer {
		if tlsa, ok := ain.(*dns.TLSA); ok {
			log.Println("Found: ", record)
			answer.Record = record                  // string
			answer.Certificate = tlsa.Certificate   // string
			answer.MatchingType = tlsa.MatchingType // uint8
			answer.Selector = tlsa.Selector         // uint8
			answer.Usage = tlsa.Usage               // uint8
		}
	}
	return answer, nil
}

// checkDomainState
func checkDomainState(domain string) string {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)
	m.SetEdns0(4096, true)
	m.MsgHdr.RecursionDesired = true
	c := new(dns.Client)

Redo:
	in, _, err := c.Exchange(m, "8.8.8.8:53")

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
