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

	domainsoa, err := resolveDomainSOA(domain)
	if err != nil {
		log.Println("No SOA found: ", err)
	}
	msg.Answer.SOA = domainsoa

	arecords, err := resolveDomainA(domain)
	msg.Answer.DomainA = arecords

	aaaarecords, err := resolveDomainAAAA(domain)
	msg.Answer.DomainAAAA = aaaarecords

	mxrecords, err := resolveDomainMX(domain)
	msg.Answer.Email.MX = mxrecords

	dmarcrecords, err := resolveDomainDMARC(domain)
	msg.Answer.Email.DMARC = dmarcrecords

	spfrecords, err := resolveDomainSPF(domain)
	msg.Answer.Email.SPF = spfrecords

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

	if msg.Answer.DSRecordCount > 0 && msg.Answer.DNSKEYRecordCount > 0 {
		calculatedDS, err := calculateDSRecord(domain, digest, domainNameserver)
		if err != nil {
			log.Println("[ERROR] DS calc failed: .", err)
		}
		msg.Answer.DomainCalcDS = calculatedDS
	}

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
			answer.String = soa.String()
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

/*
 * Used Models
 */

// Message for retunring
type Message struct {
	Question Question `json:"question"`
	Answer   Answer   `json:"answer"`
}

// Question struct
type Question struct {
	JobDomain  string    `json:"domain"`
	JobStatus  string    `json:"status"`
	JobMessage string    `json:"message"`
	JobTime    time.Time `json:"time"`
}

// Answer struct
type Answer struct {
	Registry          Registry        `json:"tld,omitempty"`
	Nameservers       Nameservers     `json:"nameservers,omitempty"`
	SOA               *Soa            `json:"SOA,omitempty"`
	DSRecordCount     int             `json:"DSRecordCount,omitempty"`
	DNSKEYRecordCount int             `json:"DNSKEYRecordCount,omitempty"`
	DomainDS          []*DomainDS     `json:"DomainDS,omitempty"`
	DomainDNSKEY      []*DomainDNSKEY `json:"DomainDNSKEY,omitempty"`
	DomainCalcDS      []*DomainCalcDS `json:"DomainCalcDS,omitempty"`
	DomainA           []string        `json:"DomainA,omitempty"`
	DomainAAAA        []string        `json:"DomainAAAA,omitempty"`
	DomainMX          []string        `json:"DomainMX,omitempty"`
	Email             Email           `json:"Email,omitempty"`
}

// Soa struct for SOA information
type Soa struct {
	String  string `json:"string,omitempty"`
	Serial  uint32 `json:"serial,omitempty"`
	Ns      string `json:"ns,omitempty"`
	Expire  uint32 `json:"expire,omitempty"`
	Mbox    string `json:"mbox,omitempty"`
	Minttl  uint32 `json:"minttl,omitempty"`
	Refresh uint32 `json:"refresh,omitempty"`
	Retry   uint32 `json:"retry,omitempty"`
}

/*
The SOA record includes the following details:

The primary name server for the domain, which is ns1.dnsimple.com or the first name server in the vanity name server list for vanity name servers.
The responsible party for the domain, which is admin.dnsimple.com.
A timestamp that changes whenever you update your domain.
The number of seconds before the zone should be refreshed.
The number of seconds before a failed refresh should be retried.
The upper limit in seconds before a zone is considered no longer authoritative.
The negative result TTL (for example, how long a resolver should consider a negative result for a subdomain to be valid before retrying).
*/

// Registry struct for information
type Registry struct {
	TLD   string `json:"tld,omitempty"`
	ICANN bool   `json:"icann,omitempty"`
}

// Nameservers struct for information
type Nameservers struct {
	Root     []string `json:"root,omitempty"`
	Registry []string `json:"registry,omitempty"`
	Domain   []string `json:"domain,omitempty"`
	Domain2  []string `json:"domain2,omitempty"`
}

// DomainDS struct
type DomainDS struct {
	Algorithm  uint8  `json:"Algorithm,omitempty"`
	Digest     string `json:"Digest,omitempty"`
	DigestType uint8  `json:"DigestType,omitempty"`
	KeyTag     uint16 `json:"KeyTag,omitempty"`
}

// DomainDNSKEY struct
type DomainDNSKEY struct {
	Algorithm uint8  `json:"Algorithm,omitempty"`
	Flags     uint16 `json:"Flags,omitempty"`
	Protocol  uint8  `json:"Protocol,omitempty"`
	PublicKey string `json:"PublicKey,omitempty"`
}

// DomainCalcDS struct
type DomainCalcDS struct {
	Algorithm  uint8  `json:"Algorithm,omitempty"`
	Digest     string `json:"Digest,omitempty"`
	DigestType uint8  `json:"DigestType,omitempty"`
	KeyTag     uint16 `json:"KeyTag,omitempty"`
}

// Email struct
type Email struct {
	MX    []string `json:"MX,omitempty"`
	SPF   []string `json:"SPF,omitempty"`
	DMARC []string `json:"DMARC,omitempty"`
}
