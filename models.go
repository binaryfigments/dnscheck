package dnscheck

import "time"

/*
 * Used Models
 */

// Message struct for returning the question and the answer.
type Message struct {
	Question Question    `json:"question"`
	Answer   Answer      `json:"answer"`
	Controls []*Controls `json:"controls"`
}

// Question struct for retuning what information is asked.
type Question struct {
	JobDomain  string    `json:"domain"`
	JobStatus  string    `json:"status"`
	JobMessage string    `json:"message"`
	JobTime    time.Time `json:"time"`
}

// Answer struct the answer of the question.
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
	TLSARecords       []*Tlsa         `json:"TLSARecords,omitempty"`
}

// Soa struct for SOA information aquired from the nameserver.
type Soa struct {
	Ns      string `json:"ns,omitempty"`
	Mbox    string `json:"mbox,omitempty"`
	Serial  uint32 `json:"serial,omitempty"`
	Refresh uint32 `json:"refresh,omitempty"`
	Retry   uint32 `json:"retry,omitempty"`
	Expire  uint32 `json:"expire,omitempty"`
	Minttl  uint32 `json:"minttl,omitempty"`
}

// Controls struct check information
type Controls struct {
	Shortcode   string `json:"shortcode,omitempty"`
	Group       string `json:"group,omitempty"`
	Description string `json:"description,omitempty"`
	Points      int    `json:"points,omitempty"`
}

// Tlsa struct for SOA information
type Tlsa struct {
	Record       string `json:"record,omitempty"`
	Certificate  string `json:"certificate,omitempty"`
	MatchingType uint8  `json:"matchingtype,omitempty"`
	Selector     uint8  `json:"selector,omitempty"`
	Usage        uint8  `json:"usage,omitempty"`
}

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
