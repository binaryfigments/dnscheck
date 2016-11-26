package models

import "time"

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
	DSRecordCount     int             `json:"DSRecordCount,omitempty"`
	DNSKEYRecordCount int             `json:"DNSKEYRecordCount,omitempty"`
	DomainDS          []*DomainDS     `json:"DomainDS,omitempty"`
	DomainDNSKEY      []*DomainDNSKEY `json:"DomainDNSKEY,omitempty"`
	DomainCalcDS      []*DomainCalcDS `json:"DomainCalcDS,omitempty"`
	DomainA           []string        `json:"DomainA,omitempty"`
	DomainAAAA        []string        `json:"DomainAAAA,omitempty"`
	DomainMX          []string        `json:"DomainMX,omitempty"`
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
