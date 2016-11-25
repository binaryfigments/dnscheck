package models

import "time"

// Question struct
type Question struct {
	JobDomain  string    `json:"JobDomain"`
	JobStatus  string    `json:"JobStatus"`
	JobMessage string    `json:"JobMessage"`
	JobTime    time.Time `json:"JobTime"`
}

// Answer struct
type Answer struct {
	TLD               TLD             `json:"tld,omitempty"`
	RootNS            []string        `json:"RootNS,omitempty"`
	DomainNS          []string        `json:"DomainNS,omitempty"`
	DSRecordCount     int             `json:"DSRecordCount,omitempty"`
	DNSKEYRecordCount int             `json:"DNSKEYRecordCount,omitempty"`
	DomainDS          []*DomainDS     `json:"DomainDS,omitempty"`
	DomainDNSKEY      []*DomainDNSKEY `json:"DomainDNSKEY,omitempty"`
	DomainCalcDS      []*DomainCalcDS `json:"DomainCalcDS,omitempty"`
	DomainA           []string        `json:"DomainA,omitempty"`
	DomainAAAA        []string        `json:"DomainAAAA,omitempty"`
	DomainMX          []string        `json:"DomainMX,omitempty"`
}

// TLD struct for information
type TLD struct {
	TLD         string   `json:"tld,omitempty"`
	ICANN       bool     `json:"icann,omitempty"`
	Nameservers []string `json:"nameservers,omitempty"`
}

// Message for retunring
type Message struct {
	Question Question `json:"Question"`
	Answer   Answer   `json:"Answer"`
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
